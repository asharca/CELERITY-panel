package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"hash/fnv"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type journalCursorState struct {
	Cursor       string `json:"cursor"`
	RealtimeUsec uint64 `json:"realtime_usec,omitempty"`
}

type journalEntry struct {
	Cursor            string `json:"__CURSOR"`
	RealtimeTimestamp string `json:"__REALTIME_TIMESTAMP"`
	Message           string `json:"MESSAGE"`
}

// JournalTailer follows one systemd unit through journalctl's JSON output. Each
// journal record carries __CURSOR, which is persisted and supplied as
// --after-cursor after an agent restart. On first enable, a durable realtime
// baseline is written before journalctl starts, then --since resumes from its
// second boundary. This may replay up to one second but leaves no attach gap.
type JournalTailer struct {
	unit       string
	cursorPath string
	emit       func([]rawLine)
	// canCheckpoint is true only after emitted access lines are durably spooled.
	canCheckpoint func() bool

	mu           sync.Mutex
	saveMu       sync.Mutex
	cursor       string
	realtimeUsec uint64
	cursorDirty  bool
	cancel       context.CancelFunc
	ready        bool
	lastError    string
	command      func(context.Context, string, ...string) *exec.Cmd

	stopCh chan struct{}
	doneCh chan struct{}
}

func NewJournalTailer(unit, cursorPath string, emit func([]rawLine), canCheckpoint func() bool) *JournalTailer {
	return &JournalTailer{
		unit:          unit,
		cursorPath:    cursorPath,
		emit:          emit,
		canCheckpoint: canCheckpoint,
		command:       exec.CommandContext,
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}
}

func (t *JournalTailer) LagBytes() int64 { return 0 }

func (t *JournalTailer) Ready() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ready
}

func (t *JournalTailer) LastError() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastError
}

// Checkpoint persists the latest journal cursor on demand. Shipper.Stop calls
// this after its final durable flush.
func (t *JournalTailer) Checkpoint() { t.saveCursor() }

func (t *JournalTailer) Stop() {
	select {
	case <-t.stopCh:
	default:
		close(t.stopCh)
	}
	t.mu.Lock()
	if t.cancel != nil {
		t.cancel()
	}
	t.mu.Unlock()
	<-t.doneCh
}

func (t *JournalTailer) Run() {
	defer func() {
		t.setReady(false)
		close(t.doneCh)
	}()
	loaded := t.loadCursor()
	if !loaded {
		// Persist a wall-clock baseline before starting journalctl. The first
		// command resumes from this baseline with --since. Flooring to journalctl's
		// integer-second precision may replay up to one second, but it closes both
		// the baseline-to-attach gap and the crash-before-first-checkpoint gap.
		baselineUsec := time.Now().UnixMicro()
		if baselineUsec <= 0 {
			t.setSourceState(false, "cannot initialize journal baseline: invalid realtime clock")
			return
		}
		for {
			if err := t.initializeBaseline(uint64(baselineUsec)); err == nil {
				break
			} else {
				t.setSourceState(false, "cannot persist journal baseline: "+err.Error())
				log.Printf("[accesslog] cannot persist journal baseline: %v", err)
			}
			select {
			case <-t.stopCh:
				return
			case <-time.After(time.Second):
			}
		}
	}

	persistDone := make(chan struct{})
	persistStopped := make(chan struct{})
	go func() {
		t.persistCursorLoop(persistDone)
		close(persistStopped)
	}()
	defer func() {
		close(persistDone)
		<-persistStopped
		t.saveCursor()
	}()

	backoff := time.Second
	for {
		select {
		case <-t.stopCh:
			return
		default:
		}

		err := t.followOnce()
		if errors.Is(err, context.Canceled) || t.stopping() {
			t.setReady(false)
			return
		}
		if err == nil {
			err = errors.New("journalctl exited unexpectedly")
		}
		t.setSourceState(false, err.Error())
		log.Printf("[accesslog] journal source %s stopped: %v", t.unit, err)

		select {
		case <-t.stopCh:
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (t *JournalTailer) stopping() bool {
	select {
	case <-t.stopCh:
		return true
	default:
		return false
	}
}

func (t *JournalTailer) followOnce() error {
	t.mu.Lock()
	cursor := t.cursor
	realtimeUsec := t.realtimeUsec
	t.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	t.mu.Lock()
	t.cancel = cancel
	t.mu.Unlock()
	defer func() {
		cancel()
		t.mu.Lock()
		t.cancel = nil
		t.mu.Unlock()
	}()

	args := journalctlArgs(t.unit, cursor, realtimeUsec)
	command := t.command
	if command == nil {
		command = exec.CommandContext
	}
	cmd := command(ctx, "journalctl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	// Run reaches this point only after a durable cursor/baseline exists. A
	// successful Start is therefore the final condition for source readiness.
	t.setSourceState(true, "")

	scanner := bufio.NewScanner(stdout)
	// journal MESSAGE values should be small, but avoid Scanner's 64 KiB limit
	// turning one unusual application log into a permanently restarting source.
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		message, entryCursor, entryRealtimeUsec, offset, ok := parseJournalLine(scanner.Bytes())
		if !ok {
			continue
		}
		if message != "" && t.emit != nil {
			t.emit([]rawLine{{Offset: offset, Line: message}})
		}
		t.setPosition(entryCursor, entryRealtimeUsec)
	}
	scanErr := scanner.Err()
	waitErr := cmd.Wait()
	if scanErr != nil {
		return scanErr
	}
	if waitErr != nil {
		// A cursor can become invalid after journal vacuuming. Clear only for an
		// explicit cursor-seek failure; unrelated errors retain the resume point.
		stderrText := strings.ToLower(stderr.String())
		if cursor != "" && strings.Contains(stderrText, "cursor") &&
			(strings.Contains(stderrText, "seek") || strings.Contains(stderrText, "invalid") || strings.Contains(stderrText, "failed")) {
			t.clearCursor()
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if stderr.Len() > 0 {
			return errors.New(strings.TrimSpace(stderr.String()))
		}
		return waitErr
	}
	return nil
}

func journalctlArgs(unit, cursor string, realtimeUsec uint64) []string {
	args := []string{
		"--unit=" + unit,
		"--output=json",
		"--no-pager",
		"--follow",
		"--quiet",
	}
	if cursor == "" {
		if realtimeUsec > 0 {
			// __REALTIME_TIMESTAMP is microseconds; @ syntax accepts integer Unix
			// seconds. Flooring intentionally replays up to one second so recovery
			// never skips a retained entry at the checkpoint boundary.
			return append(args,
				"--since=@"+strconv.FormatUint(realtimeUsec/1_000_000, 10),
				"--no-tail",
			)
		}
		return append(args, "--lines=0")
	}
	return append(args, "--after-cursor="+cursor, "--no-tail")
}

func parseJournalLine(line []byte) (message, cursor string, realtimeUsec uint64, offset int64, ok bool) {
	var entry journalEntry
	if err := json.Unmarshal(line, &entry); err != nil || entry.Cursor == "" || entry.RealtimeTimestamp == "" {
		return "", "", 0, 0, false
	}
	parsed, err := strconv.ParseUint(entry.RealtimeTimestamp, 10, 64)
	if err != nil {
		return "", "", 0, 0, false
	}
	realtimeUsec = parsed
	return entry.Message, entry.Cursor, realtimeUsec, journalCursorOffset(entry.Cursor), true
}

func journalCursorOffset(cursor string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(cursor))
	return int64(h.Sum64() & uint64(^uint64(0)>>1))
}

// loadCursor reports whether a usable cursor or realtime baseline was found.
// An empty object is not usable: treating it as a checkpoint would make the
// next process start from now without first creating a crash-safe baseline.
func (t *JournalTailer) loadCursor() bool {
	data, err := os.ReadFile(t.cursorPath)
	if err != nil {
		return false
	}
	var state journalCursorState
	if json.Unmarshal(data, &state) != nil || (state.Cursor == "" && state.RealtimeUsec == 0) {
		return false
	}
	t.mu.Lock()
	t.cursor = state.Cursor
	t.realtimeUsec = state.RealtimeUsec
	t.cursorDirty = false
	t.mu.Unlock()
	return true
}

func (t *JournalTailer) initializeBaseline(realtimeUsec uint64) error {
	if realtimeUsec == 0 {
		return errors.New("realtime baseline is zero")
	}
	t.mu.Lock()
	t.cursor = ""
	t.realtimeUsec = realtimeUsec
	t.cursorDirty = true
	t.mu.Unlock()

	persisted, err := t.persistCursorDurable()
	if err != nil {
		return err
	}
	if !persisted {
		return errors.New("journal baseline checkpoint deferred")
	}
	return nil
}

func (t *JournalTailer) setPosition(cursor string, realtimeUsec uint64) {
	if cursor == "" {
		return
	}
	t.mu.Lock()
	if cursor != t.cursor || realtimeUsec != t.realtimeUsec {
		t.cursor = cursor
		t.realtimeUsec = realtimeUsec
		t.cursorDirty = true
	}
	t.mu.Unlock()
}

func (t *JournalTailer) clearCursor() {
	t.mu.Lock()
	t.cursor = ""
	// Preserve realtimeUsec. The next journalctl invocation resumes from the
	// checkpoint second if vacuuming made the opaque cursor unseekable.
	t.cursorDirty = true
	t.mu.Unlock()
	t.saveCursor()
}

func (t *JournalTailer) setReady(ready bool) {
	t.mu.Lock()
	t.ready = ready
	t.mu.Unlock()
}

func (t *JournalTailer) setSourceState(ready bool, message string) {
	t.mu.Lock()
	t.ready = ready
	t.lastError = message
	t.mu.Unlock()
}

func (t *JournalTailer) persistCursorLoop(done <-chan struct{}) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			t.saveCursor()
		}
	}
}

func (t *JournalTailer) saveCursor() {
	if _, err := t.persistCursorDurable(); err != nil {
		log.Printf("[accesslog] journal cursor checkpoint failed: %v", err)
	}
}

func (t *JournalTailer) persistCursorDurable() (bool, error) {
	t.saveMu.Lock()
	defer t.saveMu.Unlock()

	t.mu.Lock()
	if !t.cursorDirty {
		t.mu.Unlock()
		return true, nil
	}
	state := journalCursorState{Cursor: t.cursor, RealtimeUsec: t.realtimeUsec}
	t.mu.Unlock()
	// Snapshot the cursor before consulting shipper durability. Scanner order is
	// emit -> setCursor, so a snapshotted cursor always refers only to events the
	// shipper had already seen when canCheckpoint ran. Reversing this order would
	// allow a new event to race between the durability check and cursor snapshot.
	if t.canCheckpoint != nil && !t.canCheckpoint() {
		return false, nil
	}

	data, err := json.Marshal(state)
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(t.cursorPath), 0755); err != nil {
		return false, err
	}
	tmp := t.cursorPath + ".tmp"
	if err := writeAtomicDurable(t.cursorPath, tmp, data, 0600); err != nil {
		return false, err
	}

	t.mu.Lock()
	// Do not clear dirty if a newer cursor arrived while this write was in
	// progress; the next tick will persist that newer value.
	if t.cursor == state.Cursor && t.realtimeUsec == state.RealtimeUsec {
		t.cursorDirty = false
	}
	t.mu.Unlock()
	return true, nil
}

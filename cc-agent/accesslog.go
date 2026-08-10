// NOTE: this file uses syscall.Stat_t and only builds for GOOS=linux targets.
// The agent is always cross-compiled for linux (amd64/arm64); building for a
// non-linux host OS is not supported.

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// cursorState is persisted so the tailer resumes at the right position after an
// agent restart and detects file recreation (rotation / truncation by another
// tool) via device+inode identity.
type cursorState struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
}

// rawLine is a single completed access-log line with a stable source position:
// a byte offset for files or a hash of the journal cursor. The panel currently
// treats delivery as at-least-once and does not use this field for per-event
// deduplication.
type rawLine struct {
	Offset int64  `json:"offset"`
	Line   string `json:"line"`
}

// Tailer follows the Xray access log and emits completed lines to a callback.
// It never mutates the source file: Xray keeps an O_APPEND descriptor open, so
// in-place truncation has an unavoidable race with the active writer.
type Tailer struct {
	path       string
	cursorPath string
	maxBytes   int64

	mu     sync.Mutex
	saveMu sync.Mutex
	cursor cursorState
	dirty  bool

	stopCh chan struct{}
	doneCh chan struct{}

	// canCheckpoint reports whether emitted lines have reached a sealed spool
	// file. Persisting the read offset before that point would skip events after
	// a process crash.
	canCheckpoint func() bool

	// emit receives batches of completed lines.
	emit func([]rawLine)

	// lagBytes exposes how far behind end-of-file the reader is (for status).
	lagBytes           int64
	ready              bool
	lastError          string
	sizeWarning        string
	limitWarningLogged bool
}

func NewTailer(
	path, cursorPath string,
	maxBytes int64,
	emit func([]rawLine),
	canCheckpoint func() bool,
) *Tailer {
	return &Tailer{
		path:          path,
		cursorPath:    cursorPath,
		maxBytes:      maxBytes,
		emit:          emit,
		canCheckpoint: canCheckpoint,
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}
}

func fileIdentity(fi os.FileInfo) (uint64, uint64) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev), uint64(st.Ino)
	}
	return 0, 0
}

func (t *Tailer) loadCursor() {
	data, err := os.ReadFile(t.cursorPath)
	if err != nil {
		return
	}
	var c cursorState
	if json.Unmarshal(data, &c) == nil {
		t.cursor = c
		t.dirty = false
	}
}

func (t *Tailer) saveCursor() {
	t.saveMu.Lock()
	defer t.saveMu.Unlock()

	t.mu.Lock()
	if !t.dirty {
		t.mu.Unlock()
		return
	}
	c := t.cursor
	t.mu.Unlock()
	// Snapshot before checking durability. readAvailable always emits before it
	// advances cursor, so this snapshot can never refer to an unseen line.
	if t.canCheckpoint != nil && !t.canCheckpoint() {
		return
	}
	data, err := json.Marshal(c)
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(t.cursorPath), 0755)
	tmp := t.cursorPath + ".tmp"
	if os.WriteFile(tmp, data, 0600) == nil {
		if os.Rename(tmp, t.cursorPath) == nil {
			t.mu.Lock()
			if t.cursor == c {
				t.dirty = false
			}
			t.mu.Unlock()
		}
	}
}

// Checkpoint persists the latest read position once the shipper confirms that
// all emitted lines are durably spooled.
func (t *Tailer) Checkpoint() { t.saveCursor() }

// LagBytes returns how far behind end-of-file the tailer currently is.
func (t *Tailer) LagBytes() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lagBytes
}

// Ready is true only after the configured file has been opened successfully.
// A missing/unreadable file remains an observable source failure rather than a
// misleadingly healthy enabled module.
func (t *Tailer) Ready() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ready
}

func (t *Tailer) LastError() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastError
}

// Warning reports a non-fatal source condition. The size threshold is only an
// operational warning; it must not make the source unhealthy or trigger a
// restart loop in the panel.
func (t *Tailer) Warning() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.sizeWarning
}

func (t *Tailer) updateSizeWarning(size int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.maxBytes <= 0 || size < t.maxBytes {
		t.sizeWarning = ""
		t.limitWarningLogged = false
		return
	}
	t.sizeWarning = fmt.Sprintf(
		"access log is %d bytes (warning threshold %d); configure external rotation with a coordinated Xray logger reopen",
		size,
		t.maxBytes,
	)
	if !t.limitWarningLogged {
		log.Printf("[accesslog] %s", t.sizeWarning)
		t.limitWarningLogged = true
	}
}

func (t *Tailer) setSourceState(ready bool, message string) {
	t.mu.Lock()
	t.ready = ready
	t.lastError = message
	t.mu.Unlock()
}

func (t *Tailer) setReady(ready bool) {
	t.mu.Lock()
	t.ready = ready
	t.mu.Unlock()
}

func (t *Tailer) Stop() {
	select {
	case <-t.stopCh:
	default:
		close(t.stopCh)
	}
	<-t.doneCh
}

// Run reads new lines in a loop until Stop() is called.
func (t *Tailer) Run() {
	defer func() {
		t.setReady(false)
		close(t.doneCh)
	}()
	t.loadCursor()
	t.readAvailable()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-t.stopCh:
			t.readAvailable() // final drain
			return
		case <-ticker.C:
			t.readAvailable()
		}
	}
}

// readAvailable reads all completed lines currently available and advances the
// cursor. File recreation resets the offset to 0.
func (t *Tailer) readAvailable() {
	fi, err := os.Stat(t.path)
	if err != nil {
		t.setSourceState(false, err.Error())
		return
	}
	dev, ino := fileIdentity(fi)
	t.updateSizeWarning(fi.Size())

	t.mu.Lock()
	// Detect recreation (new inode) or truncation (file shorter than offset).
	if dev != t.cursor.Device || ino != t.cursor.Inode {
		t.cursor = cursorState{Device: dev, Inode: ino, Offset: 0}
		t.dirty = true
	} else if fi.Size() < t.cursor.Offset {
		t.cursor.Offset = 0
		t.dirty = true
	}
	startOffset := t.cursor.Offset
	t.mu.Unlock()

	// Open even when there are no new bytes. Stat alone does not prove that the
	// agent can read the configured source, so readiness is asserted only after
	// this succeeds.
	f, err := os.Open(t.path)
	if err != nil {
		t.setSourceState(false, err.Error())
		return
	}
	defer f.Close()
	t.setSourceState(true, "")

	if fi.Size() <= startOffset {
		t.mu.Lock()
		t.lagBytes = 0
		t.mu.Unlock()
		return
	}

	if _, err := f.Seek(startOffset, io.SeekStart); err != nil {
		t.setSourceState(false, err.Error())
		return
	}

	reader := bufio.NewReader(f)
	offset := startOffset
	batch := make([]rawLine, 0, 256)
	var readErr error

	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			// Partial (no trailing newline) — do not consume; wait for the
			// writer to finish the line.
			break
		}
		if err != nil {
			readErr = err
			break
		}
		lineStart := offset
		offset += int64(len(line))
		trimmed := line
		if n := len(trimmed); n > 0 && trimmed[n-1] == '\n' {
			trimmed = trimmed[:n-1]
		}
		if len(trimmed) > 0 && trimmed[len(trimmed)-1] == '\r' {
			trimmed = trimmed[:len(trimmed)-1]
		}
		if trimmed == "" {
			continue
		}
		batch = append(batch, rawLine{Offset: lineStart, Line: trimmed})
		if len(batch) >= 1000 {
			t.emit(batch)
			batch = batch[:0]
		}
	}

	if len(batch) > 0 {
		t.emit(batch)
	}

	t.mu.Lock()
	t.cursor.Offset = offset
	t.cursor.Device = dev
	t.cursor.Inode = ino
	t.cursorDirtyIfChanged(startOffset, offset)
	t.lagBytes = fi.Size() - offset
	t.mu.Unlock()
	t.saveCursor()
	if readErr != nil {
		t.setSourceState(false, readErr.Error())
	}
}

// cursorDirtyIfChanged is called with t.mu held.
func (t *Tailer) cursorDirtyIfChanged(previous, current int64) {
	if previous != current {
		t.dirty = true
	}
}

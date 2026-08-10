package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

// Xray writes access records and ordinary process diagnostics to the same
// stdout stream. When journald is the source, retain only the two raw shapes
// understood by the panel's ClickHouse parser: destination-bearing access
// records and connection-level handshake errors. This keeps warnings/startup
// messages out of the bounded spool and prevents them inflating analytics.
var (
	xrayAccessRecordRE = regexp.MustCompile(
		`^\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+` +
			`(?:from\s+)?\S+\s+(?:accepted|rejected|blocked)\s+` +
			`(?:tcp|udp)\s*:\s*\S+(?:\s+\[[^\]]*\])?` +
			`(?:\s+email:\s*\S(?:.*\S)?)?\s*$`,
	)
	xrayHandshakeErrorRE = regexp.MustCompile(
		`^\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+` +
			`(?:from\s+)?\S+\s+(?:accepted|rejected|blocked)(?:\s|$)`,
	)
)

func isXrayAccessRecord(line string) bool {
	return xrayAccessRecordRE.MatchString(line) || xrayHandshakeErrorRE.MatchString(line)
}

// spoolEvent is one NDJSON record shipped to the panel. The panel parses the
// raw line; the agent only forwards it with minimal metadata.
type spoolEvent struct {
	Offset int64  `json:"offset"`
	Raw    string `json:"raw"`
	ReadAt string `json:"read_at"`
}

// ShipperStatus is surfaced through GET /info so the panel can display module
// health without it affecting the node's core health.
type ShipperStatus struct {
	Enabled       bool   `json:"enabled"`
	Source        string `json:"source,omitempty"`
	Format        string `json:"format,omitempty"`
	JournalUnit   string `json:"journal_unit,omitempty"`
	SourceReady   bool   `json:"source_ready"`
	SpoolBytes    int64  `json:"spool_bytes"`
	SpoolBatches  int    `json:"spool_batches"`
	LagBytes      int64  `json:"lag_bytes"`
	DroppedEvents int64  `json:"dropped_events"`
	InvalidEvents int64  `json:"invalid_events"`
	LastShipAt    string `json:"last_ship_at"`
	LastError     string `json:"last_error"`
	SourceError   string `json:"source_error,omitempty"`
	SourceWarning string `json:"source_warning,omitempty"`
}

type accessLogSource interface {
	Run()
	Stop()
	LagBytes() int64
	Ready() bool
}

// Shipper batches tailed lines, writes them to a bounded disk spool as
// gzipped NDJSON, and delivers them to the panel with at-least-once semantics.
type Shipper struct {
	cfg      *AccessLogsConfig
	spoolDir string
	client   *http.Client
	source   accessLogSource

	mu            sync.Mutex
	flushMu       sync.Mutex
	pending       []rawLine
	spoolBytes    int64
	droppedEvents int64
	invalidEvents int64
	lastShipAt    time.Time
	lastError     string

	stopCh chan struct{}
	doneCh chan struct{}
}

func NewShipper(cfg *Config) *Shipper {
	spoolDir := filepath.Join(cfg.DataDir, "accesslog-spool")
	al := &cfg.AccessLogs

	transport := &http.Transport{}
	if al.InsecureTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	s := &Shipper{
		cfg:      al,
		spoolDir: spoolDir,
		client:   &http.Client{Timeout: 30 * time.Second, Transport: transport},
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}

	if al.Source == accessLogSourceJournal {
		cursorPath := filepath.Join(cfg.DataDir, "accesslog-journal-cursor.json")
		s.source = NewJournalTailer(al.JournalUnit, cursorPath, s.onLines, s.canCheckpoint)
	} else {
		// Keep the legacy cursor name so existing Xray agents resume exactly
		// where pre-1.5.0 binaries stopped.
		cursorPath := filepath.Join(cfg.DataDir, "accesslog-cursor.json")
		s.source = NewTailer(al.Path, cursorPath, al.FileMaxBytes, s.onLines, s.canCheckpoint)
	}
	return s
}

// canCheckpoint reports that every accepted line emitted so far is durably in a
// sealed spool file. Source cursors must not advance while an event exists only
// in memory, otherwise a process crash could skip that access permanently.
func (s *Shipper) canCheckpoint() bool {
	s.flushMu.Lock()
	defer s.flushMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending) == 0
}

// onLines buffers completed lines; the flush loop turns them into batches.
func (s *Shipper) onLines(lines []rawLine) {
	if s.cfg.Source == accessLogSourceJournal && s.cfg.Format == accessLogFormatXray {
		filtered := make([]rawLine, 0, len(lines))
		for _, line := range lines {
			if isXrayAccessRecord(line.Line) {
				filtered = append(filtered, line)
			}
		}
		lines = filtered
	} else if s.cfg.Format == accessLogFormatHysteria2JSON {
		normalized := make([]rawLine, 0, len(lines))
		for _, line := range lines {
			accessLine, result := normalizeHysteria2AccessLineDetailed(line.Line)
			if result != hysteria2NormalizeAccepted {
				if result == hysteria2NormalizeInvalid {
					s.mu.Lock()
					s.invalidEvents++
					s.mu.Unlock()
				}
				continue
			}
			line.Line = accessLine
			normalized = append(normalized, line)
		}
		lines = normalized
	}
	if len(lines) == 0 {
		return
	}
	s.mu.Lock()
	s.pending = append(s.pending, lines...)
	shouldFlush := len(s.pending) >= s.cfg.BatchMaxEvents
	s.mu.Unlock()
	if shouldFlush {
		s.flush()
	}
}

func (s *Shipper) Start() {
	if err := os.MkdirAll(s.spoolDir, 0755); err != nil {
		log.Printf("[shipper] cannot create spool dir: %v", err)
	}
	go s.source.Run()
	go s.run()
	if s.cfg.Source == accessLogSourceJournal {
		log.Printf("[shipper] access-log shipping started (journal=%s format=%s url=%s)", s.cfg.JournalUnit, s.cfg.Format, s.cfg.IngestURL)
	} else {
		log.Printf("[shipper] access-log shipping started (path=%s format=%s url=%s)", s.cfg.Path, s.cfg.Format, s.cfg.IngestURL)
	}
}

// Stop drains the tailer, flushes pending lines, and stops delivery.
func (s *Shipper) Stop() {
	s.source.Stop()
	s.flush()
	select {
	case <-s.stopCh:
	default:
		close(s.stopCh)
	}
	<-s.doneCh
}

func (s *Shipper) run() {
	defer close(s.doneCh)
	flushTicker := time.NewTicker(time.Duration(s.cfg.FlushIntervalSeconds) * time.Second)
	defer flushTicker.Stop()

	backoff := time.Second
	for {
		select {
		case <-s.stopCh:
			// Final delivery: ignore stopCh inside the loop (it is already
			// closed) but bound the attempt so shutdown stays prompt.
			s.deliverAll(true)
			return
		case <-flushTicker.C:
			s.flush()
			if s.deliverAll(false) {
				backoff = time.Second
			} else {
				// On failure, wait a bit longer before the next attempt.
				if backoff < 60*time.Second {
					backoff *= 2
				}
				select {
				case <-time.After(backoff):
				case <-s.stopCh:
					return
				}
			}
		}
	}
}

// flush turns the pending in-memory lines into a sealed spool batch file.
func (s *Shipper) flush() {
	s.flushMu.Lock()
	s.flushPendingLocked()
	s.flushMu.Unlock()

	// Cursor persistence happens only after the flush lock is released: each
	// source's Checkpoint calls canCheckpoint, which takes the same lock to prove
	// the in-memory queue is empty and the spool rename has completed.
	s.checkpointSource()
}

func (s *Shipper) flushPendingLocked() {
	s.mu.Lock()
	if len(s.pending) == 0 {
		s.mu.Unlock()
		return
	}
	lines := s.pending
	s.pending = nil
	s.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	enc := json.NewEncoder(gz)
	for _, l := range lines {
		_ = enc.Encode(spoolEvent{Offset: l.Offset, Raw: l.Line, ReadAt: now})
	}
	_ = gz.Close()

	data := buf.Bytes()
	sum := sha256.Sum256(data)
	batchID := hex.EncodeToString(sum[:])
	name := fmt.Sprintf("%d-%s.ndjson.gz", time.Now().UnixNano(), batchID[:16])
	path := filepath.Join(s.spoolDir, name)

	tmp := path + ".tmp"
	if err := writeAtomicDurable(path, tmp, data, 0600); err != nil {
		log.Printf("[shipper] spool write failed: %v", err)
		s.requeue(lines)
		return
	}

	s.enforceSpoolCap()
}

// writeAtomicDurable seals one spool batch with the ordering required by the
// source cursor checkpoint:
//
//	write tmp -> fsync(tmp) -> rename(tmp, final) -> fsync(spool directory)
//
// Only after this returns nil may a file/journal cursor advance. That keeps an
// abrupt power loss from preserving a cursor while losing the corresponding
// spool directory entry.
func writeAtomicDurable(finalPath, tmpPath string, data []byte, perm os.FileMode) (err error) {
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	removeTmp := true
	defer func() {
		if removeTmp {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmpPath, finalPath); err != nil {
		return err
	}
	removeTmp = false

	dir, err := os.Open(filepath.Dir(finalPath))
	if err != nil {
		return err
	}
	if err = dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	return dir.Close()
}

func (s *Shipper) checkpointSource() {
	if s.source == nil {
		return
	}
	if checkpointer, ok := s.source.(interface{ Checkpoint() }); ok {
		checkpointer.Checkpoint()
	}
}

func (s *Shipper) requeue(lines []rawLine) {
	s.mu.Lock()
	// These lines are older than anything appended while the disk write was in
	// progress, so prepend them to preserve source order on the next flush.
	pending := make([]rawLine, 0, len(lines)+len(s.pending))
	pending = append(pending, lines...)
	pending = append(pending, s.pending...)
	s.pending = pending
	s.mu.Unlock()
}

// listSpool returns sealed batch files (oldest first) and total size.
func (s *Shipper) listSpool() ([]string, int64, error) {
	entries, err := os.ReadDir(s.spoolDir)
	if err != nil {
		return nil, 0, err
	}
	var files []string
	var total int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if filepath.Ext(name) != ".gz" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, filepath.Join(s.spoolDir, name))
		total += info.Size()
	}
	sort.Strings(files) // unix-nano prefix => chronological
	return files, total, nil
}

// enforceSpoolCap drops the oldest batches when the spool exceeds the cap so a
// panel outage cannot fill the node disk. Dropped batches increment the counter.
// The quarantine subdirectory is capped as well (at a fraction of the spool
// cap): a prolonged permanent-rejection state (e.g. revoked token before the
// disable config reached this node) must not grow the disk unboundedly.
func (s *Shipper) enforceSpoolCap() {
	files, total, err := s.listSpool()
	if err != nil {
		return
	}
	for total > s.cfg.SpoolMaxBytes && len(files) > 0 {
		oldest := files[0]
		if info, e := os.Stat(oldest); e == nil {
			total -= info.Size()
		}
		_ = os.Remove(oldest)
		files = files[1:]
		s.mu.Lock()
		// Approximate dropped-events accounting: count one drop event per batch.
		s.droppedEvents++
		s.mu.Unlock()
		log.Printf("[shipper] spool cap exceeded, dropped oldest batch %s", filepath.Base(oldest))
	}
	s.mu.Lock()
	s.spoolBytes = total
	s.mu.Unlock()

	s.enforceQuarantineCap()
}

// enforceQuarantineCap bounds the quarantine directory to a quarter of the
// spool cap by deleting the oldest quarantined batches first.
func (s *Shipper) enforceQuarantineCap() {
	qdir := filepath.Join(s.spoolDir, "quarantine")
	entries, err := os.ReadDir(qdir)
	if err != nil {
		return
	}
	type qf struct {
		path string
		size int64
	}
	var files []qf
	var total int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, qf{path: filepath.Join(qdir, e.Name()), size: info.Size()})
		total += info.Size()
	}
	// Name prefix is unix-nano, so lexicographic order == chronological.
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })

	limit := s.cfg.SpoolMaxBytes / 4
	for total > limit && len(files) > 0 {
		oldest := files[0]
		_ = os.Remove(oldest.path)
		total -= oldest.size
		files = files[1:]
		log.Printf("[shipper] quarantine cap exceeded, dropped %s", filepath.Base(oldest.path))
	}
}

// deliverAll ships every sealed batch. Returns true if the spool ended empty
// (or there was nothing to do); false if any delivery failed. When final is
// true (shutdown path) the closed stopCh is ignored — a bounded final drain —
// otherwise the loop aborts as soon as stop is requested.
func (s *Shipper) deliverAll(final bool) bool {
	files, _, err := s.listSpool()
	if err != nil {
		return true
	}
	// Bound the shutdown drain so a dead panel cannot stall systemd stop: at
	// most ~8s of delivery attempts (client timeout is 30s but the first
	// network error aborts the loop anyway).
	var deadline time.Time
	if final {
		deadline = time.Now().Add(8 * time.Second)
	}
	allOK := true
	for _, f := range files {
		if final {
			if time.Now().After(deadline) {
				return false
			}
		} else {
			select {
			case <-s.stopCh:
				return false
			default:
			}
		}
		ok, retryable := s.deliverBatch(f)
		if ok {
			_ = os.Remove(f)
			s.mu.Lock()
			s.lastShipAt = time.Now().UTC()
			s.lastError = ""
			s.mu.Unlock()
		} else if !retryable {
			// Permanent rejection (4xx other than 429): quarantine so it does
			// not block the queue, and record the error.
			s.quarantine(f)
		} else {
			allOK = false
			break // stop on first retryable failure; preserve order
		}
	}
	s.enforceSpoolCap()
	return allOK
}

func (s *Shipper) quarantine(f string) {
	qdir := filepath.Join(s.spoolDir, "quarantine")
	_ = os.MkdirAll(qdir, 0755)
	_ = os.Rename(f, filepath.Join(qdir, filepath.Base(f)))
	s.mu.Lock()
	s.lastError = "batch rejected by panel (quarantined)"
	s.mu.Unlock()
	log.Printf("[shipper] batch %s permanently rejected, quarantined", filepath.Base(f))
}

// deliverBatch POSTs one gzipped NDJSON batch. Returns (ok, retryable).
func (s *Shipper) deliverBatch(path string) (bool, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, false
	}
	sum := sha256.Sum256(data)
	batchID := hex.EncodeToString(sum[:])

	req, err := http.NewRequest(http.MethodPost, s.cfg.IngestURL, bytes.NewReader(data))
	if err != nil {
		s.setErr(err.Error())
		return false, false
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.IngestToken)
	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("X-Batch-Id", batchID)

	resp, err := s.client.Do(req)
	if err != nil {
		s.setErr(err.Error())
		return false, true // network error -> retryable
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true, false
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		s.setErr(fmt.Sprintf("ingest status %d", resp.StatusCode))
		return false, true
	}
	// 4xx (other than 429): permanent.
	s.setErr(fmt.Sprintf("ingest status %d", resp.StatusCode))
	return false, false
}

func (s *Shipper) setErr(msg string) {
	s.mu.Lock()
	s.lastError = msg
	s.mu.Unlock()
}

// Status returns a snapshot for GET /info.
func (s *Shipper) Status() ShipperStatus {
	files, total, _ := s.listSpool()
	s.mu.Lock()
	defer s.mu.Unlock()
	last := ""
	if !s.lastShipAt.IsZero() {
		last = s.lastShipAt.Format(time.RFC3339)
	}
	return ShipperStatus{
		Enabled:       true,
		Source:        s.cfg.Source,
		Format:        s.cfg.Format,
		JournalUnit:   journalUnitForStatus(s.cfg),
		SourceReady:   s.source.Ready(),
		SpoolBytes:    total,
		SpoolBatches:  len(files),
		LagBytes:      s.source.LagBytes(),
		DroppedEvents: s.droppedEvents,
		InvalidEvents: s.invalidEvents,
		LastShipAt:    last,
		LastError:     s.lastError,
		SourceError:   accessLogSourceError(s.source),
		SourceWarning: accessLogSourceWarning(s.source),
	}
}

func journalUnitForStatus(cfg *AccessLogsConfig) string {
	if cfg.Source == accessLogSourceJournal {
		return cfg.JournalUnit
	}
	return ""
}

func accessLogSourceError(source accessLogSource) string {
	if reporter, ok := source.(interface{ LastError() string }); ok {
		return reporter.LastError()
	}
	return ""
}

func accessLogSourceWarning(source accessLogSource) string {
	if reporter, ok := source.(interface{ Warning() string }); ok {
		return reporter.Warning()
	}
	return ""
}

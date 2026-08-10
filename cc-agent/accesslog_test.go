package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFileTailerCursorWaitsForDurableSpool(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")
	cursorPath := filepath.Join(dir, "cursor.json")
	line := "2026/08/10 12:00:00 203.0.113.1:123 accepted tcp:example.com:443 [in -> direct] email: user\n"
	if err := os.WriteFile(logPath, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}

	durable := false
	var emitted []rawLine
	tailer := NewTailer(
		logPath,
		cursorPath,
		1024*1024,
		func(lines []rawLine) { emitted = append(emitted, lines...) },
		func() bool { return durable },
	)
	tailer.readAvailable()
	if len(emitted) != 1 || emitted[0].Line == "" {
		t.Fatalf("emitted = %+v", emitted)
	}
	if _, err := os.Stat(cursorPath); !os.IsNotExist(err) {
		t.Fatalf("cursor persisted before spool durability: %v", err)
	}

	// The in-memory read cursor still prevents duplicate emission while the same
	// process waits for its spool write to finish.
	tailer.readAvailable()
	if len(emitted) != 1 {
		t.Fatalf("line re-emitted before checkpoint: %+v", emitted)
	}

	durable = true
	tailer.Checkpoint()
	data, err := os.ReadFile(cursorPath)
	if err != nil {
		t.Fatalf("read cursor: %v", err)
	}
	var cursor cursorState
	if err := json.Unmarshal(data, &cursor); err != nil {
		t.Fatalf("decode cursor: %v", err)
	}
	if cursor.Offset != int64(len(line)) || cursor.Device == 0 || cursor.Inode == 0 {
		t.Fatalf("unexpected legacy cursor state: %+v", cursor)
	}
}

func TestFileTailerReadinessRequiresReadableSource(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")
	tailer := NewTailer(
		logPath,
		filepath.Join(dir, "cursor.json"),
		1024*1024,
		nil,
		nil,
	)

	tailer.readAvailable()
	if tailer.Ready() {
		t.Fatal("missing file source reported ready")
	}
	if tailer.LastError() == "" {
		t.Fatal("missing file source did not expose source_error")
	}

	if err := os.WriteFile(logPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	tailer.readAvailable()
	if !tailer.Ready() {
		t.Fatalf("readable file source not ready: %s", tailer.LastError())
	}
	if tailer.LastError() != "" {
		t.Fatalf("successful file source retained error: %s", tailer.LastError())
	}
}

func TestFileTailerSizeThresholdNeverTruncatesActiveWriter(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")
	cursorPath := filepath.Join(dir, "cursor.json")
	first := "2026/08/10 12:00:00 203.0.113.1:123 accepted tcp:first.example:443 [in -> direct] email: user\n"
	second := "2026/08/10 12:00:01 203.0.113.1:123 accepted tcp:second.example:443 [in -> direct] email: user\n"
	if err := os.WriteFile(logPath, []byte(first), 0600); err != nil {
		t.Fatal(err)
	}

	writer, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()

	var emitted []rawLine
	tailer := NewTailer(
		logPath,
		cursorPath,
		1, // force the warning path on the first read
		func(lines []rawLine) { emitted = append(emitted, lines...) },
		func() bool { return true },
	)
	tailer.readAvailable()
	if tailer.Warning() == "" {
		t.Fatal("oversized active log did not expose source_warning")
	}
	if _, err := writer.WriteString(second); err != nil {
		t.Fatal(err)
	}
	tailer.readAvailable()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != first+second {
		t.Fatalf("agent mutated active access log: %q", data)
	}
	if len(emitted) != 2 || emitted[0].Line == "" || emitted[1].Line == "" {
		t.Fatalf("emitted lines = %+v", emitted)
	}
}

func TestShipperFlushSealsSpoolBeforeFileCursorCheckpoint(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")
	line := "2026/08/10 12:00:00 203.0.113.1:123 accepted tcp:example.com:443 [in -> direct] email: user\n"
	if err := os.WriteFile(logPath, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{DataDir: dir, AccessLogs: AccessLogsConfig{
		Source:         accessLogSourceFile,
		Format:         accessLogFormatXray,
		Path:           logPath,
		BatchMaxEvents: 500,
		FileMaxBytes:   1024 * 1024,
		SpoolMaxBytes:  1024 * 1024,
	}}
	shipper := NewShipper(cfg)
	if err := os.MkdirAll(shipper.spoolDir, 0755); err != nil {
		t.Fatal(err)
	}
	tailer := shipper.source.(*Tailer)
	tailer.readAvailable()
	cursorPath := filepath.Join(dir, "accesslog-cursor.json")
	if _, err := os.Stat(cursorPath); !os.IsNotExist(err) {
		t.Fatalf("cursor persisted while line was only in memory: %v", err)
	}

	shipper.flush()
	spoolFiles, _, err := shipper.listSpool()
	if err != nil || len(spoolFiles) != 1 {
		t.Fatalf("sealed spool files=%v err=%v", spoolFiles, err)
	}
	if _, err := os.Stat(cursorPath); err != nil {
		t.Fatalf("cursor not checkpointed after durable spool: %v", err)
	}
}

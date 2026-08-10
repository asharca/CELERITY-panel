package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAtomicDurableSealsBatchAndRemovesTemp(t *testing.T) {
	dir := t.TempDir()
	finalPath := filepath.Join(dir, "batch.ndjson.gz")
	tmpPath := finalPath + ".tmp"
	want := []byte("durable spool payload")

	if err := writeAtomicDurable(finalPath, tmpPath, want, 0600); err != nil {
		t.Fatalf("writeAtomicDurable: %v", err)
	}
	got, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatalf("read final: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("final payload = %q", got)
	}
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Fatalf("temporary file still exists: %v", err)
	}
	info, err := os.Stat(finalPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
}

func TestWriteAtomicDurableFailureDoesNotCreateFinal(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")
	finalPath := filepath.Join(dir, "batch.ndjson.gz")
	tmpPath := finalPath + ".tmp"
	if err := writeAtomicDurable(finalPath, tmpPath, []byte("payload"), 0600); err == nil {
		t.Fatal("expected missing spool directory to fail")
	}
	if _, err := os.Stat(finalPath); !os.IsNotExist(err) {
		t.Fatalf("final unexpectedly exists: %v", err)
	}
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Fatalf("temporary unexpectedly exists: %v", err)
	}
}

func TestXrayJournalFiltersProcessNoiseBeforeSpooling(t *testing.T) {
	access := rawLine{Line: "2026/08/10 12:00:00 203.0.113.1:123 accepted tcp:example.com:443 [in -> direct] email: user"}
	handshake := rawLine{Line: "2026/08/10 12:00:01 from 203.0.113.2:456 rejected proxy/vless/encoding: invalid request user id: bad"}
	warning := rawLine{Line: "2026/08/10 12:00:02 [Warning] transport/internet: failed to accept connection"}
	startup := rawLine{Line: "Xray 1.260206.0 started"}

	shipper := &Shipper{cfg: &AccessLogsConfig{
		Source:         accessLogSourceJournal,
		Format:         accessLogFormatXray,
		BatchMaxEvents: 100,
	}}
	shipper.onLines([]rawLine{access, warning, handshake, startup})

	if len(shipper.pending) != 2 {
		t.Fatalf("journal pending records = %d, want 2", len(shipper.pending))
	}
	if shipper.pending[0].Line != access.Line || shipper.pending[1].Line != handshake.Line {
		t.Fatalf("journal filter retained unexpected records: %#v", shipper.pending)
	}

	// Legacy file mode remains a raw access-file tailer. Do not change its
	// historical behavior while migrating newly provisioned nodes to journald.
	legacy := &Shipper{cfg: &AccessLogsConfig{
		Source:         accessLogSourceFile,
		Format:         accessLogFormatXray,
		BatchMaxEvents: 100,
	}}
	legacy.onLines([]rawLine{warning})
	if len(legacy.pending) != 1 {
		t.Fatalf("legacy file pending records = %d, want 1", len(legacy.pending))
	}
}

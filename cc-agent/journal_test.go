package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func waitForJournalCondition(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for journal source state")
}

func TestJournalctlReadyHelperProcess(t *testing.T) {
	if os.Getenv("CC_AGENT_JOURNAL_READY_HELPER") != "1" {
		return
	}
	for {
		time.Sleep(time.Hour)
	}
}

func TestJournalctlArgs(t *testing.T) {
	base := []string{
		"--unit=hysteria-server",
		"--output=json",
		"--no-pager",
		"--follow",
		"--quiet",
	}

	if got, want := journalctlArgs("hysteria-server", "", 1786350896789123), append(append([]string{}, base...), "--since=@1786350896", "--no-tail"); !reflect.DeepEqual(got, want) {
		t.Fatalf("baseline args = %#v, want %#v", got, want)
	}
	if got, want := journalctlArgs("hysteria-server", "s=cursor;i=1", 1786350896789123), append(append([]string{}, base...), "--after-cursor=s=cursor;i=1", "--no-tail"); !reflect.DeepEqual(got, want) {
		t.Fatalf("resume args = %#v, want %#v", got, want)
	}
	if got, want := journalctlArgs("hysteria-server", "", 0), append(append([]string{}, base...), "--lines=0"); !reflect.DeepEqual(got, want) {
		t.Fatalf("legacy no-baseline args = %#v, want %#v", got, want)
	}
}

func TestJournalSourceNotReadyWhileBaselineCheckpointDeferred(t *testing.T) {
	dir := t.TempDir()
	cursorPath := filepath.Join(dir, "cursor.json")
	var commandStarts atomic.Int32
	tailer := NewJournalTailer("hysteria-server", cursorPath, nil, func() bool { return false })
	tailer.command = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		commandStarts.Add(1)
		return exec.CommandContext(ctx, filepath.Join(dir, "must-not-start"))
	}

	go tailer.Run()
	defer tailer.Stop()
	waitForJournalCondition(t, func() bool { return tailer.LastError() != "" })

	if tailer.Ready() {
		t.Fatal("journal source reported ready before durable baseline")
	}
	if commandStarts.Load() != 0 {
		t.Fatalf("journalctl started %d times before durable baseline", commandStarts.Load())
	}
	if _, err := os.Stat(cursorPath); !os.IsNotExist(err) {
		t.Fatalf("deferred baseline unexpectedly created state: %v", err)
	}
}

func TestJournalSourceNotReadyWhenCommandStartFails(t *testing.T) {
	dir := t.TempDir()
	cursorPath := filepath.Join(dir, "cursor.json")
	missingCommand := filepath.Join(dir, "missing-journalctl")
	var commandStarts atomic.Int32
	tailer := NewJournalTailer("hysteria-server", cursorPath, nil, nil)
	tailer.command = func(ctx context.Context, _ string, args ...string) *exec.Cmd {
		commandStarts.Add(1)
		return exec.CommandContext(ctx, missingCommand, args...)
	}

	go tailer.Run()
	defer tailer.Stop()
	waitForJournalCondition(t, func() bool {
		return commandStarts.Load() > 0 && tailer.LastError() != ""
	})

	if tailer.Ready() {
		t.Fatal("journal source reported ready after command Start failure")
	}
	if _, err := os.Stat(cursorPath); err != nil {
		t.Fatalf("durable baseline missing before Start attempt: %v", err)
	}
	if tailer.LastError() == "" {
		t.Fatal("command Start failure did not remain in source_error")
	}
	status := (&Shipper{
		cfg:      &AccessLogsConfig{Source: accessLogSourceJournal, Format: accessLogFormatHysteria2JSON},
		spoolDir: dir,
		source:   tailer,
	}).Status()
	if status.SourceReady || status.SourceError == "" {
		t.Fatalf("shipper source status = ready:%v error:%q", status.SourceReady, status.SourceError)
	}
}

func TestJournalSourceReadyOnlyAfterDurableBaselineAndCommandStart(t *testing.T) {
	dir := t.TempDir()
	cursorPath := filepath.Join(dir, "cursor.json")
	tailer := NewJournalTailer("hysteria-server", cursorPath, nil, nil)
	tailer.command = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestJournalctlReadyHelperProcess$")
		cmd.Env = append(os.Environ(), "CC_AGENT_JOURNAL_READY_HELPER=1")
		return cmd
	}

	go tailer.Run()
	defer tailer.Stop()
	waitForJournalCondition(t, tailer.Ready)

	if tailer.LastError() != "" {
		t.Fatalf("ready journal source retained error: %s", tailer.LastError())
	}
	data, err := os.ReadFile(cursorPath)
	if err != nil {
		t.Fatalf("read durable baseline: %v", err)
	}
	var state journalCursorState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("decode durable baseline: %v", err)
	}
	if state.Cursor != "" || state.RealtimeUsec == 0 {
		t.Fatalf("invalid durable baseline before readiness: %+v", state)
	}
}

func TestInitialJournalBaselineSurvivesCrashBeforeFirstCursor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "cursor.json")
	const baselineUsec = uint64(1786350896789123)
	pending := false

	firstProcess := NewJournalTailer("hysteria-server", path, nil, func() bool { return !pending })
	if firstProcess.loadCursor() {
		t.Fatal("unexpected pre-existing cursor state")
	}
	if err := firstProcess.initializeBaseline(baselineUsec); err != nil {
		t.Fatalf("initialize baseline: %v", err)
	}

	// The activating process starts from the durable boundary. Flooring the
	// timestamp may replay up to one second, but no request can fall into an
	// unobserved baseline-to-journalctl attach gap.
	firstArgs := journalctlArgs("hysteria-server", "", baselineUsec)
	if got, want := firstArgs[len(firstArgs)-2:], []string{"--since=@1786350896", "--no-tail"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("first command args = %#v", firstArgs)
	}

	// Model the exact loss window: journalctl emitted the first request, its
	// in-memory cursor advanced, but the shipper has not sealed the pending line.
	// Checkpoint must leave the on-disk state at the startup baseline.
	pending = true
	firstProcess.setPosition("s=first-request;i=1", baselineUsec+1234)
	firstProcess.Checkpoint()
	var diskState journalCursorState
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read baseline state: %v", err)
	}
	if err := json.Unmarshal(data, &diskState); err != nil {
		t.Fatalf("decode baseline state: %v", err)
	}
	if diskState.Cursor != "" || diskState.RealtimeUsec != baselineUsec {
		t.Fatalf("pending request advanced durable state: %+v", diskState)
	}

	// Simulate SIGKILL before the first request reaches a sealed spool/cursor
	// checkpoint: a fresh process must recover from the baseline, not from now.
	secondProcess := NewJournalTailer("hysteria-server", path, nil, nil)
	if !secondProcess.loadCursor() {
		t.Fatal("durable baseline was not reloadable after simulated crash")
	}
	secondProcess.mu.Lock()
	state := journalCursorState{Cursor: secondProcess.cursor, RealtimeUsec: secondProcess.realtimeUsec}
	secondProcess.mu.Unlock()
	if state.Cursor != "" || state.RealtimeUsec != baselineUsec {
		t.Fatalf("reloaded baseline = %+v", state)
	}
	recoveryArgs := journalctlArgs("hysteria-server", state.Cursor, state.RealtimeUsec)
	if got, want := recoveryArgs[len(recoveryArgs)-2:], []string{"--since=@1786350896", "--no-tail"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("crash recovery args = %#v", recoveryArgs)
	}

	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("baseline state mode/stat = %v, err=%v", info, err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("baseline temp file remains: %v", err)
	}
}

func TestParseJournalLine(t *testing.T) {
	message := `{"time":1786350896789,"msg":"TCP request","addr":"203.0.113.1:1","id":"u","reqAddr":"example.com:443"}`
	encoded, err := json.Marshal(map[string]any{
		"__CURSOR":             "s=abc;i=123",
		"__REALTIME_TIMESTAMP": "1786350896789123",
		"MESSAGE":              message,
	})
	if err != nil {
		t.Fatal(err)
	}

	gotMessage, cursor, realtimeUsec, offset, ok := parseJournalLine(encoded)
	if !ok || gotMessage != message || cursor != "s=abc;i=123" || realtimeUsec != 1786350896789123 {
		t.Fatalf("got message=%q cursor=%q realtime=%d ok=%v", gotMessage, cursor, realtimeUsec, ok)
	}
	if offset == 0 || offset != journalCursorOffset(cursor) {
		t.Fatalf("unexpected stable cursor offset %d", offset)
	}

	if _, _, _, _, ok := parseJournalLine([]byte(`{"MESSAGE":"missing cursor"}`)); ok {
		t.Fatal("entry without cursor must be rejected")
	}
	if _, _, _, _, ok := parseJournalLine([]byte(`{"__CURSOR":"c","MESSAGE":"missing timestamp"}`)); ok {
		t.Fatal("entry without realtime timestamp must be rejected")
	}
	if _, _, _, _, ok := parseJournalLine([]byte(`{"__CURSOR":"c","__REALTIME_TIMESTAMP":"invalid"}`)); ok {
		t.Fatal("entry with malformed realtime timestamp must be rejected")
	}
}

func TestJournalCursorPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "cursor.json")
	tailer := NewJournalTailer("hysteria-server", path, nil, nil)
	tailer.setPosition("s=first;i=9", 1786350896789123)
	tailer.saveCursor()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("cursor file not persisted: %v", err)
	}
	reloaded := NewJournalTailer("hysteria-server", path, nil, nil)
	reloaded.loadCursor()
	reloaded.mu.Lock()
	gotCursor := reloaded.cursor
	gotRealtime := reloaded.realtimeUsec
	reloaded.mu.Unlock()
	if gotCursor != "s=first;i=9" || gotRealtime != 1786350896789123 {
		t.Fatalf("reloaded cursor=%q realtime_usec=%d", gotCursor, gotRealtime)
	}
}

func TestJournalCheckpointWaitsForDurableSpool(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cursor.json")
	durable := false
	tailer := NewJournalTailer("hysteria-server", path, nil, func() bool { return durable })
	tailer.setPosition("s=pending;i=10", 1786350896789123)
	tailer.Checkpoint()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("cursor persisted before spool was durable: %v", err)
	}

	durable = true
	tailer.Checkpoint()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("cursor not persisted after durable spool: %v", err)
	}
}

func TestInvalidJournalCursorFallsBackToCheckpointTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cursor.json")
	tailer := NewJournalTailer("hysteria-server", path, nil, nil)
	tailer.setPosition("s=vacuumed;i=11", 1786350896789123)
	tailer.saveCursor()
	tailer.clearCursor()

	reloaded := NewJournalTailer("hysteria-server", path, nil, nil)
	reloaded.loadCursor()
	reloaded.mu.Lock()
	cursor := reloaded.cursor
	realtimeUsec := reloaded.realtimeUsec
	reloaded.mu.Unlock()
	if cursor != "" {
		t.Fatalf("cursor = %q after invalidation", cursor)
	}
	args := journalctlArgs("hysteria-server", cursor, realtimeUsec)
	if !reflect.DeepEqual(args[len(args)-2:], []string{"--since=@1786350896", "--no-tail"}) {
		t.Fatalf("fallback args = %#v", args)
	}
}

func TestLegacyCursorWithoutRealtimeFallsBackToNow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cursor.json")
	if err := os.WriteFile(path, []byte(`{"cursor":"s=legacy;i=1"}`), 0600); err != nil {
		t.Fatal(err)
	}
	tailer := NewJournalTailer("hysteria-server", path, nil, nil)
	tailer.loadCursor()
	tailer.clearCursor()
	tailer.mu.Lock()
	cursor := tailer.cursor
	realtimeUsec := tailer.realtimeUsec
	tailer.mu.Unlock()
	args := journalctlArgs("hysteria-server", cursor, realtimeUsec)
	if args[len(args)-1] != "--lines=0" {
		t.Fatalf("legacy fallback args = %#v", args)
	}
}

func TestValidSystemdUnitName(t *testing.T) {
	valid := []string{"hysteria-server", "hysteria-server.service", "hysteria@edge-1.service"}
	for _, unit := range valid {
		if !validSystemdUnitName(unit) {
			t.Errorf("expected %q to be valid", unit)
		}
	}

	invalid := []string{"", "-unit", "../hysteria.service", "hysteria server", "hysteria/service", "hysteria..service"}
	for _, unit := range invalid {
		if validSystemdUnitName(unit) {
			t.Errorf("expected %q to be invalid", unit)
		}
	}
}

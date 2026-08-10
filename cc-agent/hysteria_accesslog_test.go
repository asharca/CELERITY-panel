package main

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

// Go/RE2 equivalent of the panel's CH_LINE_RE. This contract test protects the
// agent-side normalization from silently producing parse_ok=0 ClickHouse rows.
var panelAccessLineContractRE = regexp.MustCompile(
	`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+` +
		`(?:from\s+)?(\S+?)\s+` +
		`(accepted|rejected|blocked)\s+` +
		`(tcp|udp)\s*:\s*(\S+?)` +
		`(?:\s+\[([^\]]*)\])?` +
		`(?:\s+email:\s*(\S(?:.*\S)?))?\s*$`,
)

func TestNormalizeHysteria2TCPRequest(t *testing.T) {
	line := `{"time":1786350896789,"level":"debug","msg":"TCP request","addr":"203.0.113.7:54321","id":"user-42","reqAddr":"example.com:443"}`

	got, ok := normalizeHysteria2AccessLine(line)
	if !ok {
		t.Fatal("expected TCP request to be normalized")
	}
	want := "2026/08/10 08:34:56.789 203.0.113.7:54321 accepted tcp:example.com:443 [hysteria2 -> direct] email: user-42"
	if got != want {
		t.Fatalf("normalized line mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestNormalizeHysteria2UDPRequestRetainsSession(t *testing.T) {
	line := `{"time":"2026-08-10T12:34:56.123456Z","level":"debug","msg":"UDP request","addr":"[2001:db8::10]:4567","id":"507f1f77bcf86cd799439011","sessionID":37,"reqAddr":"dns.example:53"}`

	got, ok := normalizeHysteria2AccessLine(line)
	if !ok {
		t.Fatal("expected UDP request to be normalized")
	}
	want := "2026/08/10 12:34:56.123 [2001:db8::10]:4567 accepted udp:dns.example:53 [hysteria2/session-37 -> direct] email: 507f1f77bcf86cd799439011"
	if got != want {
		t.Fatalf("normalized line mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestNormalizedHysteria2LineMatchesPanelClickHouseContract(t *testing.T) {
	line := `{"time":1786350896789,"msg":"TCP request","addr":"203.0.113.7:54321","id":"user-42","reqAddr":"api.example.com:8443"}`
	normalized, ok := normalizeHysteria2AccessLine(line)
	if !ok {
		t.Fatal("expected request to normalize")
	}
	groups := panelAccessLineContractRE.FindStringSubmatch(normalized)
	if len(groups) != 8 {
		t.Fatalf("normalized line does not match panel CH_LINE_RE contract: %q", normalized)
	}
	if groups[2] != "203.0.113.7:54321" || groups[3] != "accepted" || groups[4] != "tcp" ||
		groups[5] != "api.example.com:8443" || groups[6] != "hysteria2 -> direct" || groups[7] != "user-42" {
		t.Fatalf("unexpected panel captures: %#v", groups)
	}
}

func TestNormalizeHysteria2AllowsInternalAccountSpace(t *testing.T) {
	line := `{"time":1786350896789,"msg":"TCP request","addr":"203.0.113.7:54321","id":"Team Alice","reqAddr":"api.example.com:8443"}`
	normalized, ok := normalizeHysteria2AccessLine(line)
	if !ok {
		t.Fatal("expected internal ordinary space in account ID to be accepted")
	}
	groups := panelAccessLineContractRE.FindStringSubmatch(normalized)
	if len(groups) != 8 || groups[7] != "Team Alice" {
		t.Fatalf("account capture failed: normalized=%q groups=%#v", normalized, groups)
	}
}

func TestParseHysteria2LifecycleEvents(t *testing.T) {
	tests := []struct {
		message  string
		wantNet  string
		wantKind hysteria2EventKind
	}{
		{"TCP request", "tcp", hysteria2EventRequest},
		{"TCP closed", "tcp", hysteria2EventClosed},
		{"TCP error", "tcp", hysteria2EventError},
		{"UDP request", "udp", hysteria2EventRequest},
		{"UDP closed", "udp", hysteria2EventClosed},
		{"UDP error", "udp", hysteria2EventError},
	}

	for _, tt := range tests {
		t.Run(strings.ReplaceAll(tt.message, " ", "_"), func(t *testing.T) {
			line := `{"time":1786350896789,"msg":"` + tt.message + `","addr":"198.51.100.2:1234","id":"u","reqAddr":"target.test:443","sessionID":9,"error":"dial failed"}`
			event, err := parseHysteria2Event(line)
			if err != nil {
				t.Fatalf("parse failed: %v", err)
			}
			if event.Network != tt.wantNet || event.Kind != tt.wantKind {
				t.Fatalf("got network=%q kind=%d", event.Network, event.Kind)
			}
			if event.SessionID != 9 || event.ID != "u" || event.ReqAddr != "target.test:443" {
				t.Fatalf("event fields not retained: %+v", event)
			}

			_, stored := normalizeHysteria2AccessLine(line)
			if stored != (tt.wantKind == hysteria2EventRequest) {
				t.Fatalf("stored=%v for kind=%d", stored, tt.wantKind)
			}
		})
	}
}

func TestNormalizeHysteria2RejectsUnrelatedOrUnsafeLines(t *testing.T) {
	tests := []string{
		`not-json`,
		`{"time":1786350896789,"msg":"client connected","addr":"203.0.113.1:1","id":"u"}`,
		`{"time":1786350896789,"msg":"TCP request","addr":"203.0.113.1:1","id":"","reqAddr":"example.com:443"}`,
		`{"time":1786350896789,"msg":"TCP request","addr":"203.0.113.1:1","id":"bad\tid","reqAddr":"example.com:443"}`,
		`{"time":1786350896789,"msg":"TCP request","addr":"203.0.113.1:1","id":" user","reqAddr":"example.com:443"}`,
		`{"time":1786350896789,"msg":"TCP request","addr":"203.0.113.1:1","id":"bad\nemail","reqAddr":"example.com:443"}`,
		`{"time":1786350896789,"msg":"TCP request","addr":"203.0.113.1:1","id":"bad\u0000email","reqAddr":"example.com:443"}`,
		`{"time":1786350896789,"msg":"TCP request","addr":"203.0.113.1 accepted udp:evil.test:53","id":"u","reqAddr":"example.com:443"}`,
		`{"time":1786350896789,"msg":"TCP request","addr":"203.0.113.1:1","id":"u","reqAddr":"example.com:443\nemail: attacker"}`,
		`{"time":1786350896789,"msg":"TCP request","addr":"203.0.113.1:1","id":"u","reqAddr":"missing-port"}`,
		`{"msg":"TCP request","addr":"203.0.113.1:1","id":"u","reqAddr":"example.com:443"}`,
	}
	for _, line := range tests {
		if got, ok := normalizeHysteria2AccessLine(line); ok {
			t.Fatalf("unexpected normalized line %q from %s", got, line)
		}
	}
}

func TestShipperCountsInvalidHysteria2Requests(t *testing.T) {
	shipper := &Shipper{cfg: &AccessLogsConfig{
		Format:         accessLogFormatHysteria2JSON,
		BatchMaxEvents: 100,
	}}
	shipper.onLines([]rawLine{
		{Offset: 1, Line: `{"time":1786350896789,"msg":"client connected","addr":"203.0.113.1:1","id":"u"}`},
		{Offset: 2, Line: `{"time":1786350896789,"msg":"TCP request","addr":"203.0.113.1:1","id":"bad\tid","reqAddr":"example.com:443"}`},
		{Offset: 3, Line: `{"time":1786350896789,"msg":"TCP request","addr":"203.0.113.1:1","id":"u","reqAddr":"example.com:443"}`},
	})

	shipper.mu.Lock()
	defer shipper.mu.Unlock()
	if shipper.invalidEvents != 1 {
		t.Fatalf("invalidEvents = %d, want 1", shipper.invalidEvents)
	}
	if len(shipper.pending) != 1 || shipper.pending[0].Offset != 3 {
		t.Fatalf("pending = %+v", shipper.pending)
	}
}

func TestParseHysteria2EpochMillisFraction(t *testing.T) {
	ts, err := parseHysteria2Time([]byte(`1786350896789.25`))
	if err != nil {
		t.Fatalf("parse time: %v", err)
	}
	want := time.Date(2026, 8, 10, 8, 34, 56, 789250000, time.UTC)
	if !ts.Equal(want) {
		t.Fatalf("got %s want %s", ts, want)
	}
}

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type hysteria2EventKind uint8

const (
	hysteria2EventUnknown hysteria2EventKind = iota
	hysteria2EventRequest
	hysteria2EventClosed
	hysteria2EventError
)

// hysteria2AccessEvent is the stable subset of Hysteria 2's zap JSON event
// logger. The upstream server emits these fields from EventLogger methods:
// msg, addr, id, reqAddr and (for UDP) sessionID.
type hysteria2AccessEvent struct {
	Time      time.Time
	Kind      hysteria2EventKind
	Network   string
	Addr      string
	ID        string
	ReqAddr   string
	SessionID uint32
	Error     string
}

type hysteria2JSONLine struct {
	Time      json.RawMessage `json:"time"`
	Message   string          `json:"msg"`
	Addr      string          `json:"addr"`
	ID        string          `json:"id"`
	ReqAddr   string          `json:"reqAddr"`
	SessionID json.RawMessage `json:"sessionID"`
	Error     string          `json:"error"`
}

// parseHysteria2Event recognizes every TCP/UDP request lifecycle event. The
// shipper deliberately stores only request events: closed/error lines describe
// the same destination and would double-count one access in the current panel
// schema. Recognizing them here still makes the filtering explicit and tested.
func parseHysteria2Event(line string) (hysteria2AccessEvent, error) {
	var raw hysteria2JSONLine
	dec := json.NewDecoder(strings.NewReader(line))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return hysteria2AccessEvent{}, fmt.Errorf("decode Hysteria 2 JSON: %w", err)
	}

	network, kind := classifyHysteria2Message(raw.Message)
	if kind == hysteria2EventUnknown {
		return hysteria2AccessEvent{}, fmt.Errorf("not a Hysteria 2 access event")
	}

	ts, err := parseHysteria2Time(raw.Time)
	if err != nil {
		return hysteria2AccessEvent{}, err
	}

	event := hysteria2AccessEvent{
		Time:    ts,
		Kind:    kind,
		Network: network,
		// Do not trim identity/address fields: any whitespace makes the legacy
		// one-line ingest shape ambiguous and must be rejected by validation.
		Addr:    raw.Addr,
		ID:      raw.ID,
		ReqAddr: raw.ReqAddr,
		Error:   raw.Error,
	}
	if len(raw.SessionID) > 0 && !bytes.Equal(raw.SessionID, []byte("null")) {
		sessionID, err := parseUint32JSON(raw.SessionID)
		if err != nil {
			return hysteria2AccessEvent{}, fmt.Errorf("invalid Hysteria 2 sessionID: %w", err)
		}
		event.SessionID = sessionID
	}
	return event, nil
}

func classifyHysteria2Message(message string) (string, hysteria2EventKind) {
	switch strings.ToLower(strings.TrimSpace(message)) {
	case "tcp request":
		return "tcp", hysteria2EventRequest
	case "tcp closed":
		return "tcp", hysteria2EventClosed
	case "tcp error":
		return "tcp", hysteria2EventError
	case "udp request":
		return "udp", hysteria2EventRequest
	case "udp closed":
		return "udp", hysteria2EventClosed
	case "udp error":
		return "udp", hysteria2EventError
	default:
		return "", hysteria2EventUnknown
	}
}

func parseHysteria2Time(raw json.RawMessage) (time.Time, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return time.Time{}, fmt.Errorf("Hysteria 2 event has no time")
	}

	// The official JSON logger uses zap's EpochMillisTimeEncoder. Accept an
	// RFC3339 string too so direct file sources remain compatible with wrappers
	// that rewrite the timestamp representation without changing event fields.
	if raw[0] == '"' {
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return time.Time{}, fmt.Errorf("invalid Hysteria 2 time: %w", err)
		}
		if _, ok := new(big.Rat).SetString(value); ok {
			return timeFromEpochMillis(value)
		}
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
			if parsed, err := time.Parse(layout, value); err == nil {
				return parsed.UTC(), nil
			}
		}
		return time.Time{}, fmt.Errorf("invalid Hysteria 2 time %q", value)
	}

	return timeFromEpochMillis(string(raw))
}

func timeFromEpochMillis(value string) (time.Time, error) {
	millis, ok := new(big.Rat).SetString(value)
	if !ok || millis.Sign() <= 0 {
		return time.Time{}, fmt.Errorf("invalid epoch milliseconds")
	}

	// Convert milliseconds to integer nanoseconds with exact decimal math. A
	// float64 loses sub-millisecond precision for present-day epoch values.
	nanos := new(big.Rat).Mul(millis, big.NewRat(int64(time.Millisecond), 1))
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(nanos.Num(), nanos.Denom(), remainder)
	// Round a sub-nanosecond remainder to the nearest nanosecond.
	if new(big.Int).Lsh(remainder, 1).Cmp(nanos.Denom()) >= 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	if !quotient.IsInt64() {
		return time.Time{}, fmt.Errorf("epoch milliseconds out of range")
	}
	totalNanos := quotient.Int64()
	return time.Unix(totalNanos/int64(time.Second), totalNanos%int64(time.Second)).UTC(), nil
}

func parseUint32JSON(raw json.RawMessage) (uint32, error) {
	value := strings.Trim(string(raw), `"`)
	n, err := strconv.ParseUint(value, 10, 32)
	return uint32(n), err
}

// normalizeHysteria2AccessLine converts one HY2 request event to the legacy
// Xray access-line shape understood by the existing panel/ClickHouse ingest:
//
//	timestamp source accepted network:destination [in -> out] email: id
//
// UDP's session ID is retained in the inbound tag of the raw line. The current
// structured schema has no session column, while the raw record stays searchable
// and no panel-side contract change is required.
func normalizeHysteria2AccessLine(line string) (string, bool) {
	normalized, result := normalizeHysteria2AccessLineDetailed(line)
	return normalized, result == hysteria2NormalizeAccepted
}

type hysteria2NormalizeResult uint8

const (
	hysteria2NormalizeIgnored hysteria2NormalizeResult = iota
	hysteria2NormalizeAccepted
	hysteria2NormalizeInvalid
)

func normalizeHysteria2AccessLineDetailed(line string) (string, hysteria2NormalizeResult) {
	event, err := parseHysteria2Event(line)
	if err != nil || event.Kind != hysteria2EventRequest {
		return "", hysteria2NormalizeIgnored
	}
	if event.Time.IsZero() || !safeAccessID(event.ID) || !validHostPortToken(event.Addr) || !validHostPortToken(event.ReqAddr) {
		return "", hysteria2NormalizeInvalid
	}

	inboundTag := "hysteria2"
	if event.Network == "udp" {
		inboundTag = fmt.Sprintf("hysteria2/session-%d", event.SessionID)
	}

	return fmt.Sprintf(
		"%s %s accepted %s:%s [%s -> direct] email: %s",
		event.Time.UTC().Format("2006/01/02 15:04:05.000"),
		event.Addr,
		event.Network,
		event.ReqAddr,
		inboundTag,
		event.ID,
	), hysteria2NormalizeAccepted
}

func safeAccessID(value string) bool {
	if value == "" || len(value) > 1024 || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		// Account IDs in the panel may contain an ordinary internal space. Other
		// whitespace (tabs, line separators, etc.) and all controls would make the
		// normalized line ambiguous or allow record injection.
		if unicode.IsControl(r) || (unicode.IsSpace(r) && r != ' ') {
			return false
		}
	}
	return true
}

func validHostPortToken(value string) bool {
	if value == "" || len(value) > 4096 {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" || port == "" {
		return false
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	return err == nil && portNumber > 0
}

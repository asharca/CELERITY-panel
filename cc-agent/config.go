package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

type TLSConfig struct {
	Enabled bool   `json:"enabled"`
	Cert    string `json:"cert"`
	Key     string `json:"key"`
}

const (
	accessLogSourceFile    = "file"
	accessLogSourceJournal = "journal"

	accessLogFormatXray          = "xray"
	accessLogFormatHysteria2JSON = "hysteria2-json"
)

var systemdUnitNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}$`)
var journalSourceTagRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// JournalSource identifies one systemd journal stream. Tag is appended to
// normalized HY2 inbound tags so multiple services on the same physical host
// remain distinguishable after they share a single cc-agent and ingest token.
type JournalSource struct {
	Unit string `json:"unit"`
	Tag  string `json:"tag"`
}

// AccessLogsConfig configures the opt-in access-log tail/ship module.
// When Enabled is false (or the whole block is absent) the module stays inert
// and the agent behaves exactly like older versions — this preserves
// backward/downgrade compatibility with panels that never write this block.
type AccessLogsConfig struct {
	Enabled bool `json:"enabled"`

	// Source selects how log lines enter the shipper. "file" keeps the legacy
	// Xray file tailer; "journal" follows one systemd unit with journalctl.
	Source string `json:"source"`

	// Format selects the input parser. Xray lines already match the panel's raw
	// ingest contract. Hysteria 2 JSON request events are normalized to that
	// same contract before spooling, so older panel ingest endpoints still work.
	Format string `json:"format"`

	// Path to the Xray access log file the agent tails.
	Path string `json:"path"`

	// JournalUnit is the legacy single journal source. It is retained so older
	// panel versions and existing configs remain compatible. New configs may
	// supply JournalSources instead.
	JournalUnit string `json:"journal_unit"`

	// JournalSources follows multiple systemd units through independent cursors.
	// It is only meaningful for Source="journal". The first source also becomes
	// JournalUnit for compatibility with older status consumers.
	JournalSources []JournalSource `json:"journal_sources,omitempty"`

	// IngestURL is the full panel endpoint that receives NDJSON+gzip batches.
	IngestURL string `json:"ingest_url"`

	// IngestToken is the per-node Bearer credential sent with every batch.
	IngestToken string `json:"ingest_token"`

	// InsecureTLS disables TLS verification for the ingest connection. Used
	// only when the panel serves a self-signed certificate (mirrors the
	// existing agent TLS behavior).
	InsecureTLS bool `json:"insecure_tls"`

	// SpoolMaxBytes caps the on-disk batch spool. Oldest batches are dropped
	// past this cap (with a dropped-events counter) so a long panel outage
	// cannot fill the node disk.
	SpoolMaxBytes int64 `json:"spool_max_bytes"`

	// BatchMaxEvents / FlushIntervalSeconds control batching cadence.
	BatchMaxEvents       int `json:"batch_max_events"`
	FlushIntervalSeconds int `json:"flush_interval_seconds"`

	// FileMaxBytes is a warning threshold. The agent intentionally never
	// truncates an active Xray log because Xray does not coordinate its O_APPEND
	// writer with external rotation, which would create a data-loss race.
	FileMaxBytes int64 `json:"file_max_bytes"`
}

// applyDefaults fills unset access-log fields with conservative defaults.
func (c *AccessLogsConfig) applyDefaults() {
	if c.Source == "" {
		c.Source = accessLogSourceFile
	}
	if c.Format == "" {
		c.Format = accessLogFormatXray
	}
	if c.Path == "" {
		c.Path = "/var/log/xray/access.log"
	}
	if c.JournalUnit == "" && len(c.JournalSources) > 0 {
		c.JournalUnit = c.JournalSources[0].Unit
	}
	if c.JournalUnit == "" {
		c.JournalUnit = "hysteria-server"
	}
	if c.SpoolMaxBytes <= 0 {
		c.SpoolMaxBytes = 200 * 1024 * 1024 // 200 MB
	}
	if c.BatchMaxEvents <= 0 {
		c.BatchMaxEvents = 500
	}
	if c.FlushIntervalSeconds <= 0 {
		c.FlushIntervalSeconds = 5
	}
	if c.FileMaxBytes <= 0 {
		c.FileMaxBytes = 64 * 1024 * 1024 // 64 MB
	}
}

// validate rejects unsupported source/format values and unsafe systemd unit
// names before the agent starts. The unit is still passed to exec.Command as a
// separate argv item, but the allowlist prevents surprising journal selectors.
func (c *AccessLogsConfig) validate() error {
	switch c.Source {
	case accessLogSourceFile, accessLogSourceJournal:
	default:
		return fmt.Errorf("access_logs.source must be %q or %q", accessLogSourceFile, accessLogSourceJournal)
	}

	switch c.Format {
	case accessLogFormatXray, accessLogFormatHysteria2JSON:
	default:
		return fmt.Errorf("access_logs.format must be %q or %q", accessLogFormatXray, accessLogFormatHysteria2JSON)
	}

	if c.Source == accessLogSourceFile && strings.TrimSpace(c.Path) == "" {
		return fmt.Errorf("access_logs.path is required for file source")
	}
	if c.Source == accessLogSourceJournal {
		seenUnits := make(map[string]struct{})
		seenTags := make(map[string]struct{})
		for _, source := range c.EffectiveJournalSources() {
			if !validSystemdUnitName(source.Unit) {
				return fmt.Errorf("access_logs journal source unit is invalid")
			}
			if source.Tag != "" && !journalSourceTagRE.MatchString(source.Tag) {
				return fmt.Errorf("access_logs journal source tag is invalid")
			}
			if _, exists := seenUnits[source.Unit]; exists {
				return fmt.Errorf("access_logs journal source unit is duplicated")
			}
			seenUnits[source.Unit] = struct{}{}
			if source.Tag != "" {
				if _, exists := seenTags[source.Tag]; exists {
					return fmt.Errorf("access_logs journal source tag is duplicated")
				}
				seenTags[source.Tag] = struct{}{}
			}
		}
		if len(c.JournalSources) > 1 {
			for _, source := range c.JournalSources {
				if source.Tag == "" {
					return fmt.Errorf("access_logs journal source tag is required for multiple sources")
				}
			}
		}
	}
	return nil
}

// EffectiveJournalSources returns the configured sources, falling back to the
// legacy singular journal_unit. Callers can use this without branching on the
// version of the panel that produced the config.
func (c AccessLogsConfig) EffectiveJournalSources() []JournalSource {
	if c.Source != accessLogSourceJournal {
		return nil
	}
	if len(c.JournalSources) == 0 {
		return []JournalSource{{Unit: c.JournalUnit}}
	}
	sources := make([]JournalSource, len(c.JournalSources))
	copy(sources, c.JournalSources)
	return sources
}

func validSystemdUnitName(unit string) bool {
	return systemdUnitNameRE.MatchString(unit) && !strings.Contains(unit, "..")
}

// IsHysteriaOnly identifies the cc-agent deployment used solely to collect
// Hysteria 2's structured journal. It intentionally does not depend on Enabled:
// disabling collection must not turn this process into an Xray manager on the
// next restart. The panel always writes source/format for both enabled and
// disabled Hysteria access-log configurations.
func (c *Config) IsHysteriaOnly() bool {
	return c != nil &&
		c.AccessLogs.Source == accessLogSourceJournal &&
		c.AccessLogs.Format == accessLogFormatHysteria2JSON
}

func (c *Config) RuntimeMode() string {
	if c.IsHysteriaOnly() {
		return "hysteria-only"
	}
	return "xray"
}

// InboundEntry describes a single Xray VLESS inbound the agent has to
// add/remove users to/from. Flow is the per-inbound XTLS flow (empty for
// transports that do not support flow, e.g. WebSocket/gRPC/XHTTP).
type InboundEntry struct {
	Tag  string `json:"tag"`
	Flow string `json:"flow"`
}

type Config struct {
	Listen  string    `json:"listen"`
	Token   string    `json:"token"`
	XrayAPI string    `json:"xray_api"`
	DataDir string    `json:"data_dir"`
	TLS     TLSConfig `json:"tls"`

	// InboundTag is the legacy single-inbound tag. It is kept for backward
	// compatibility with old panels that do not write the Inbounds array.
	InboundTag string `json:"inbound_tag"`

	// Inbounds is the new multi-inbound configuration. When set, AddUser /
	// RemoveUser iterate over every entry and apply the per-tag Flow.
	// When empty, the loader synthesizes a single entry from InboundTag and
	// flow is resolved from the running Xray config (best-effort).
	Inbounds []InboundEntry `json:"inbounds,omitempty"`

	// AccessLogs configures the opt-in access-log shipping module. Absent =
	// disabled; older panels never write it, so downgrade stays safe.
	AccessLogs AccessLogsConfig `json:"access_logs"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		Listen:     "0.0.0.0:62080",
		XrayAPI:    "127.0.0.1:61000",
		InboundTag: "vless-in",
		DataDir:    "/var/lib/cc-agent",
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	// Resolve mode before considering any Xray-specific compatibility probes.
	// This keeps Hysteria-only config loading from even reading an unrelated
	// co-located /usr/local/etc/xray/config.json.
	cfg.AccessLogs.applyDefaults()
	if err := cfg.AccessLogs.validate(); err != nil {
		return nil, err
	}

	// Backward compatibility: if the new Inbounds array is missing but the
	// legacy InboundTag is present, synthesize a single entry. Flow is
	// resolved from the running Xray config (best-effort) so XTLS-Vision
	// clients keep working when the panel only writes the legacy field.
	if !cfg.IsHysteriaOnly() && len(cfg.Inbounds) == 0 && cfg.InboundTag != "" {
		flow := ""
		if probed, ok := probeFlowFromXrayConfig(cfg.InboundTag); ok {
			flow = probed
		}
		cfg.Inbounds = []InboundEntry{{Tag: cfg.InboundTag, Flow: flow}}
	}

	return cfg, nil
}

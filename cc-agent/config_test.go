package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeConfigForTest(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfigHysteriaJournalAccessLogs(t *testing.T) {
	path := writeConfigForTest(t, `{
		"token":"agent-token",
		"data_dir":"/tmp/cc-agent-test",
		"access_logs":{
			"enabled":true,
			"source":"journal",
			"format":"hysteria2-json",
			"journal_unit":"hysteria-server",
			"ingest_url":"https://panel.example/api/access-logs/ingest",
			"ingest_token":"ingest-token"
		}
	}`)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg.AccessLogs.Source != accessLogSourceJournal || cfg.AccessLogs.Format != accessLogFormatHysteria2JSON {
		t.Fatalf("unexpected access log config: %+v", cfg.AccessLogs)
	}
	if cfg.AccessLogs.JournalUnit != "hysteria-server" {
		t.Fatalf("journal unit = %q", cfg.AccessLogs.JournalUnit)
	}
	if cfg.AccessLogs.BatchMaxEvents != 500 || cfg.AccessLogs.FlushIntervalSeconds != 5 {
		t.Fatalf("defaults not applied: %+v", cfg.AccessLogs)
	}
}

func TestLoadConfigRejectsUnsafeJournalUnit(t *testing.T) {
	path := writeConfigForTest(t, `{
		"access_logs":{
			"enabled":true,
			"source":"journal",
			"format":"hysteria2-json",
			"journal_unit":"hysteria-server --since yesterday"
		}
	}`)

	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected unsafe journal unit to be rejected")
	}
}

func TestLoadConfigKeepsLegacyXrayDefaults(t *testing.T) {
	path := writeConfigForTest(t, `{"access_logs":{"enabled":true}}`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg.AccessLogs.Source != accessLogSourceFile || cfg.AccessLogs.Format != accessLogFormatXray || cfg.AccessLogs.Path != "/var/log/xray/access.log" {
		t.Fatalf("legacy defaults changed: %+v", cfg.AccessLogs)
	}
	if cfg.IsHysteriaOnly() || cfg.RuntimeMode() != "xray" {
		t.Fatalf("legacy Xray config detected as mode %q", cfg.RuntimeMode())
	}
}

func TestLoadConfigSupportsXrayJournalSource(t *testing.T) {
	path := writeConfigForTest(t, `{
		"access_logs":{
			"enabled":true,
			"source":"journal",
			"format":"xray",
			"journal_unit":"xray",
			"path":""
		}
	}`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg.AccessLogs.Source != accessLogSourceJournal ||
		cfg.AccessLogs.Format != accessLogFormatXray ||
		cfg.AccessLogs.JournalUnit != "xray" {
		t.Fatalf("Xray journal config = %+v", cfg.AccessLogs)
	}
	if cfg.IsHysteriaOnly() || cfg.RuntimeMode() != "xray" {
		t.Fatalf("Xray journal config detected as mode %q", cfg.RuntimeMode())
	}
}

func TestDisabledHysteriaJournalConfigStaysHysteriaOnly(t *testing.T) {
	path := writeConfigForTest(t, `{
		"access_logs":{
			"enabled":false,
			"source":"journal",
			"format":"hysteria2-json",
			"journal_unit":"hysteria-server"
		}
	}`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if !cfg.IsHysteriaOnly() || cfg.RuntimeMode() != "hysteria-only" {
		t.Fatalf("disabled HY2 config detected as mode %q", cfg.RuntimeMode())
	}
}

func TestDisabledHysteriaJournalConfigStillValidatesUnit(t *testing.T) {
	path := writeConfigForTest(t, `{
		"access_logs":{
			"enabled":false,
			"source":"journal",
			"format":"hysteria2-json",
			"journal_unit":"hysteria-server --since yesterday"
		}
	}`)
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("expected disabled HY2 config with unsafe journal unit to be rejected")
	}
}

func TestHysteriaFormatOnFileDoesNotDisableXrayManagement(t *testing.T) {
	cfg := &Config{AccessLogs: AccessLogsConfig{
		Source: accessLogSourceFile,
		Format: accessLogFormatHysteria2JSON,
	}}
	if cfg.IsHysteriaOnly() {
		t.Fatal("only the explicit journal + hysteria2-json contract may select hysteria-only mode")
	}
}

func TestLoadConfigSupportsMultipleTaggedJournalSources(t *testing.T) {
	path := writeConfigForTest(t, `{
		"access_logs":{
			"enabled":true,
			"source":"journal",
			"format":"hysteria2-json",
			"journal_sources":[
				{"unit":"hysteria-server","tag":"main"},
				{"unit":"hysteria-server@mobile","tag":"mobile"},
				{"unit":"hysteria-dev","tag":"dev"}
			]
		}
	}`)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg.AccessLogs.JournalUnit != "hysteria-server" {
		t.Fatalf("legacy journal unit = %q", cfg.AccessLogs.JournalUnit)
	}
	want := []JournalSource{
		{Unit: "hysteria-server", Tag: "main"},
		{Unit: "hysteria-server@mobile", Tag: "mobile"},
		{Unit: "hysteria-dev", Tag: "dev"},
	}
	if got := cfg.AccessLogs.EffectiveJournalSources(); !reflect.DeepEqual(got, want) {
		t.Fatalf("journal sources = %#v, want %#v", got, want)
	}
}

func TestLoadConfigRejectsUnsafeOrAmbiguousJournalSources(t *testing.T) {
	for _, config := range []string{
		`{"access_logs":{"source":"journal","format":"hysteria2-json","journal_sources":[{"unit":"hysteria-server; reboot","tag":"main"}]}}`,
		`{"access_logs":{"source":"journal","format":"hysteria2-json","journal_sources":[{"unit":"hysteria-server","tag":""},{"unit":"hysteria-dev","tag":"dev"}]}}`,
		`{"access_logs":{"source":"journal","format":"hysteria2-json","journal_sources":[{"unit":"hysteria-server","tag":"main"},{"unit":"hysteria-server","tag":"other"}]}}`,
		`{"access_logs":{"source":"journal","format":"hysteria2-json","journal_sources":[{"unit":"hysteria-server","tag":"not valid"}]}}`,
	} {
		if _, err := LoadConfig(writeConfigForTest(t, config)); err == nil {
			t.Fatalf("expected invalid journal sources to fail: %s", config)
		}
	}
}

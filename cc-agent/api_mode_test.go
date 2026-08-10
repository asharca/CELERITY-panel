package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newHysteriaOnlyTestAPI() (*API, *http.ServeMux) {
	cfg := &Config{
		Token: "test-token",
		AccessLogs: AccessLogsConfig{
			Source: accessLogSourceJournal,
			Format: accessLogFormatHysteria2JSON,
		},
	}
	// Xray dependencies intentionally stay nil. Any accidental execution of an
	// Xray handler will panic, making these tests a strong side-effect boundary.
	api := &API{cfg: cfg}
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	return api, mux
}

func authenticatedRequest(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-token")
	return req
}

func TestHysteriaOnlyReadOnlyEndpointsRemainAvailable(t *testing.T) {
	_, mux := newHysteriaOnlyTestAPI()

	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/health"},
		{http.MethodGet, "/info"},
		{http.MethodPost, "/connect"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, authenticatedRequest(tc.method, tc.path, ""))
			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
			}
			var body map[string]any
			if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if body["mode"] != "hysteria-only" {
				t.Fatalf("mode = %#v", body["mode"])
			}
			if tc.path != "/health" && body["xray_version"] != "not-applicable" {
				t.Fatalf("xray_version = %#v", body["xray_version"])
			}
		})
	}
}

func TestInfoExposesAccessLogSourceReady(t *testing.T) {
	api, mux := newHysteriaOnlyTestAPI()
	source := NewJournalTailer("hysteria-server", "", nil, nil)
	source.setSourceState(true, "")
	api.shipper = &Shipper{
		cfg:      &api.cfg.AccessLogs,
		spoolDir: t.TempDir(),
		source:   source,
	}

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, authenticatedRequest(http.MethodGet, "/info", ""))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	accessLogs, ok := body["access_logs"].(map[string]any)
	if !ok {
		t.Fatalf("access_logs = %#v", body["access_logs"])
	}
	if accessLogs["source_ready"] != true {
		t.Fatalf("source_ready = %#v", accessLogs["source_ready"])
	}
}

func TestHysteriaOnlyRejectsEveryXrayOperationBeforeHandler(t *testing.T) {
	_, mux := newHysteriaOnlyTestAPI()

	tests := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPost, "/sync", `{"users":[]}`},
		{http.MethodPost, "/users", `{"id":"id","email":"user"}`},
		{http.MethodDelete, "/users/user", ""},
		{http.MethodGet, "/stats", ""},
		{http.MethodPost, "/restart", ""},
	}

	for _, tc := range tests {
		t.Run(tc.method+"_"+tc.path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, authenticatedRequest(tc.method, tc.path, tc.body))
			if recorder.Code != http.StatusNotImplemented {
				t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
			}
			if !strings.Contains(recorder.Body.String(), "not applicable") {
				t.Fatalf("unexpected body: %s", recorder.Body.String())
			}
		})
	}
}

func TestHysteriaOnlyXrayGateStillRequiresAuthentication(t *testing.T) {
	_, mux := newHysteriaOnlyTestAPI()
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/restart", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d", recorder.Code)
	}
}

func TestLegacyXrayModeStillPassesXrayGate(t *testing.T) {
	api := &API{cfg: &Config{AccessLogs: AccessLogsConfig{
		Source: accessLogSourceFile,
		Format: accessLogFormatXray,
	}}}
	called := false
	handler := api.xrayOnly(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	recorder := httptest.NewRecorder()
	handler(recorder, httptest.NewRequest(http.MethodPost, "/sync", nil))
	if !called || recorder.Code != http.StatusNoContent {
		t.Fatalf("legacy Xray handler called=%v status=%d", called, recorder.Code)
	}
}

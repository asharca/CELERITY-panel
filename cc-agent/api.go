package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// API holds dependencies for the HTTP handler layer
type API struct {
	cfg        *Config
	userStore  *UserStore
	xrayClient *XrayClient
	persister  *ConfigPersister
	// shipper is nil when the access-log module is disabled.
	shipper *Shipper
}

func (a *API) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", a.auth(a.handleHealth))
	mux.HandleFunc("GET /info", a.auth(a.handleInfo))
	mux.HandleFunc("POST /connect", a.auth(a.handleConnect))
	// Keep the Xray routes registered for API compatibility, but put a hard
	// mode gate in front of every one. Hysteria-only agents must never reach a
	// handler that can touch gRPC, users.json, Xray config, stats, or systemd.
	mux.HandleFunc("POST /sync", a.auth(a.xrayOnly(a.handleSync)))
	mux.HandleFunc("POST /users", a.auth(a.xrayOnly(a.handleAddUser)))
	mux.HandleFunc("DELETE /users/{email}", a.auth(a.xrayOnly(a.handleRemoveUser)))
	mux.HandleFunc("GET /stats", a.auth(a.xrayOnly(a.handleStats)))
	mux.HandleFunc("POST /restart", a.auth(a.xrayOnly(a.handleRestart)))
}

// auth middleware validates the Bearer token
func (a *API) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		token := strings.TrimPrefix(auth, "Bearer ")
		if token == "" || token == auth || token != a.cfg.Token {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func (a *API) xrayOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.cfg.IsHysteriaOnly() {
			jsonErr(w, http.StatusNotImplemented, "xray operation is not applicable in hysteria-only mode")
			return
		}
		next(w, r)
	}
}

func jsonOK(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// GET /health — simple liveness probe
func (a *API) handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]string{"status": "ok", "mode": a.cfg.RuntimeMode()})
}

// GET /info — version, uptime, user count, and access-log module status.
func (a *API) handleInfo(w http.ResponseWriter, r *http.Request) {
	xrayVersion := "not-applicable"
	usersCount := 0
	var lastSync any
	if !a.cfg.IsHysteriaOnly() {
		xrayVersion = getXrayVersion()
		if a.userStore != nil {
			usersCount = a.userStore.Count()
			lastSync = a.userStore.GetLastSync()
		}
	}
	info := map[string]any{
		"agent_version":  Version,
		"mode":           a.cfg.RuntimeMode(),
		"xray_version":   xrayVersion,
		"uptime_seconds": int(time.Since(startTime).Seconds()),
		"users_count":    usersCount,
		"last_sync":      lastSync,
	}
	if a.shipper != nil {
		info["access_logs"] = a.shipper.Status()
	} else {
		info["access_logs"] = ShipperStatus{Enabled: false}
	}
	jsonOK(w, info)
}

// POST /connect — handshake; panel calls this to verify connectivity
func (a *API) handleConnect(w http.ResponseWriter, r *http.Request) {
	xrayVersion := "not-applicable"
	if !a.cfg.IsHysteriaOnly() {
		xrayVersion = getXrayVersion()
	}
	jsonOK(w, map[string]any{
		"status":        "connected",
		"agent_version": Version,
		"mode":          a.cfg.RuntimeMode(),
		"xray_version":  xrayVersion,
	})
}

// POST /sync — full user sync (replace all users)
func (a *API) handleSync(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Users []*User `json:"users"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "Bad request: "+err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	current := a.userStore.List()
	currentMap := make(map[string]*User, len(current))
	for _, u := range current {
		currentMap[u.Email] = u
	}

	newMap := make(map[string]*User, len(req.Users))
	for _, u := range req.Users {
		newMap[u.Email] = u
	}

	added, removed, errors := 0, 0, 0

	for email := range currentMap {
		if _, exists := newMap[email]; !exists {
			if err := a.xrayClient.RemoveUser(ctx, email); err != nil {
				log.Printf("[sync] Remove %s: %v", email, err)
				errors++
			} else {
				removed++
			}
		}
	}

	for email, u := range newMap {
		if _, exists := currentMap[email]; !exists {
			if err := a.xrayClient.AddUser(ctx, u); err != nil {
				log.Printf("[sync] Add %s: %v", email, err)
				errors++
			} else {
				added++
			}
		}
	}

	a.userStore.Sync(req.Users)
	a.persister.MarkDirty()
	go func() {
		if err := a.userStore.Save(); err != nil {
			log.Printf("[store] Save: %v", err)
		}
	}()

	log.Printf("[sync] Done: +%d -%d errors=%d total=%d", added, removed, errors, len(req.Users))
	jsonOK(w, map[string]any{
		"added":   added,
		"removed": removed,
		"errors":  errors,
		"total":   len(req.Users),
	})
}

// POST /users — add a single user
func (a *API) handleAddUser(w http.ResponseWriter, r *http.Request) {
	var u User
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		jsonErr(w, http.StatusBadRequest, "Bad request: "+err.Error())
		return
	}
	if u.ID == "" || u.Email == "" {
		jsonErr(w, http.StatusBadRequest, "id and email are required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := a.xrayClient.AddUser(ctx, &u); err != nil {
		log.Printf("[api] AddUser %s: %v", u.Email, err)
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	a.userStore.Add(&u)
	a.persister.MarkDirty()
	go func() { _ = a.userStore.Save() }()

	jsonOK(w, map[string]string{"status": "ok"})
}

// DELETE /users/{email} — remove a single user
func (a *API) handleRemoveUser(w http.ResponseWriter, r *http.Request) {
	email := r.PathValue("email")
	if email == "" {
		jsonErr(w, http.StatusBadRequest, "email is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := a.xrayClient.RemoveUser(ctx, email); err != nil {
		// Log but don't fail — user may not exist in Xray (e.g. after restart)
		log.Printf("[api] RemoveUser %s: %v", email, err)
	}

	a.userStore.Remove(email)
	a.persister.MarkDirty()
	go func() { _ = a.userStore.Save() }()

	jsonOK(w, map[string]string{"status": "ok"})
}

// GET /stats — take one atomic snapshot from Xray (reset=true) and return
// { users: { <userId>: {tx, rx} }, node: {tx, rx} }.
// Users carry per-user uplink/downlink; node is the sum of outbound uplink/downlink
// across all non-API outbounds (i.e. real traffic that traversed Xray).
func (a *API) handleStats(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	rawStats, err := a.xrayClient.QueryStats(ctx, "", true)
	if err != nil {
		log.Printf("[stats] QueryStats: %v", err)
		jsonOK(w, map[string]any{
			"users": map[string]any{},
			"node":  map[string]int64{"tx": 0, "rx": 0},
		})
		return
	}

	snap := ParseSnapshot(rawStats)

	users := make(map[string]map[string]int64, len(snap.Users))
	for email, t := range snap.Users {
		if t.Tx == 0 && t.Rx == 0 {
			continue
		}
		users[email] = map[string]int64{"tx": t.Tx, "rx": t.Rx}
	}

	jsonOK(w, map[string]any{
		"users": users,
		"node":  map[string]int64{"tx": snap.Node.Tx, "rx": snap.Node.Rx},
	})
}

// POST /restart — restart Xray service. The on-disk config.json already carries
// the current user list (kept in sync by ConfigPersister), so Xray comes back up
// with the correct users on its own — no gRPC replay needed.
func (a *API) handleRestart(w http.ResponseWriter, r *http.Request) {
	// Make sure the latest user set is persisted before the restart so the
	// reloaded Xray cannot pick up a stale snapshot.
	if _, err := a.persister.Flush(); err != nil {
		log.Printf("[api] Restart: config flush failed: %v", err)
	}

	out, err := exec.Command("systemctl", "restart", "xray").CombinedOutput()
	if err != nil {
		log.Printf("[api] Restart xray error: %v, output: %s", err, out)
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Give Xray a moment to come up before returning, so a follow-up /sync from
	// the panel hits a live gRPC API.
	time.Sleep(2 * time.Second)

	log.Printf("[api] Xray restarted (%d users in config)", a.userStore.Count())
	jsonOK(w, map[string]string{"status": "ok", "users": fmt.Sprintf("%d", a.userStore.Count())})
}

// getXrayVersion reads the installed Xray version by running `xray version`
func getXrayVersion() string {
	out, err := exec.Command("xray", "version").Output()
	if err != nil {
		return "unknown"
	}
	lines := strings.SplitN(string(out), "\n", 2)
	if len(lines) == 0 {
		return "unknown"
	}
	// "Xray 1.8.24 (Xray, Penetrates Everything.) ..."
	parts := strings.Fields(lines[0])
	if len(parts) >= 2 {
		return parts[1]
	}
	return strings.TrimSpace(lines[0])
}

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"
)

const Version = "1.5.2"

var startTime = time.Now()

func main() {
	configPath := flag.String("config", "/etc/cc-agent/config.json", "Path to config file")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		log.Printf("cc-agent %s", Version)
		os.Exit(0)
	}

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("[main] Failed to load config: %v", err)
	}

	// A Hysteria journal collector is deliberately not an Xray manager. This
	// guard protects co-located hosts too: even if an Xray config/binary happens
	// to exist, Hysteria-only mode never reads or rewrites it, opens gRPC, resets
	// stats, persists users, or restarts the Xray service.
	hysteriaOnly := cfg.IsHysteriaOnly()
	var userStore *UserStore
	var xrayClient *XrayClient
	var persister *ConfigPersister
	if hysteriaOnly {
		log.Printf("[main] Hysteria-only mode: Xray management is disabled")
	} else {
		userStore = NewUserStore(cfg)
		if err := userStore.Load(); err != nil {
			log.Printf("[main] Warning: could not load users from disk: %v", err)
		}

		xrayClient, err = NewXrayClient(cfg)
		if err != nil {
			log.Printf("[main] Warning: could not connect to Xray gRPC: %v (will retry on use)", err)
		}

		// ConfigPersister keeps /usr/local/etc/xray/config.json in sync with the
		// authoritative user list so any Xray restart reloads the correct users.
		persister = NewConfigPersister(xrayConfigPath, cfg.Inbounds, userStore)
		go persister.run()

		// Startup reconciliation. Make the on-disk config reflect the current users
		// (durability), then heal the running Xray only if the disk was actually
		// stale and no panel /sync arrived to fix the runtime during the grace window.
		// A panel full-push restarts cc-agent (reloadCcAgent) BEFORE it calls /sync,
		// so the grace window avoids a redundant heal restart in that race.
		go func() {
			time.Sleep(3 * time.Second)

			// diskWasStale captures whether the on-disk config differed from the
			// authoritative user list at boot. This (not the post-grace reflush) is
			// what tells us the live Xray runtime is likely stale too: the first
			// Flush already rewrote the file, so a second Flush would report no
			// change even though the running Xray still holds the old user set.
			diskWasStale, err := persister.Flush()
			if err != nil {
				log.Printf("[main] Startup config flush: %v", err)
			}

			syncBefore := userStore.GetLastSync()
			time.Sleep(15 * time.Second)
			syncedDuringGrace := !userStore.GetLastSync().Equal(syncBefore)

			// Re-flush to capture any user changes that landed during the grace
			// window (durability only; not used for the heal decision).
			if _, err := persister.Flush(); err != nil {
				log.Printf("[main] Startup config reflush: %v", err)
			}

			if diskWasStale && !syncedDuringGrace {
				// On-disk config was stale and nothing healed the runtime — the live
				// Xray still has the old user set. One restart reloads the corrected
				// config from disk (no gRPC AddUser storm).
				log.Printf("[main] Stale Xray config on startup, restarting xray once to heal runtime")
				if out, rerr := exec.Command("systemctl", "restart", "xray").CombinedOutput(); rerr != nil {
					log.Printf("[main] Xray heal restart failed: %v, output: %s", rerr, out)
				} else {
					time.Sleep(2 * time.Second)
				}
			}

			// Discard the first Xray stats snapshot. Xray accumulates counters from
			// boot, and without this discard the panel's first /stats poll would
			// attribute all of that since-boot traffic to the current interval.
			if xrayClient != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				defer cancel()
				if _, err := xrayClient.QueryStats(ctx, "", true); err != nil {
					log.Printf("[main] Startup stats discard failed: %v", err)
				} else {
					log.Printf("[main] Startup stats discarded (cold-start reset)")
				}
			}
		}()

		// Periodic user store flush to disk every 5 minutes.
		go func() {
			for {
				time.Sleep(5 * time.Minute)
				if err := userStore.Save(); err != nil {
					log.Printf("[store] Save error: %v", err)
				}
			}
		}()
	}

	// Optional access-log shipping module. Stays inert unless explicitly
	// enabled by the panel via config.access_logs.enabled.
	var shipper *Shipper
	if cfg.AccessLogs.Enabled && cfg.AccessLogs.IngestURL != "" && cfg.AccessLogs.IngestToken != "" {
		shipper = NewShipper(cfg)
		shipper.Start()
	}

	api := &API{
		cfg:        cfg,
		userStore:  userStore,
		xrayClient: xrayClient,
		persister:  persister,
		shipper:    shipper,
	}

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	server := &http.Server{
		Addr:         cfg.Listen,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if cfg.TLS.Enabled {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.Cert, cfg.TLS.Key)
		if err != nil {
			log.Fatalf("[main] TLS cert load error: %v", err)
		}
		server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		log.Printf("[main] CC Agent %s starting on %s (mode=%s TLS=%v)", Version, cfg.Listen, cfg.RuntimeMode(), cfg.TLS.Enabled)
		var srvErr error
		if cfg.TLS.Enabled {
			srvErr = server.ListenAndServeTLS("", "")
		} else {
			srvErr = server.ListenAndServe()
		}
		if srvErr != nil && srvErr != http.ErrServerClosed {
			log.Fatalf("[main] Server error: %v", srvErr)
		}
	}()

	<-sigCh
	log.Printf("[main] Shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)

	// Stop the access-log shipper first so it drains the tailer and flushes any
	// pending batches before the process exits.
	if shipper != nil {
		shipper.Stop()
	}

	// Hysteria-only mode leaves these nil by construction; therefore shutdown
	// cannot accidentally create users.json or touch an Xray config either.
	if persister != nil {
		persister.Stop()
		if _, err := persister.Flush(); err != nil {
			log.Printf("[config] Final flush: %v", err)
		}
	}
	if userStore != nil {
		_ = userStore.Save()
	}
	if xrayClient != nil {
		xrayClient.Close()
	}
	log.Printf("[main] Shutdown complete")
}

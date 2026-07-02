// main.go — starts the server and registers routes.
package main

import (
	"log"
	"net/http"
)

type config struct {
	ListenAddr      string
	BaseURL         string
	MongoURI        string // e.g. mongodb://localhost:27017
	MongoDB         string // database name
	InternalAPIKey  string
	TokenTTLHours   int // total approval window (e.g. 48h)
	RefTTLHours     int // email link lifetime (e.g. 4h) — shorter than approval window

	SSOAuthURL      string
	SSOTokenURL     string
	SSOUserInfoURL  string
	SSOClientID     string
	SSOClientSecret string
}

func configFromEnv() config {
	return config{
		ListenAddr:      envOr("LISTEN_ADDR", ":8000"),
		BaseURL:         envOr("BASE_URL", "http://localhost:8000"),
		MongoURI:        envOr("MONGODB_URI", "mongodb://localhost:27017"),
		MongoDB:         envOr("MONGODB_DB", "approval_service"),
		InternalAPIKey:  envOr("INTERNAL_API_KEY", ""),
		TokenTTLHours:   envInt("TOKEN_TTL_HOURS", 48),
		RefTTLHours:     envInt("REF_TTL_HOURS", 4),
		SSOAuthURL:      envOr("SSO_AUTH_URL", ""),
		SSOTokenURL:     envOr("SSO_TOKEN_URL", ""),
		SSOUserInfoURL:  envOr("SSO_USERINFO_URL", ""),
		SSOClientID:     envOr("SSO_CLIENT_ID", ""),
		SSOClientSecret: envOr("SSO_CLIENT_SECRET", ""),
	}
}

func main() {
	cfg := configFromEnv()

	if cfg.InternalAPIKey == "" {
		log.Println("WARN: INTERNAL_API_KEY not set — internal endpoints are unauthenticated")
	}
	if cfg.SSOAuthURL == "" {
		log.Println("WARN: SSO not configured — running in dev mode, no identity verification")
	}

	store, err := newStore(cfg.MongoURI, cfg.MongoDB)
	if err != nil {
		log.Fatalf("cannot connect to MongoDB: %v", err)
	}
	defer store.close()

	h := &handlers{store: store, cfg: cfg}

	mux := http.NewServeMux()

	// Internal — Harness pipeline only (X-Internal-Key required)
	mux.HandleFunc("POST /approval/create", h.create)
	mux.HandleFunc("GET /approval/status/{token}", h.status)
	mux.HandleFunc("GET /approval/audit/verify", h.auditVerify)

	// Manager-facing — email link lands here, SSO redirect, no state change on GET
	mux.HandleFunc("GET /approval/review/{reference}", h.review)

	// SSO provider sends manager here after login
	mux.HandleFunc("GET /approval/callback", h.ssoCallback)

	// Manager submits the review form here — only place status changes
	mux.HandleFunc("POST /approval/decide", h.decide)

	mux.HandleFunc("GET /health", h.health)

	log.Printf("approval service listening on %s", cfg.ListenAddr)
	log.Fatal(http.ListenAndServe(cfg.ListenAddr, mux))
}

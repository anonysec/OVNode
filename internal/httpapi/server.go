// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

// Package httpapi serves the node side of the OVManager ⇄ OVNode contract.
//
// Every route sits under /sync and answers the {success,msg,data} envelope.
// The panel accepts a call only when the HTTP status is 200 and success is
// true, so a business failure is reported inside the envelope and never as
// a 500: a traceback must never leak to the panel.
//
// The routes are method-scoped (Go 1.22 ServeMux patterns). One path
// serving three methods is how a PUT /sync/user/limit ended up deleting a
// user named "limit".
package httpapi

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"time"

	"ovnode/internal/logging"
	"ovnode/internal/pki"
	"ovnode/internal/ratelimit"
	"ovnode/internal/version"
)

// Server is the node's HTTP agent.
type Server struct {
	Addr     string
	APIKey   string
	CertFile string
	KeyFile  string

	limiter *ratelimit.Limiter
	started time.Time
}

func envOr(name, fb string) string {
	if v, ok := os.LookupEnv(name); ok && v != "" {
		return v
	}
	return fb
}

// NewServer builds the server from the environment.
func NewServer() *Server {
	s := &Server{limiter: ratelimit.New(), started: time.Now()}
	port := envOr("SERVICE_PORT", "")
	if port == "" {
		port = "2083"
	}
	s.Addr = ":" + port
	s.APIKey = envOr("API_KEY", "")
	cf := envOr("SSL_CERTFILE", "")
	kf := envOr("SSL_KEYFILE", "")
	if cf == "" {
		cf = pki.ServerCert()
	}
	if kf == "" {
		kf = pki.ServerKey()
	}
	s.CertFile = cf
	s.KeyFile = kf
	return s
}

// routes returns the node's route table.
//
// The patterns are method-scoped on purpose: the panel calls /sync/user with
// POST, PUT and /sync/user/{uid} with DELETE, and a method-blind table
// served all of them with one handler.
func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /sync/health", s.handleHealth)
	mux.HandleFunc("GET /sync/status", s.handleStatus)
	mux.HandleFunc("GET /sync/usage", s.handleUsage)
	mux.HandleFunc("GET /sync/sessions", s.handleSessions)
	mux.HandleFunc("GET /sync/logs", s.handleLogs)
	mux.HandleFunc("GET /sync/config", s.handleConfigGet)
	mux.HandleFunc("POST /sync/config", s.handleConfigPost)
	mux.HandleFunc("POST /sync/restart", s.handleRestart)
	mux.HandleFunc("POST /sync/renew-cert", s.handleRenewCert)
	mux.HandleFunc("POST /sync/update", s.handleUpdate)
	mux.HandleFunc("POST /sync/user", s.handleUserCreate)
	mux.HandleFunc("PUT /sync/user", s.handleUserStatus)
	mux.HandleFunc("PUT /sync/user/limit", s.handleUserLimit)
	mux.HandleFunc("DELETE /sync/user/{uid}", s.handleUserDelete)
	mux.HandleFunc("POST /sync/user/{uid}/disconnect", s.handleUserDisconnect)
	mux.HandleFunc("POST /sync/user/{uid}/reset-usage", s.handleResetUsage)
	mux.HandleFunc("GET /sync/download/ovpn/{uid}", s.handleDownloadOVPN)
	mux.HandleFunc("POST /sync/users", s.handleBulkLimits)
	mux.HandleFunc("PUT /sync/users/{cn}", s.handlePushCreds)
	mux.HandleFunc("PUT /sync/pki", s.handlePushPKI)
	return mux
}

func (s *Server) recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				logging.Error("http handler panic: %v", rec)
				writeFail(w, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// ListenAndServe serves the /sync API over TLS.
//
// TLS is not optional: the panel pins the node CA, so a missing or
// unreadable certificate or key kills the agent instead of falling back to
// plaintext.
func (s *Server) ListenAndServe() error {
	cert, err := tls.LoadX509KeyPair(s.CertFile, s.KeyFile)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              s.Addr,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
		Handler: s.recoveryMiddleware(s.routes()),
	}
	return srv.ListenAndServeTLS("", "")
}

// TLSMaterial resolves cert+key like Python _tls_material: operator override
// (SSL_CERTFILE/SSL_KEYFILE) wins, then the PKI server pair. Missing or
// unreadable file is fatal — no plaintext fallback.
func TLSMaterial() (string, string, error) {
	cert := envOr("SSL_CERTFILE", "")
	key := envOr("SSL_KEYFILE", "")
	if cert == "" {
		cert = pki.ServerCert()
	}
	if key == "" {
		key = pki.ServerKey()
	}
	for _, item := range []struct {
		l, p string
	}{{"cert", cert}, {"key", key}} {
		label, path := item.l, item.p
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			return "", "", fmt.Errorf("TLS %s missing or unreadable: %s — refusing to start without TLS", label, path)
		}
		f, err := os.Open(path)
		if err != nil {
			return "", "", fmt.Errorf("TLS %s missing or unreadable: %s — refusing to start without TLS", label, path)
		}
		f.Close()
	}
	return cert, key, nil
}

// Run starts the agent.
func Run() error {
	cert, key, err := TLSMaterial()
	if err != nil {
		return err
	}
	s := NewServer()
	s.CertFile = cert
	s.KeyFile = key
	logging.Info("ovnode agent %s starting (addr=%s, openvpn_root=%s)",
		version.Version, s.Addr, pki.OpenVPNRoot())
	fmt.Println("ovnode serve listening on", s.Addr)
	return s.ListenAndServe()
}

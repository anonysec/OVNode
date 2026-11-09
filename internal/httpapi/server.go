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
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"ovnode/internal/fsx"
	"ovnode/internal/logging"
	"ovnode/internal/ovpn"
	"ovnode/internal/pki"
	"ovnode/internal/ratelimit"
	"ovnode/internal/store"
	"ovnode/internal/version"
)

const (
	writeTimeout     = 30 * time.Second
	longWriteTimeout = 150 * time.Second
)

// Server is the node's HTTP agent.
type Server struct {
	Addr     string
	APIKey   string
	CertFile string
	KeyFile  string

	limiter    *ratelimit.Limiter
	started    time.Time
	panelAllow []netip.Prefix
	allowEmpty bool
	appDirPath string
}

// NewServer builds the server from the environment.
func NewServer() *Server {
	s := &Server{limiter: ratelimit.New(), started: time.Now()}
	port := fsx.EnvOr("SERVICE_PORT", "")
	if port == "" {
		port = "2083"
	}
	s.Addr = ":" + port
	s.APIKey = fsx.EnvOr("API_KEY", "")
	cf := fsx.EnvOr("SSL_CERTFILE", "")
	kf := fsx.EnvOr("SSL_KEYFILE", "")
	if cf == "" {
		cf = pki.ServerCert()
	}
	if kf == "" {
		kf = pki.ServerKey()
	}
	s.CertFile = cf
	s.KeyFile = kf
	s.panelAllow, s.allowEmpty = parsePanelAllow(os.Getenv("OVNODE_PANEL_ALLOW"))
	s.appDirPath = fsx.EnvOr("APP_DIR", "")
	if s.appDirPath == "" {
		for _, c := range []string{"/opt/ovnode", "/usr/local/ovnode"} {
			if _, err := os.Stat(c + "/install.sh"); err == nil {
				s.appDirPath = c
				break
			}
		}
	}
	if s.appDirPath == "" {
		s.appDirPath = "/opt/ovnode"
	}
	return s
}

// parsePanelAllow parses the comma-separated allowlist once. An empty list
// means allow any IP that presents a valid API key.
func parsePanelAllow(spec string) ([]netip.Prefix, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, true
	}
	var out []netip.Prefix
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			if p, err := netip.ParsePrefix(part); err == nil {
				out = append(out, p.Masked())
			}
		} else if a, err := netip.ParseAddr(part); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out, len(out) == 0
}

// routes returns the node's route table.
//
// The patterns are method-scoped on purpose: the panel calls /sync/user with
// POST, PUT and /sync/user/{uid} with DELETE, and a method-blind table
// served all of them with one handler.
// guard runs authorize and then h. Health is the only route without it.
func (s *Server) guard(h http.HandlerFunc, heavy bool) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authorize(w, r, heavy) {
			return
		}
		h(w, r)
	})
}

// longWrite sets a 150s write deadline for slow heavy routes.
func longWrite(h http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(longWriteTimeout)); err != nil {
			logging.Warn("set write deadline failed for %s %s: %v", r.Method, r.URL.Path, err)
		}
		h(w, r)
	})
}

func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /sync/health", s.handleHealth)
	mux.HandleFunc("GET /sync/status", s.guard(s.handleStatus, false))
	mux.HandleFunc("GET /sync/usage", s.guard(s.handleUsage, false))
	mux.HandleFunc("GET /sync/sessions", s.guard(s.handleSessions, false))
	mux.HandleFunc("GET /sync/logs", s.guard(s.handleLogs, false))
	mux.HandleFunc("GET /sync/config", s.guard(s.handleConfigGet, false))
	mux.HandleFunc("POST /sync/config", longWrite(s.guard(s.handleConfigPost, false)))
	mux.HandleFunc("POST /sync/restart", longWrite(s.guard(s.handleRestart, true)))
	mux.HandleFunc("POST /sync/renew-cert", longWrite(s.guard(s.handleRenewCert, true)))
	mux.HandleFunc("POST /sync/update", s.guard(s.handleUpdate, true))
	mux.HandleFunc("POST /sync/user", s.guard(s.handleUserCreate, true))
	mux.HandleFunc("PUT /sync/user", s.guard(s.handleUserStatus, false))
	mux.HandleFunc("PUT /sync/user/limit", s.guard(s.handleUserLimit, false))
	mux.HandleFunc("DELETE /sync/user/{uid}", s.guard(s.handleUserDelete, true))
	mux.HandleFunc("POST /sync/user/{uid}/disconnect", s.guard(s.handleUserDisconnect, false))
	mux.HandleFunc("POST /sync/user/{uid}/reset-usage", s.guard(s.handleResetUsage, false))
	mux.HandleFunc("GET /sync/download/ovpn/{uid}", s.gzipSkip(s.guard(s.handleDownloadOVPN, true)))
	mux.HandleFunc("POST /sync/users", s.guard(s.handleBulkLimits, false))
	mux.HandleFunc("PUT /sync/users/{cn}", s.guard(s.handlePushCreds, false))
	mux.HandleFunc("PUT /sync/pki", s.guard(s.handlePushPKI, true))
	return mux
}

var panelAllowWarned sync.Once

func (s *Server) panelAllowMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.allowEmpty {
			panelAllowWarned.Do(func() {
				logging.Warn("OVNODE_PANEL_ALLOW is empty — panel allowlist disabled (any IP with valid API key accepted)")
			})
			next.ServeHTTP(w, r)
			return
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip, err := netip.ParseAddr(strings.TrimSpace(host))
		if err != nil {
			writeFail(w, "forbidden")
			return
		}
		for _, p := range s.panelAllow {
			if p.Contains(ip) {
				next.ServeHTTP(w, r)
				return
			}
		}
		writeFail(w, "forbidden")
	})
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

// gzipSkip marks a route as raw (the .ovpn download), independent of
// the URL path. Registered through routes() so a new raw route only has
// to set the flag once.
func (s *Server) gzipSkip(h http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), gzipSkipCtx{}, true))
		h(w, r)
	})
}

type gzipSkipCtx struct{}

// gzipMiddleware compresses JSON responses when the client accepts gzip, which
// keeps high-traffic usage reports small on the wire.
func gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v, ok := r.Context().Value(gzipSkipCtx{}).(bool); ok && v {
			next.ServeHTTP(w, r)
			return
		}
		if r.Pattern == "GET /sync/download/ovpn/{uid}" {
			next.ServeHTTP(w, r)
			return
		}
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Vary", "Accept-Encoding")
		gz := gzip.NewWriter(w)
		defer gz.Close()
		next.ServeHTTP(&gzipWriter{ResponseWriter: w, gz: gz}, r)
	})
}

type gzipWriter struct {
	http.ResponseWriter
	gz *gzip.Writer
}

func (g *gzipWriter) Write(b []byte) (int, error) {
	return g.gz.Write(b)
}

func (g *gzipWriter) Flush() {
	_ = g.gz.Flush()
	if f, ok := g.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (g *gzipWriter) Unwrap() http.ResponseWriter { return g.ResponseWriter }

// ListenAndServe serves the /sync API over TLS.
//
// TLS is not optional: the panel pins the node CA, so a missing or
// unreadable certificate or key kills the agent instead of falling back to
// plaintext.
func (s *Server) ListenAndServe(ctx context.Context) error {
	cert, err := tls.LoadX509KeyPair(s.CertFile, s.KeyFile)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              s.Addr,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
		Handler: gzipMiddleware(s.panelAllowMiddleware(s.recoveryMiddleware(s.routes()))),
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServeTLS("", "") }()
	select {
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	return nil
}

// TLSMaterial resolves cert+key like Python _tls_material: operator override
// (SSL_CERTFILE/SSL_KEYFILE) wins, then the PKI server pair. Missing or
// unreadable file is fatal — no plaintext fallback.
func TLSMaterial() (string, string, error) {
	cert := fsx.EnvOr("SSL_CERTFILE", "")
	key := fsx.EnvOr("SSL_KEYFILE", "")
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

// setupPrintedPath is the marker that makes the first-boot print happen once.
func setupPrintedPath() string {
	dir := fsx.EnvOr("DATA_DIR", "/var/lib/ovnode")
	return filepath.Join(dir, ".setup-printed")
}

// isTTY reports whether f is a terminal.
func isTTY(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

// keyFingerprint returns a non-secret hint for the API key.
func keyFingerprint(key string) string {
	if len(key) < 8 {
		return "****"
	}
	return key[:4] + "..." + key[len(key)-4:]
}

// printSetupIfFirstBoot writes the connection details to stdout the first time
// the agent successfully serves. It returns true when it printed.
func printSetupIfFirstBoot() bool {
	marker := setupPrintedPath()
	if _, err := os.Stat(marker); err == nil {
		return false
	}
	port := fsx.EnvOr("SERVICE_PORT", "2083")
	key := fsx.EnvOr("API_KEY", "")
	certFile := fsx.EnvOr("SSL_CERTFILE", "")
	if certFile == "" {
		certFile = pki.ServerCert()
	}
	proto := "https"
	fmt.Println("# OVNode connection details")
	fmt.Println("Address:", pki.PrimaryIP())
	fmt.Println("Port:", port)
	fmt.Println("Protocol:", proto)
	if isTTY(os.Stdout) {
		fmt.Println("API Key:", key)
	} else {
		fmt.Println("API Key fingerprint:", keyFingerprint(key))
	}
	fmt.Println("Certificate:")
	if data, err := os.ReadFile(certFile); err == nil {
		fmt.Print(string(data))
	}
	return true
}

// markSetupPrinted records that the first successful serve has happened.
func markSetupPrinted() {
	marker := setupPrintedPath()
	_ = os.MkdirAll(filepath.Dir(marker), 0o700)
	_ = os.WriteFile(marker, []byte(time.Now().UTC().Format(time.RFC3339)), 0o600)
}

// Run starts the agent.
func Run() error {
	if _, err := os.Lstat(pki.PKIDir()); err == nil {
		store.EnsureLayout(pki.OpenVPNRoot())
	} else if _, err := os.Lstat(filepath.Join(pki.OpenVPNRoot(), "server", "server.conf")); err == nil {
		store.EnsureLayout(pki.OpenVPNRoot())
	}
	if err := store.FixRuntimePermissions(pki.OpenVPNRoot()); err != nil {
		return fmt.Errorf("runtime permissions: %w", err)
	}
	pki.EnsureSecretPerms()
	if src := fsx.EnvFileSource(); src != "" {
		logging.Info(".env loaded from %s (.env wins over process env)", src)
	}
	s := NewServer()
	if len(s.APIKey) < 16 {
		return fmt.Errorf("API_KEY must be at least 16 characters")
	}
	if len(s.APIKey) < 32 {
		logging.Warn("API_KEY shorter than 32 characters; use openssl rand -hex 32 for new nodes")
	}
	cert, key, err := TLSMaterial()
	if err != nil {
		return err
	}
	s.CertFile = cert
	s.KeyFile = key
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// The agent now owns the OpenVPN daemon: ovnode.service forks openvpn as
	// a child and respawns it in SuperviseOpenVPN. There is no second unit.
	ovpn.SuperviseOpenVPN(ctx)
	logging.Info("ovnode agent %s starting (addr=%s, openvpn_root=%s)",
		version.Version, s.Addr, pki.OpenVPNRoot())
	fmt.Println("ovnode serve listening on", s.Addr)
	printed := printSetupIfFirstBoot()
	if printed {
		markSetupPrinted()
	}
	go func() {
		if _, err := os.Stat(filepath.Join(pki.PKIDir(), "private", "ca.key")); err != nil {
			return
		}
		if !pki.RefreshCRL() {
			logging.Warn("CRL refresh failed")
		}
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !pki.RefreshCRL() {
					logging.Warn("CRL refresh failed")
				}
			}
		}
	}()
	return s.ListenAndServe(ctx)
}

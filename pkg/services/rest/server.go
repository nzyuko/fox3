package rest

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/nzyuko/fox3/v2/pkg/pivot"
	"github.com/nzyuko/fox3/v2/pkg/screenshots"
	"github.com/nzyuko/fox3/v2/pkg/services/agent"
	"github.com/nzyuko/fox3/v2/pkg/services/credentials"
	"github.com/nzyuko/fox3/v2/pkg/services/job"
	"github.com/nzyuko/fox3/v2/pkg/services/listeners"
)

// Server structure holds the services required for the API
type Server struct {
	ls                listeners.ListenerService
	agentService      *agent.Service
	jobService        *job.Service
	credService       *credentials.Service
	screenshotService *screenshots.Service
	pivotService      *pivot.Service
	password          string
	httpServer        *http.Server
}

// NewRestServer creates a new Server instance
func NewRestServer(password string) *Server {
	return &Server{
		ls:                listeners.NewListenerService(),
		agentService:      agent.NewAgentService(),
		jobService:        job.NewJobService(),
		credService:       credentials.NewCredentialService(),
		screenshotService: screenshots.NewService(),
		pivotService:      pivot.NewService(),
		password:          password,
	}
}

// Shutdown gracefully stops the HTTP server with the given context deadline.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}
	return s.httpServer.Shutdown(ctx)
}

// corsMiddleware restricts cross-origin requests to localhost origins only.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && !isLocalhostOrigin(origin) {
			http.Error(w, "CORS: origin not allowed", http.StatusForbidden)
			return
		}
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Vary", "Origin")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// isLocalhostOrigin returns true when the origin host is 127.0.0.1 or localhost.
func isLocalhostOrigin(origin string) bool {
	host := origin
	if idx := strings.Index(host, "://"); idx != -1 {
		host = host[idx+3:]
	}
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}
	return host == "127.0.0.1" || host == "localhost" || host == "::1"
}

// Run starts the API server and blocks until it stops.
// Only login (HTTP) and WebSocket are exposed — all operations go through WS.
func (s *Server) Run(addr string) error {
	slog.Log(context.Background(), slog.LevelDebug, "starting API server")

	mux := http.NewServeMux()

	// Public: login (returns JWT for WS auth)
	mux.HandleFunc("/api/login", s.LoginHandler)

	// Protected: WebSocket only
	apiMux := http.NewServeMux()
	hub := newWSHub(s)
	go hub.run()
	apiMux.HandleFunc("/api/ws", hub.ServeWS)

	mux.Handle("/api/", AuthMiddleware(apiMux))

	// Serve frontend static files
	// Try relative path first, fall back to checking common locations
	frontendDir := "frontend/dist"
	if _, err := os.Stat(frontendDir); os.IsNotExist(err) {
		// Try from executable directory
		if exe, err := os.Executable(); err == nil {
			candidate := filepath.Join(filepath.Dir(exe), "frontend", "dist")
			if _, err := os.Stat(candidate); err == nil {
				frontendDir = candidate
			}
		}
	}
	mux.Handle("/", spaFileServer(frontendDir))

	handler := corsMiddleware(mux)

	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  0, // WebSocket streams must stay open
		WriteTimeout: 0,
		IdleTimeout:  120 * time.Second,
	}

	slog.Info(fmt.Sprintf("API server listening on %s (WS-only)", addr))
	err := s.httpServer.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func spaFileServer(frontendDir string) http.Handler {
	root := http.Dir(frontendDir)
	fs := http.FileServer(root)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			fs.ServeHTTP(w, r)
			return
		}

		cleanPath := path.Clean("/" + r.URL.Path)
		filePath := strings.TrimPrefix(cleanPath, "/")
		if filePath == "." || filePath == "" {
			fs.ServeHTTP(w, r)
			return
		}

		if file, err := root.Open(filePath); err == nil {
			if stat, statErr := file.Stat(); statErr == nil && !stat.IsDir() {
				_ = file.Close()
				fs.ServeHTTP(w, r)
				return
			}
			_ = file.Close()
		}

		if strings.HasPrefix(r.URL.Path, "/assets/") || strings.Contains(path.Base(r.URL.Path), ".") {
			http.NotFound(w, r)
			return
		}

		indexReq := r.Clone(r.Context())
		indexReq.URL.Path = "/"
		indexReq.URL.RawPath = ""
		fs.ServeHTTP(w, indexReq)
	})
}

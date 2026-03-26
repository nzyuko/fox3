package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// JwtSecret will be initialized globally to sign JWT tokens
	JwtSecret = []byte("default-fox3-secret-override-me")
)

// ── Login rate limiter ──────────────────────────────────────────────────────

const (
	loginMaxFailures   = 5
	loginLockoutPeriod = 15 * time.Minute
	loginCleanupEvery  = 5 * time.Minute
)

type loginAttempt struct {
	failures int
	lockedAt time.Time
}

type loginRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*loginAttempt
}

var loginLimiter = &loginRateLimiter{entries: make(map[string]*loginAttempt)}

func init() {
	go func() {
		ticker := time.NewTicker(loginCleanupEvery)
		defer ticker.Stop()
		for range ticker.C {
			loginLimiter.cleanup()
		}
	}()
}

// allowed returns true if the IP is not currently locked out.
func (r *loginRateLimiter) allowed(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[ip]
	if !ok {
		return true
	}
	if !e.lockedAt.IsZero() && time.Now().Before(e.lockedAt.Add(loginLockoutPeriod)) {
		return false
	}
	return true
}

// fail records a failed attempt for the IP and locks it out after maxFailures.
func (r *loginRateLimiter) fail(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.entries[ip]
	if e == nil {
		e = &loginAttempt{}
		r.entries[ip] = e
	}
	e.failures++
	if e.failures >= loginMaxFailures {
		e.lockedAt = time.Now()
		slog.Warn("REST login: IP locked out after repeated failures", "ip", ip, "failures", e.failures)
	}
}

// succeed clears the record for the IP on successful authentication.
func (r *loginRateLimiter) succeed(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, ip)
}

// cleanup removes entries whose lockout has fully expired.
func (r *loginRateLimiter) cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := time.Now().Add(-loginLockoutPeriod)
	for ip, e := range r.entries {
		if e.lockedAt.IsZero() || e.lockedAt.Before(cutoff) {
			delete(r.entries, ip)
		}
	}
}

// remoteIP extracts the bare IP from a host:port string.
func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// contextKey is an unexported type for context keys in this package, preventing collisions
// with keys from other packages that use plain string keys.
type contextKey string

const userContextKey contextKey = "user"

type Claims struct {
	User string `json:"user"`
	jwt.RegisteredClaims
}

// SetSecret allows main.go to override the default JWT secret (e.g., using the supplied password)
func SetSecret(secret string) {
	if secret != "" {
		JwtSecret = []byte(secret)
	}
}

// GenerateToken creates a new JWT token for a given user
func GenerateToken(user string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		User: user,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(JwtSecret)
}

// AuthMiddleware intercepts HTTP requests to ensure a valid JWT is present
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CORS preflight
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		// EventSource API doesn't support custom headers; allow token as query param
		if authHeader == "" {
			if tok := r.URL.Query().Get("token"); tok != "" {
				authHeader = "Bearer " + tok
			} else {
				http.Error(w, "authorization header missing", http.StatusUnauthorized)
				return
			}
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			http.Error(w, "invalid authorization header format", http.StatusUnauthorized)
			return
		}

		tokenStr := parts[1]
		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return JwtSecret, nil
		})

		if err != nil || !token.Valid {
			slog.Warn("failed incoming REST API authentication request", "error", err)
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), userContextKey, claims.User)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// LoginRequest defines the expected JSON body for the login endpoint
type LoginRequest struct {
	Password string `json:"password"`
}

// LoginResponse defines the JSON body returned on a successful login
type LoginResponse struct {
	Token string `json:"token"`
}

// LoginHandler handles authentication for the REST API
func (s *Server) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := remoteIP(r.RemoteAddr)

	// Rate-limit check before touching the password at all
	if !loginLimiter.allowed(ip) {
		slog.Warn("REST login: request from locked-out IP", "ip", ip)
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if req.Password != s.password {
		slog.Warn("failed REST API login attempt with incorrect password", "ip", ip)
		loginLimiter.fail(ip)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	loginLimiter.succeed(ip)

	// Password is correct, issue token
	token, err := GenerateToken("admin")
	if err != nil {
		slog.Error("failed to generate JWT token", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(LoginResponse{Token: token}) //nolint:errcheck
}

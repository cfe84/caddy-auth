package authsvc

import (
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Server struct {
	Store       *Store
	InstanceKey string
	limiter     *loginLimiter
}

type loginLimiter struct {
	mu     sync.Mutex
	counts map[string]rateEntry
}

type rateEntry struct {
	count int
	reset time.Time
}

func NewServer(store *Store, instanceKey string) (*Server, error) {
	if store == nil || len(instanceKey) < 32 {
		return nil, errors.New("store and an instance key of at least 32 characters are required")
	}
	s := &Server{Store: store, InstanceKey: instanceKey, limiter: &loginLimiter{counts: make(map[string]rateEntry)}}
	return s, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /login", s.login)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("GET /logout", s.logout)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("POST /api/sites", s.registerSite)
	mux.HandleFunc("POST /api/health", s.apiHealth)
	mux.HandleFunc("POST /api/exchange", s.exchange)
	mux.HandleFunc("POST /api/validate", s.validate)
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		next.ServeHTTP(w, r)
	})
}

type loginRequest struct {
	Callback  string `json:"callback"`
	Site      string `json:"site"`
	State     string `json:"state"`
	Challenge string `json:"challenge"`
	Role      string `json:"role"`
	TTL       int64  `json:"ttl_seconds"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.Method == http.MethodPost {
		if r.ContentLength > 32<<10 {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	}
	request, err := parseLogin(r)
	if err != nil {
		log.Printf("WARN invalid login attempt: reason=malformed_parameters")
		http.Error(w, "invalid login request", http.StatusBadRequest)
		return
	}
	reason, err := s.callbackRejectionReason(request)
	if err != nil {
		http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
		return
	}
	if reason != "" {
		log.Printf("WARN invalid login attempt: reason=%s", reason)
		http.Error(w, "invalid login request", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodPost {
		if r.ParseForm() != nil || !validCSRF(r) {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if !s.limiter.allow(clientIP(r)) {
			http.Error(w, "try again later", http.StatusTooManyRequests)
			return
		}
		id, err := s.Store.authenticate(r.Form.Get("username"), r.Form.Get("password"))
		if err != nil {
			status := http.StatusServiceUnavailable
			message := "authentication unavailable"
			if errors.Is(err, errInvalidCredentials) {
				status, message = http.StatusUnauthorized, "sign-in failed"
			}
			http.Error(w, message, status)
			return
		}
		token, expires, err := s.Store.CreateSession(id)
		if err != nil {
			http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "__Host-auth_sso", Value: token, Path: "/", Expires: expires, MaxAge: int(ssolifetime.Seconds()), Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		s.finishLogin(w, r, request, token)
		return
	}
	if cookie, err := r.Cookie("__Host-auth_sso"); err == nil {
		if _, _, err = s.Store.Session(cookie.Value); err == nil {
			s.finishLogin(w, r, request, cookie.Value)
			return
		} else if !errors.Is(err, sql.ErrNoRows) && !errors.Is(err, errSessionExpired) {
			http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	csrf, err := randomToken(24)
	if err != nil {
		http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "__Host-auth_csrf", Value: csrf, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 600})
	encoded, _ := json.Marshal(request)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><title>Sign in</title></head><body><form method="post" action="/login"><input type="hidden" name="csrf" value="%s"><input type="hidden" name="request" value="%s"><label>Username <input name="username" autocomplete="username" required></label><label>Password <input type="password" name="password" autocomplete="current-password" required></label><button type="submit">Sign in</button></form></body></html>`, html.EscapeString(csrf), html.EscapeString(string(encoded)))
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		forwarded := r.Header.Values("X-Forwarded-For")
		if len(forwarded) == 1 {
			first := strings.TrimSpace(strings.SplitN(forwarded[0], ",", 2)[0])
			if client := net.ParseIP(first); client != nil {
				return client.String()
			}
		}
	}
	if ip != nil {
		return ip.String()
	}
	return host
}

func parseLogin(r *http.Request) (loginRequest, error) {
	var request loginRequest
	if r.Method == http.MethodPost {
		if r.ParseForm() != nil || json.Unmarshal([]byte(r.Form.Get("request")), &request) != nil {
			return request, errors.New("invalid request")
		}
		return request, nil
	}
	values := r.URL.Query()
	var err error
	request.Callback, err = queryOne(values, "callback")
	if err != nil {
		return request, err
	}
	request.Site, err = queryOne(values, "site")
	if err != nil {
		return request, err
	}
	request.State, err = queryOne(values, "state")
	if err != nil {
		return request, err
	}
	request.Challenge, err = queryOne(values, "challenge")
	if err != nil {
		return request, err
	}
	request.Role, err = queryOne(values, "role")
	if err != nil {
		return request, err
	}
	ttl, err := queryOne(values, "ttl")
	if err != nil {
		return request, err
	}
	if request.TTL, err = strconv.ParseInt(ttl, 10, 64); err != nil {
		return request, err
	}
	return request, nil
}

func queryOne(values url.Values, key string) (string, error) {
	items := values[key]
	if len(items) != 1 || items[0] == "" {
		return "", errors.New("missing or duplicate parameter")
	}
	return items[0], nil
}

func (s *Server) callbackRejectionReason(request loginRequest) (string, error) {
	canonical, err := canonicalOrigin(request.Site)
	if err != nil || canonical != request.Site {
		return "invalid_origin", nil
	}
	if request.Callback != request.Site+"/_caddy_auth/callback" {
		return "invalid_callback", nil
	}
	if !validPKCEValue(request.State) {
		return "invalid_state", nil
	}
	if !validPKCEValue(request.Challenge) {
		return "invalid_pkce", nil
	}
	if request.Role == "" {
		return "missing_role", nil
	}
	if request.TTL <= 0 || request.TTL > int64((24*time.Hour).Seconds()) {
		return "invalid_ttl", nil
	}
	var registered int
	if err := s.Store.db.QueryRow("SELECT count(*) FROM sites WHERE origin=?", request.Site).Scan(&registered); err != nil {
		return "", err
	}
	if registered != 1 {
		return "unregistered_site", nil
	}
	return "", nil
}

func validPKCEValue(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, request loginRequest, session string) {
	id, _, err := s.Store.Session(session)
	if err != nil {
		status := http.StatusServiceUnavailable
		message := "authentication unavailable"
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, errSessionExpired) {
			status, message = http.StatusUnauthorized, "sign in again"
		}
		http.Error(w, message, status)
		return
	}
	hasRole, err := s.Store.HasRole(id, request.Role)
	if err != nil {
		http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
		return
	}
	if !hasRole {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	code, err := s.Store.IssueCode(session, request.Site, request.Callback, request.State, request.Role, request.Challenge)
	if err != nil {
		http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
		return
	}
	location, err := url.Parse(request.Callback)
	if err != nil {
		http.Error(w, "invalid login request", http.StatusBadRequest)
		return
	}
	query := location.Query()
	query.Set("code", code)
	query.Set("state", request.State)
	location.RawQuery = query.Encode()
	http.Redirect(w, r, location.String(), http.StatusSeeOther)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if err := s.Store.db.PingContext(r.Context()); err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiHealth(w http.ResponseWriter, r *http.Request) {
	if !s.trusted(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	s.health(w, r)
}

func validCSRF(r *http.Request) bool {
	cookie, err := r.Cookie("__Host-auth_csrf")
	if err != nil {
		return false
	}
	form := r.Form.Get("csrf")
	return len(cookie.Value) == len(form) && subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(form)) == 1
}

func (l *loginLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.counts) > 10000 {
		for key, entry := range l.counts {
			if now.After(entry.reset) {
				delete(l.counts, key)
			}
		}
		if len(l.counts) > 10000 {
			return false
		}
	}
	entry := l.counts[key]
	if now.After(entry.reset) {
		entry = rateEntry{reset: now.Add(time.Minute)}
	}
	entry.count++
	l.counts[key] = entry
	return entry.count <= 10
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		csrf, err := randomToken(24)
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "__Host-auth_csrf", Value: csrf, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 600})
		fmt.Fprintf(w, `<form method="post" action="/logout"><input type="hidden" name="csrf" value="%s"><button>Sign out</button></form>`, html.EscapeString(csrf))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if r.ParseForm() != nil || !validCSRF(r) {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if cookie, err := r.Cookie("__Host-auth_sso"); err == nil {
		if err := s.Store.RevokeSession(cookie.Value); err != nil {
			http.Error(w, "sign out unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	http.SetCookie(w, &http.Cookie{Name: "__Host-auth_sso", Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) trusted(r *http.Request) bool {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return false
	}
	key := strings.TrimPrefix(values[0], "Bearer ")
	return len(key) == len(s.InstanceKey) && subtle.ConstantTimeCompare([]byte(key), []byte(s.InstanceKey)) == 1
}

func (s *Server) registerSite(w http.ResponseWriter, r *http.Request) {
	if !s.trusted(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var body struct {
		Origin string `json:"origin"`
	}
	if decodeJSON(w, r, &body) != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	canonical, err := canonicalOrigin(body.Origin)
	if err != nil {
		http.Error(w, "invalid origin", http.StatusBadRequest)
		return
	}
	if err := s.Store.registerCanonicalSite(canonical); err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) exchange(w http.ResponseWriter, r *http.Request) {
	if !s.trusted(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var body struct {
		Code     string `json:"code"`
		Verifier string `json:"verifier"`
		Callback string `json:"callback"`
		Site     string `json:"site"`
		State    string `json:"state"`
		Role     string `json:"role"`
		TTL      int64  `json:"ttl_seconds"`
	}
	if decodeJSON(w, r, &body) != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	token, expires, err := s.Store.ExchangeCode(body.Code, body.Verifier, body.Callback, body.Site, body.State, body.Role, time.Duration(body.TTL)*time.Second)
	if err != nil {
		if errors.Is(err, errForbidden) {
			http.Error(w, "forbidden", http.StatusForbidden)
		} else if errors.Is(err, errCapacity) {
			http.Error(w, "authorization unavailable", http.StatusServiceUnavailable)
		} else {
			http.Error(w, "invalid authorization code", http.StatusUnauthorized)
		}
		return
	}
	writeJSON(w, map[string]any{"token": token, "expires_at": expires.Unix()})
}

func (s *Server) validate(w http.ResponseWriter, r *http.Request) {
	if !s.trusted(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var body struct {
		Token string `json:"token"`
		Site  string `json:"site"`
		Role  string `json:"role"`
		TTL   int64  `json:"ttl_seconds"`
	}
	if decodeJSON(w, r, &body) != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	result, err := s.Store.Validate(body.Token, body.Site, body.Role, time.Duration(body.TTL)*time.Second)
	if err != nil {
		http.Error(w, "validation unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, result)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(destination)
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

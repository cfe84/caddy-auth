package caddy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const callbackPath = "/_caddy_auth/callback"

func init() {
	caddy.RegisterModule(Auth{})
	httpcaddyfile.RegisterGlobalOption("auth", parseGlobal)
	httpcaddyfile.RegisterDirective("require_auth", parseRequireAuth)
	httpcaddyfile.RegisterDirectiveOrder("require_auth", httpcaddyfile.Before, "reverse_proxy")
}

type globalConfig struct {
	Service       string `json:"service"`
	InstanceToken string `json:"instance_token,omitempty"`
}

func parseGlobal(d *caddyfile.Dispenser, existing any) (any, error) {
	if existing != nil {
		return nil, errors.New("auth global option may only be configured once")
	}
	d.Next()
	var config globalConfig
	for d.NextBlock(0) {
		switch d.Val() {
		case "service":
			if !d.NextArg() || config.Service != "" {
				return nil, d.ArgErr()
			}
			config.Service = strings.TrimRight(d.Val(), "/")
		case "instance_token":
			if !d.NextArg() || config.InstanceToken != "" {
				return nil, d.ArgErr()
			}
			config.InstanceToken = d.Val()
		default:
			return nil, d.Errf("unrecognized auth option %q", d.Val())
		}
		if d.NextArg() {
			return nil, d.ArgErr()
		}
	}
	u, err := url.Parse(config.Service)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" && u.Path != "/" || u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("auth service must be an HTTPS origin")
	}
	if len(config.InstanceToken) < 32 {
		return nil, errors.New("auth instance_token must contain at least 32 characters")
	}
	return config, nil
}

func parseRequireAuth(h httpcaddyfile.Helper) ([]httpcaddyfile.ConfigValue, error) {
	if !h.Next() {
		return nil, h.ArgErr()
	}
	matcher, err := h.ExtractMatcherSet()
	if err != nil {
		return nil, err
	}
	h.Next() // ExtractMatcherSet resets the dispenser after examining an optional matcher.
	global, ok := h.Option("auth").(globalConfig)
	if !ok {
		return nil, errors.New("require_auth requires the global auth option")
	}
	config := Auth{Service: global.Service, InstanceToken: global.InstanceToken}
	for h.NextBlock(0) {
		switch h.Val() {
		case "role":
			if !h.NextArg() || config.Role != "" {
				return nil, h.ArgErr()
			}
			config.Role = h.Val()
		case "ttl":
			if !h.NextArg() || config.TTL != "" {
				return nil, h.ArgErr()
			}
			config.TTL = h.Val()
		default:
			return nil, h.Errf("unrecognized require_auth option %q", h.Val())
		}
		if h.NextArg() {
			return nil, h.ArgErr()
		}
	}
	if config.Role == "" {
		return nil, errors.New("require_auth role is required")
	}
	if config.TTL == "" {
		config.TTL = "1h"
	}
	duration, err := time.ParseDuration(config.TTL)
	if err != nil || duration < time.Second || duration > 24*time.Hour {
		return nil, errors.New("require_auth ttl must be between 1s and 24h")
	}
	callbackConfig := config
	callbackConfig.Callback = true
	callback := h.NewRoute(caddy.ModuleMap{"path": json.RawMessage(`["` + callbackPath + `"]`)}, &callbackConfig)
	config.Callback = false
	protected := h.NewRoute(matcher, &config)
	return append(callback, protected...), nil
}

type Auth struct {
	Service       string `json:"service,omitempty"`
	InstanceToken string `json:"instance_token,omitempty"`
	Role          string `json:"role,omitempty"`
	TTL           string `json:"ttl,omitempty"`
	Callback      bool   `json:"callback,omitempty"`
	client        *http.Client
}

func (Auth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.require_auth", New: func() caddy.Module { return new(Auth) }}
}

func (a *Auth) Provision(caddy.Context) error {
	service, err := url.Parse(a.Service)
	if err != nil || service.Scheme != "https" || service.Host == "" || service.User != nil || service.Path != "" && service.Path != "/" || service.RawPath != "" || service.RawQuery != "" || service.Fragment != "" || len(a.InstanceToken) < 32 {
		return errors.New("require_auth has invalid auth service settings")
	}
	if !a.Callback {
		if a.Role == "" {
			return errors.New("require_auth role is required")
		}
		ttl, err := time.ParseDuration(a.TTL)
		if err != nil {
			return fmt.Errorf("invalid require_auth ttl: %w", err)
		}
		if ttl < time.Second || ttl > 24*time.Hour {
			return errors.New("require_auth ttl must be between 1s and 24h")
		}
	}
	a.client = &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return nil
}

func (a *Auth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if r.URL.Path == callbackPath {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		defer func() {
			r.URL.RawQuery = ""
			r.URL.RawPath = ""
			r.URL.Path = callbackPath
			r.RequestURI = callbackPath
		}()
		if !a.Callback {
			return caddyhttp.HandlerError{StatusCode: http.StatusBadRequest, Err: errors.New("invalid callback route")}
		}
		return a.callback(w, r)
	}
	if a.Callback {
		return caddyhttp.HandlerError{StatusCode: http.StatusNotFound, Err: errors.New("not found")}
	}
	origin, err := requestOrigin(r)
	if err != nil {
		return caddyhttp.HandlerError{StatusCode: http.StatusForbidden, Err: err}
	}
	ttl, _ := time.ParseDuration(a.TTL)
	cookie, err := r.Cookie(authorizationCookieName(origin))
	if err == nil && cookie.Value != "" {
		result, err := a.validate(r.Context(), cookie.Value, origin, a.Role, ttl)
		if err != nil {
			return caddyhttp.HandlerError{StatusCode: http.StatusServiceUnavailable, Err: err}
		}
		switch result.Outcome {
		case "authorized":
			stripAuthCookies(r)
			return next.ServeHTTP(w, r)
		case "renewal_required":
			if result.Token == "" {
				return caddyhttp.HandlerError{StatusCode: http.StatusServiceUnavailable, Err: errors.New("auth service returned an empty renewed token")}
			}
			setAuthCookie(w, authorizationCookieName(origin), result.Token)
			stripAuthCookies(r)
			return next.ServeHTTP(w, r)
		case "forbidden":
			return caddyhttp.HandlerError{StatusCode: http.StatusForbidden, Err: errors.New("required role is not assigned")}
		case "invalid":
			clearAuthCookie(w, authorizationCookieName(origin))
		default:
			return caddyhttp.HandlerError{StatusCode: http.StatusServiceUnavailable, Err: errors.New("unexpected auth service response")}
		}
	}
	return a.beginLogin(w, r, origin, ttl)
}

func (a *Auth) beginLogin(w http.ResponseWriter, r *http.Request, origin string, ttl time.Duration) error {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if err := a.api(r.Context(), "/api/health", nil, nil); err != nil {
		return caddyhttp.HandlerError{StatusCode: http.StatusServiceUnavailable, Err: err}
	}
	returnURL, err := localReturnURL(r.URL)
	if err != nil {
		return caddyhttp.HandlerError{StatusCode: http.StatusBadRequest, Err: err}
	}
	state, err := randomString(32)
	if err != nil {
		return caddyhttp.HandlerError{StatusCode: http.StatusInternalServerError, Err: err}
	}
	verifier, err := randomString(32)
	if err != nil {
		return caddyhttp.HandlerError{StatusCode: http.StatusInternalServerError, Err: err}
	}
	challenge := sha256.Sum256([]byte(verifier))
	if !attempts.add(state, loginAttempt{Verifier: verifier, Return: returnURL, Site: origin, Role: a.Role, TTL: ttl, Expires: time.Now().Add(5 * time.Minute)}) {
		return caddyhttp.HandlerError{StatusCode: http.StatusServiceUnavailable, Err: errors.New("login attempt capacity reached")}
	}
	callback := origin + callbackPath
	service := strings.TrimRight(a.Service, "/") + "/login"
	loginURL, _ := url.Parse(service)
	query := loginURL.Query()
	query.Set("callback", callback)
	query.Set("site", origin)
	query.Set("state", state)
	query.Set("challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
	query.Set("role", a.Role)
	query.Set("ttl", fmt.Sprint(int64(ttl.Seconds())))
	loginURL.RawQuery = query.Encode()
	http.SetCookie(w, &http.Cookie{Name: flowCookieName(state), Value: state, Path: "/", Expires: time.Now().Add(5 * time.Minute), MaxAge: 300, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, loginURL.String(), http.StatusSeeOther)
	return nil
}

func (a *Auth) callback(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		return caddyhttp.HandlerError{StatusCode: http.StatusMethodNotAllowed, Err: errors.New("callback requires GET")}
	}
	query := r.URL.Query()
	if len(query["state"]) != 1 || len(query["code"]) != 1 {
		return caddyhttp.HandlerError{StatusCode: http.StatusBadRequest, Err: errors.New("invalid callback")}
	}
	state, code := query.Get("state"), query.Get("code")
	if !validState(state) {
		return caddyhttp.HandlerError{StatusCode: http.StatusBadRequest, Err: errors.New("invalid callback state")}
	}
	cookie, err := r.Cookie(flowCookieName(state))
	if err != nil || len(cookie.Value) != len(state) || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		return caddyhttp.HandlerError{StatusCode: http.StatusBadRequest, Err: errors.New("invalid callback state")}
	}
	attempt, ok := attempts.take(state)
	clearFlowCookie(w, state)
	if !ok || time.Now().After(attempt.Expires) {
		return caddyhttp.HandlerError{StatusCode: http.StatusBadRequest, Err: errors.New("expired login attempt")}
	}
	origin, err := requestOrigin(r)
	if err != nil || origin != attempt.Site {
		return caddyhttp.HandlerError{StatusCode: http.StatusBadRequest, Err: errors.New("callback origin mismatch")}
	}
	var response struct {
		Token string `json:"token"`
	}
	body := map[string]any{"code": code, "verifier": attempt.Verifier, "callback": attempt.Site + callbackPath, "site": attempt.Site, "state": state, "role": attempt.Role, "ttl_seconds": int64(attempt.TTL.Seconds())}
	if err := a.api(r.Context(), "/api/exchange", body, &response); err != nil {
		var statusErr serviceStatusError
		if errors.As(err, &statusErr) && statusErr.Status == http.StatusForbidden {
			return caddyhttp.HandlerError{StatusCode: http.StatusForbidden, Err: errors.New("required role is not assigned")}
		}
		if errors.As(err, &statusErr) && (statusErr.Status == http.StatusUnauthorized || statusErr.Status == http.StatusBadRequest) {
			return caddyhttp.HandlerError{StatusCode: http.StatusBadRequest, Err: errors.New("invalid authorization response")}
		}
		return caddyhttp.HandlerError{StatusCode: http.StatusServiceUnavailable, Err: err}
	}
	if response.Token == "" {
		return caddyhttp.HandlerError{StatusCode: http.StatusServiceUnavailable, Err: errors.New("auth service returned an empty token")}
	}
	setAuthCookie(w, authorizationCookieName(attempt.Site), response.Token)
	returnURL, err := validateReturnURL(attempt.Return)
	if err != nil {
		return caddyhttp.HandlerError{StatusCode: http.StatusBadRequest, Err: err}
	}
	http.Redirect(w, r, returnURL, http.StatusSeeOther)
	return nil
}

func (a *Auth) validate(ctx context.Context, token, site, role string, ttl time.Duration) (authResult, error) {
	var result authResult
	request := map[string]any{"token": token, "site": site, "role": role, "ttl_seconds": int64(ttl.Seconds())}
	err := a.api(ctx, "/api/validate", request, &result)
	return result, err
}

type authResult struct {
	Outcome string `json:"outcome"`
	Token   string `json:"token"`
}

func (a *Auth) api(ctx context.Context, path string, payload, result any) error {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(a.Service, "/")+path, body)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+a.InstanceToken)
	response, err := a.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusForbidden {
		return serviceStatusError{Status: response.StatusCode}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return serviceStatusError{Status: response.StatusCode}
	}
	if result == nil {
		_, err := io.Copy(io.Discard, io.LimitReader(response.Body, 32<<10))
		return err
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 32<<10)).Decode(result); err != nil {
		return err
	}
	return nil
}

func requestOrigin(r *http.Request) (string, error) {
	if r.TLS == nil {
		return "", errors.New("authentication requires HTTPS")
	}
	if r.Host == "" || strings.HasSuffix(r.Host, ":") || strings.ContainsAny(r.Host, "@/%?#\\") {
		return "", errors.New("invalid request host")
	}
	host := strings.ToLower(r.Host)
	if parsedHost, port, err := net.SplitHostPort(host); err == nil {
		if port == "443" {
			host = parsedHost
		} else {
			host = net.JoinHostPort(parsedHost, port)
		}
	}
	parsed, err := url.Parse("https://" + host)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Path != "" {
		return "", errors.New("invalid request host")
	}
	return "https://" + strings.ToLower(parsed.Host), nil
}

func localReturnURL(requestURL *url.URL) (string, error) {
	if requestURL == nil || requestURL.Opaque != "" {
		return "", errors.New("invalid return URL")
	}
	path := requestURL.EscapedPath()
	if path == "" {
		path = "/"
	}
	lower := strings.ToLower(path)
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "\\\r\n") || strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.Contains(lower, "%2e") {
		return "", errors.New("invalid local return path")
	}
	return validateReturnURL(path + rawQuery(requestURL))
}

func rawQuery(u *url.URL) string {
	if u.RawQuery == "" {
		return ""
	}
	return "?" + u.RawQuery
}

func validateReturnURL(value string) (string, error) {
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.User != nil || parsed.Fragment != "" || parsed.Opaque != "" {
		return "", errors.New("invalid local return URL")
	}
	path := parsed.EscapedPath()
	lower := strings.ToLower(path)
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "\\\r\n") || strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") || strings.Contains(lower, "%2e") {
		return "", errors.New("invalid local return path")
	}
	return parsed.RequestURI(), nil
}

func stripAuthCookies(r *http.Request) {
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	// Rebuild application cookies after removing the host-only flow credentials.
	var forwarded []string
	for _, cookie := range cookies {
		if !strings.HasPrefix(cookie.Name, "__Host-caddy_auth_") {
			forwarded = append(forwarded, cookie.String())
		}
	}
	if len(forwarded) > 0 {
		r.Header.Set("Cookie", strings.Join(forwarded, "; "))
	}
}

type serviceStatusError struct{ Status int }

func (e serviceStatusError) Error() string {
	return fmt.Sprintf("auth service returned status %d", e.Status)
}

func setAuthCookie(w http.ResponseWriter, name, token string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

func clearAuthCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

func clearFlowCookie(w http.ResponseWriter, state string) {
	http.SetCookie(w, &http.Cookie{Name: flowCookieName(state), Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

func randomString(size int) (string, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func authorizationCookieName(site string) string {
	digest := sha256.Sum256([]byte(site))
	return "__Host-caddy_auth_" + base64.RawURLEncoding.EncodeToString(digest[:12])
}

func flowCookieName(state string) string { return "__Host-caddy_auth_state_" + state }

func validState(state string) bool {
	if len(state) != 43 {
		return false
	}
	for _, char := range state {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '-' || char == '_') {
			return false
		}
	}
	return true
}

type loginAttempt struct {
	Verifier, Return, Site, Role string
	TTL                          time.Duration
	Expires                      time.Time
}
type attemptStore struct {
	mu      sync.Mutex
	entries map[string]loginAttempt
}

var attempts = attemptStore{entries: make(map[string]loginAttempt)}

func (s *attemptStore) add(key string, value loginAttempt) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for key, item := range s.entries {
		if now.After(item.Expires) {
			delete(s.entries, key)
		}
	}
	if len(s.entries) >= 10000 { // shortcut: reject new flows at process-local capacity; use shared storage when scaling instances.
		return false
	}
	s.entries[key] = value
	return true
}

func (s *attemptStore) take(key string) (loginAttempt, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.entries[key]
	delete(s.entries, key)
	return value, ok
}

var _ caddy.Provisioner = (*Auth)(nil)
var _ caddyhttp.MiddlewareHandler = (*Auth)(nil)

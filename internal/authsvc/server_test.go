package authsvc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestBrowserSignInSSOCodeExchangeAndTrustedBoundary(t *testing.T) {
	store, _ := testStore(t)
	if err := store.AddRole("unassigned"); err != nil {
		t.Fatal(err)
	}
	service, err := NewServer(store, strings.Repeat("k", 32))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(service.Handler())
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	verifier, err := randomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(verifier))
	state, err := randomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	login := loginRequest{Callback: "https://app.example.com/_caddy_auth/callback", Site: "https://app.example.com", State: state, Challenge: base64.RawURLEncoding.EncodeToString(digest[:]), Role: "accounting", TTL: 3600}
	encoded, _ := json.Marshal(login)
	query := url.Values{"callback": {login.Callback}, "site": {login.Site}, "state": {login.State}, "challenge": {login.Challenge}, "role": {login.Role}, "ttl": {"3600"}}
	response, err := client.Get(server.URL + "/login?" + query.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || !strings.Contains(readBody(t, response), "autocomplete=\"current-password\"") {
		t.Fatalf("sign-in page status %d", response.StatusCode)
	}
	var csrf string
	for _, cookie := range response.Cookies() {
		if cookie.Name == "__Host-auth_csrf" {
			csrf = cookie.Value
			if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
				t.Fatalf("CSRF cookie attributes: %+v", cookie)
			}
		}
	}
	if csrf == "" {
		t.Fatal("missing CSRF cookie")
	}
	response.Body.Close()
	form := url.Values{"csrf": {csrf}, "request": {string(encoded)}, "username": {"alice"}, "password": {"correct horse battery staple"}}
	invalidPost, _ := http.NewRequest(http.MethodPost, server.URL+"/login", strings.NewReader(form.Encode()))
	invalidPost.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	invalidResponse, err := client.Do(invalidPost)
	if err != nil {
		t.Fatal(err)
	}
	if invalidResponse.StatusCode != http.StatusBadRequest {
		t.Fatalf("login without CSRF status %d", invalidResponse.StatusCode)
	}
	invalidResponse.Body.Close()
	post, _ := http.NewRequest(http.MethodPost, server.URL+"/login", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(&http.Cookie{Name: "__Host-auth_csrf", Value: csrf})
	response, err = client.Do(post)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusSeeOther {
		t.Fatalf("sign-in status %d", response.StatusCode)
	}
	callback, err := url.Parse(response.Header.Get("Location"))
	if err != nil || callback.Host != "app.example.com" || callback.Path != "/_caddy_auth/callback" || callback.Query().Get("state") != login.State {
		t.Fatalf("callback location %q", response.Header.Get("Location"))
	}
	var sso string
	for _, cookie := range response.Cookies() {
		if cookie.Name == "__Host-auth_sso" {
			sso = cookie.Value
			if cookie.Path != "/" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
				t.Fatalf("SSO cookie attributes: %+v", cookie)
			}
		}
	}
	response.Body.Close()
	if sso == "" {
		t.Fatal("missing SSO cookie")
	}

	login.State, err = randomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	query.Set("state", login.State)
	getURL := server.URL + "/login?" + query.Encode()
	get, _ := http.NewRequest(http.MethodGet, getURL, nil)
	get.AddCookie(&http.Cookie{Name: "__Host-auth_sso", Value: sso})
	response, err = client.Do(get)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusSeeOther || strings.Contains(response.Header.Get("Location"), "username") {
		t.Fatalf("SSO did not issue silently: %d %s", response.StatusCode, response.Header.Get("Location"))
	}
	silentCallback, _ := url.Parse(response.Header.Get("Location"))
	silentCode := silentCallback.Query().Get("code")
	response.Body.Close()
	if silentCode == "" {
		t.Fatal("SSO did not issue an authorization code")
	}
	denialState, _ := randomToken(32)
	denialChallenge, _ := randomToken(32)
	deniedQuery := url.Values{"callback": {login.Callback}, "site": {login.Site}, "state": {denialState}, "challenge": {denialChallenge}, "role": {"unassigned"}, "ttl": {"3600"}}
	deniedLogin, _ := http.NewRequest(http.MethodGet, server.URL+"/login?"+deniedQuery.Encode(), nil)
	deniedLogin.AddCookie(&http.Cookie{Name: "__Host-auth_sso", Value: sso})
	response, err = client.Do(deniedLogin)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusForbidden || response.Header.Get("Location") != "" {
		t.Fatalf("authenticated user without required role got %d and %q", response.StatusCode, response.Header.Get("Location"))
	}
	response.Body.Close()

	api := func(path string, body any, authorized bool) *http.Response {
		t.Helper()
		data, _ := json.Marshal(body)
		request, _ := http.NewRequest(http.MethodPost, server.URL+path, strings.NewReader(string(data)))
		request.Header.Set("Content-Type", "application/json")
		if authorized {
			request.Header.Set("Authorization", "Bearer "+strings.Repeat("k", 32))
		}
		result, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	unauthorized := api("/api/sites", map[string]string{"origin": "https://evil.example"}, false)
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("untrusted site registration status %d", unauthorized.StatusCode)
	}
	unauthorized.Body.Close()
	unauthorized = api("/api/health", nil, false)
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("untrusted health API status %d", unauthorized.StatusCode)
	}
	unauthorized.Body.Close()
	badSite := api("/api/sites", map[string]string{"origin": "https://*.example.com"}, true)
	if badSite.StatusCode != http.StatusBadRequest {
		t.Fatalf("wildcard origin registration status %d", badSite.StatusCode)
	}
	badSite.Body.Close()

	exchange := map[string]any{"code": silentCode, "verifier": verifier, "callback": login.Callback, "site": login.Site, "state": login.State, "role": login.Role, "ttl_seconds": login.TTL}
	response = api("/api/exchange", exchange, true)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("code exchange status %d", response.StatusCode)
	}
	var issued struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&issued); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	response = api("/api/exchange", exchange, true)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed code status %d", response.StatusCode)
	}
	response.Body.Close()
	response = api("/api/validate", map[string]any{"token": "opaque", "site": login.Site, "role": login.Role, "ttl_seconds": 3600}, false)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("untrusted validation status %d", response.StatusCode)
	}
	response.Body.Close()

	logoutPage, err := client.Get(server.URL + "/logout")
	if err != nil {
		t.Fatal(err)
	}
	logoutCSRF := findCookie(t, logoutPage.Cookies(), "__Host-auth_csrf")
	logoutPage.Body.Close()
	logoutForm := url.Values{"csrf": {logoutCSRF.Value}}
	logout, _ := http.NewRequest(http.MethodPost, server.URL+"/logout", strings.NewReader(logoutForm.Encode()))
	logout.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	logout.AddCookie(logoutCSRF)
	logout.AddCookie(&http.Cookie{Name: "__Host-auth_sso", Value: sso})
	response, err = client.Do(logout)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("signout status %d", response.StatusCode)
	}
	if cleared := findCookie(t, response.Cookies(), "__Host-auth_sso"); cleared.MaxAge >= 0 {
		t.Fatalf("SSO cookie was not cleared: %+v", cleared)
	}
	response.Body.Close()
	response = api("/api/validate", map[string]any{"token": issued.Token, "site": login.Site, "role": login.Role, "ttl_seconds": 3600}, true)
	var revoked Validation
	if err := json.NewDecoder(response.Body).Decode(&revoked); err != nil {
		t.Fatal(err)
	}
	if revoked.Outcome != "invalid" {
		t.Fatalf("signout retained grant: %+v", revoked)
	}
	response.Body.Close()
}

func readBody(t *testing.T, response *http.Response) string {
	t.Helper()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func findCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("cookie %q missing", name)
	return nil
}

func TestLoginRejectsUnregisteredAndAmbiguousCallbacks(t *testing.T) {
	store, _ := testStore(t)
	service, err := NewServer(store, strings.Repeat("k", 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, callback := range []string{"https://evil.example/_caddy_auth/callback", "https://app.example.com/%5f_caddy_auth/callback", "https://app.example.com@evil.example/_caddy_auth/callback", "https://app.example.com/_caddy_auth/callback?next=https://evil.example"} {
		request := loginRequest{Callback: callback, Site: "https://app.example.com", State: "state", Challenge: "challenge", Role: "accounting", TTL: int64(time.Hour.Seconds())}
		if valid, err := service.validCallback(request); err != nil || valid {
			t.Errorf("accepted callback %q", callback)
		}
	}
}

func TestLoginRateLimitUsesClientIPBehindLoopbackProxy(t *testing.T) {
	limiter := loginLimiter{counts: make(map[string]rateEntry)}
	request := httptest.NewRequest(http.MethodPost, "https://auth.example.com/login", nil)
	request.RemoteAddr = "127.0.0.1:51000"
	request.Header.Set("X-Forwarded-For", "203.0.113.9, 127.0.0.1")
	if got := clientIP(request); got != "203.0.113.9" {
		t.Fatalf("proxied client IP = %q", got)
	}
	request.RemoteAddr = "198.51.100.2:443"
	request.Header.Set("X-Forwarded-For", "192.0.2.7")
	if got := clientIP(request); got != "198.51.100.2" {
		t.Fatalf("untrusted forwarded IP = %q", got)
	}
	request.RemoteAddr = "127.0.0.1:51000"
	request.Header.Set("X-Forwarded-For", "203.0.113.9, 127.0.0.1")
	for attempt := 1; attempt <= 10; attempt++ {
		if !limiter.allow(clientIP(request)) {
			t.Fatalf("attempt %d was unexpectedly blocked", attempt)
		}
	}
	if limiter.allow(clientIP(request)) {
		t.Fatal("eleventh password attempt was allowed")
	}
	if !limiter.allow("203.0.113.10") {
		t.Fatal("limit for one client blocked another client")
	}
}

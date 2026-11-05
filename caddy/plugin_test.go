package caddy

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	"github.com/cfe84/caddy-auth/internal/authsvc"
)

func TestSignInCallbackSSOGrantRenewalAndUpstreamBoundary(t *testing.T) {
	store, err := authsvc.Open(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, role := range []string{"accounting", "other"} {
		if err := store.AddRole(role); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.AddCredential("alice", "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"accounting", "other"} {
		if err := store.AssignRole("alice", role); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.RegisterSite("https://app.example.com"); err != nil {
		t.Fatal(err)
	}
	service, err := authsvc.NewServer(store, strings.Repeat("k", 32))
	if err != nil {
		t.Fatal(err)
	}
	serviceServer := httptest.NewTLSServer(service.Handler())
	defer serviceServer.Close()
	client := serviceServer.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	attempts = attemptStore{entries: make(map[string]loginAttempt)}
	policy := &Auth{Service: serviceServer.URL, InstanceToken: strings.Repeat("k", 32), Role: "accounting", TTL: "1s"}
	if err := policy.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	policy.client = client
	request := httptest.NewRequest(http.MethodGet, "https://app.example.com/reports/quarter?period=Q4", nil)
	request.TLS = &tls.ConnectionState{}
	first := httptest.NewRecorder()
	if err := policy.ServeHTTP(first, request, nil); err != nil {
		t.Fatal(err)
	}
	if first.Code != http.StatusSeeOther {
		t.Fatalf("login start status %d", first.Code)
	}
	loginURL, err := url.Parse(first.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loginURL.Path != "/login" || loginURL.Query().Get("callback") != "https://app.example.com"+callbackPath {
		t.Fatalf("login location %s", loginURL)
	}
	stateCookie := cookieNamed(t, first.Result().Cookies(), flowCookieName(loginURL.Query().Get("state")))
	challenge := loginURL.Query().Get("challenge")
	loginBody, _ := json.Marshal(map[string]any{"callback": loginURL.Query().Get("callback"), "site": loginURL.Query().Get("site"), "state": loginURL.Query().Get("state"), "challenge": challenge, "role": "accounting", "ttl_seconds": 1})
	loginPage, err := client.Get(loginURL.String())
	if err != nil {
		t.Fatal(err)
	}
	if loginPage.StatusCode != http.StatusOK {
		t.Fatalf("login page status %d", loginPage.StatusCode)
	}
	csrf := cookieNamed(t, loginPage.Cookies(), "__Host-auth_csrf")
	loginPage.Body.Close()
	csrfValue := csrf.Value
	form := url.Values{"csrf": {csrfValue}, "request": {string(loginBody)}, "username": {"alice"}, "password": {"correct horse battery staple"}}
	post, _ := http.NewRequest(http.MethodPost, serviceServer.URL+"/login", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(&http.Cookie{Name: "__Host-auth_csrf", Value: csrfValue})
	loginResponse, err := client.Do(post)
	if err != nil {
		t.Fatal(err)
	}
	if loginResponse.StatusCode != http.StatusSeeOther {
		t.Fatalf("credential sign-in status %d", loginResponse.StatusCode)
	}
	ssoCookie := cookieNamed(t, loginResponse.Cookies(), "__Host-auth_sso")
	callbackURL, err := url.Parse(loginResponse.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	loginResponse.Body.Close()
	if callbackURL.Query().Get("state") != stateCookie.Value {
		t.Fatal("service changed login state")
	}

	callbackHandler := &Auth{Service: serviceServer.URL, InstanceToken: strings.Repeat("k", 32), Callback: true}
	if err := callbackHandler.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	callbackHandler.client = client
	callbackRequest := httptest.NewRequest(http.MethodGet, callbackURL.String(), nil)
	callbackRequest.Host = "app.example.com"
	callbackRequest.TLS = &tls.ConnectionState{}
	callbackRequest.AddCookie(stateCookie)
	wrongState := callbackRequest.Clone(callbackRequest.Context())
	wrongState.URL, _ = url.Parse(callbackURL.String())
	wrongQuery := wrongState.URL.Query()
	wrongQuery.Set("state", "wrong")
	wrongState.URL.RawQuery = wrongQuery.Encode()
	if err := callbackHandler.ServeHTTP(httptest.NewRecorder(), wrongState, nil); statusCode(t, err) != http.StatusBadRequest {
		t.Fatal("wrong state was accepted")
	}
	callbackRecorder := httptest.NewRecorder()
	if err := callbackHandler.ServeHTTP(callbackRecorder, callbackRequest, nil); err != nil {
		t.Fatal(err)
	}
	if callbackRecorder.Code != http.StatusSeeOther || callbackRecorder.Header().Get("Location") != "/reports/quarter?period=Q4" {
		t.Fatalf("callback redirect %d %q", callbackRecorder.Code, callbackRecorder.Header().Get("Location"))
	}
	if callbackRequest.URL.RawQuery != "" || callbackRequest.RequestURI != callbackPath || callbackRecorder.Header().Get("Cache-Control") != "no-store" || callbackRecorder.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("callback response did not suppress sensitive query context")
	}
	authorizationCookie := cookieNamed(t, callbackRecorder.Result().Cookies(), authorizationCookieName("https://app.example.com"))
	if !authorizationCookie.Secure || !authorizationCookie.HttpOnly || authorizationCookie.Path != "/" || authorizationCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("authorization cookie attributes: %+v", authorizationCookie)
	}
	if ssoCookie.Value == "" {
		t.Fatal("credential sign-in did not establish SSO")
	}
	replayRequest := httptest.NewRequest(http.MethodGet, callbackURL.String(), nil)
	replayRequest.Host = "app.example.com"
	replayRequest.TLS = &tls.ConnectionState{}
	replayRequest.AddCookie(stateCookie)
	if err := callbackHandler.ServeHTTP(httptest.NewRecorder(), replayRequest, nil); statusCode(t, err) != http.StatusBadRequest {
		t.Fatal("callback replay was accepted")
	}

	time.Sleep(1100 * time.Millisecond)
	var upstreamCookie string
	var upstreamAuthorization string
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		upstreamCookie = r.Header.Get("Cookie")
		upstreamAuthorization = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		return nil
	})
	protectedRequest := httptest.NewRequest(http.MethodPost, "https://app.example.com/reports/quarter?period=Q4", strings.NewReader("not replayed during login"))
	protectedRequest.TLS = &tls.ConnectionState{}
	protectedRequest.Header.Set("Cookie", authorizationCookie.Name+"="+authorizationCookie.Value+"; app_session=keep; __Host-caddy_auth_state=flow")
	protectedRequest.Header.Set("Authorization", "Bearer customer-token")
	protectedRecorder := httptest.NewRecorder()
	if err := policy.ServeHTTP(protectedRecorder, protectedRequest, next); err != nil {
		t.Fatal(err)
	}
	if protectedRecorder.Code != http.StatusOK || upstreamCookie != "app_session=keep" || upstreamAuthorization != "Bearer customer-token" {
		t.Fatalf("upstream status=%d cookie=%q authorization=%q", protectedRecorder.Code, upstreamCookie, upstreamAuthorization)
	}
	newAuthorization := cookieNamed(t, protectedRecorder.Result().Cookies(), authorizationCookieName("https://app.example.com"))
	if newAuthorization.Value == authorizationCookie.Value || newAuthorization.Value == "" {
		t.Fatal("expired grant did not silently renew")
	}
	if err := store.RemoveMembership("alice", "accounting"); err != nil {
		t.Fatal(err)
	}
	denied := httptest.NewRecorder()
	deniedRequest := httptest.NewRequest(http.MethodGet, "https://app.example.com/report", nil)
	deniedRequest.TLS = &tls.ConnectionState{}
	deniedRequest.AddCookie(newAuthorization)
	if err := policy.ServeHTTP(denied, deniedRequest, next); statusCode(t, err) != http.StatusForbidden {
		t.Fatal("role revocation did not deny access")
	}

	unavailable := &Auth{Service: "https://127.0.0.1:1", InstanceToken: strings.Repeat("k", 32), Role: "accounting", TTL: "1h"}
	if err := unavailable.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	downRequest := httptest.NewRequest(http.MethodGet, "https://app.example.com/", nil)
	downRequest.TLS = &tls.ConnectionState{}
	downRequest.AddCookie(newAuthorization)
	if err := unavailable.ServeHTTP(httptest.NewRecorder(), downRequest, next); statusCode(t, err) != http.StatusServiceUnavailable {
		t.Fatal("unavailable auth service did not fail closed")
	}
}

func TestLocalReturnURLRejectsEncodedOpenRedirects(t *testing.T) {
	for _, value := range []string{"//evil.example/path", "/%2f%2fevil.example", "/%5c%5cevil.example", "/%2e%2e/evil", "https://evil.example/path", "/\\evil.example"} {
		if _, err := validateReturnURL(value); err == nil {
			t.Errorf("accepted return URL %q", value)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "https://app.example.com/reports?q=a%20b", nil)
	got, err := localReturnURL(request.URL)
	if err != nil || got != "/reports?q=a%20b" {
		t.Fatalf("local return URL = %q, %v", got, err)
	}
}

func TestCaddyfileAdaptAddsIndependentCallbackRoutes(t *testing.T) {
	config := []byte(`{
		auth {
			service https://auth.example.com
			instance_token ` + strings.Repeat("k", 32) + `
		}
	}
	whole.example.com {
		require_auth {
			role accounting
			ttl 1h
		}
		reverse_proxy 127.0.0.1:9001
	}
	endpoint.example.com {
		@private path /secret/*
		require_auth @private {
			role accounting
			ttl 15m
		}
		reverse_proxy 127.0.0.1:9002
	}`)
	adapter := caddyconfig.GetAdapter("caddyfile")
	if adapter == nil {
		t.Fatal("Caddyfile adapter is not registered")
	}
	adapted, _, err := adapter.Adapt(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := bytes.Count(adapted, []byte(`"callback":true`)); got != 2 {
		t.Fatalf("automatic callback handlers = %d, JSON: %s", got, adapted)
	}
	if !bytes.Contains(adapted, []byte(`"path":["/_caddy_auth/callback"]`)) || !bytes.Contains(adapted, []byte(`"path":["/secret/*"]`)) {
		t.Fatalf("callback or endpoint matcher missing: %s", adapted)
	}
	if bytes.Index(adapted, []byte(`"callback":true`)) > bytes.Index(adapted, []byte(`"dial":"127.0.0.1:9001"`)) {
		t.Fatalf("whole-site callback is not ordered before its proxy: %s", adapted)
	}
}

func cookieNamed(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("cookie %q missing", name)
	return nil
}

func statusCode(t *testing.T, err error) int {
	t.Helper()
	var handlerErr caddyhttp.HandlerError
	if !errors.As(err, &handlerErr) {
		t.Fatalf("expected handler error, got %v", err)
	}
	return handlerErr.StatusCode
}

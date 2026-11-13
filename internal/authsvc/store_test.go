package authsvc

import (
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) (*Store, int64) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("database mode = %o, want 600", info.Mode().Perm())
	}
	t.Cleanup(func() { store.Close() })
	if err := store.AddCredential("alice", "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	if err := store.AddRole("accounting"); err != nil {
		t.Fatal(err)
	}
	if err := store.AssignRole("alice", "accounting"); err != nil {
		t.Fatal(err)
	}
	if err := store.RegisterSite("https://APP.example.com:443/"); err != nil {
		t.Fatal(err)
	}
	id, err := store.authenticate("alice", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	return store, id
}

func TestGrantPKCEExpiryRevocationAndPasswordChange(t *testing.T) {
	store, id := testStore(t)
	if err := store.AddRole("reports"); err != nil {
		t.Fatal(err)
	}
	if err := store.AssignRole("alice", "reports"); err != nil {
		t.Fatal(err)
	}
	session, _, err := store.CreateSession(id)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := randomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	challenge := sha256.Sum256([]byte(verifier))
	encodedChallenge := base64.RawURLEncoding.EncodeToString(challenge[:])
	callback := "https://app.example.com/_caddy_auth/callback"
	code, err := store.IssueCode(session, "https://app.example.com", callback, "state", "accounting", encodedChallenge)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ExchangeCode(code, "wrong", callback, "https://app.example.com", "state", "accounting", time.Hour); err == nil {
		t.Fatal("wrong PKCE verifier was accepted")
	}
	if _, _, err := store.ExchangeCode(code, verifier, callback, "https://app.example.com", "other-state", "accounting", time.Hour); err == nil {
		t.Fatal("authorization code was accepted for another login state")
	}
	token, _, err := store.ExchangeCode(code, verifier, callback, "https://app.example.com", "state", "accounting", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ExchangeCode(code, verifier, callback, "https://app.example.com", "state", "accounting", time.Hour); err == nil {
		t.Fatal("authorization code replay was accepted")
	}
	if outcome, err := store.Validate(token, "https://app.example.com", "accounting", time.Hour); err != nil || outcome.Outcome != "authorized" {
		t.Fatalf("validation = %+v, %v", outcome, err)
	}
	if outcome, err := store.Validate(token, "https://app.example.com", "reports", time.Hour); err != nil || outcome.Outcome != "authorized" {
		t.Fatalf("same site grant did not authorize another current role: %+v, %v", outcome, err)
	}
	if _, err := store.db.Exec("UPDATE grants SET created_at=? WHERE token=?", time.Now().Add(-2*time.Hour).Unix(), token); err != nil {
		t.Fatal(err)
	}
	renewed, err := store.Validate(token, "https://app.example.com", "accounting", time.Hour)
	if err != nil || renewed.Outcome != "renewal_required" || renewed.Token == "" {
		t.Fatalf("renewal = %+v, %v", renewed, err)
	}
	if old, err := store.Validate(token, "https://app.example.com", "accounting", time.Hour); err != nil || old.Outcome != "invalid" {
		t.Fatalf("old grant = %+v, %v", old, err)
	}
	if err := store.RemoveMembership("alice", "accounting"); err != nil {
		t.Fatal(err)
	}
	if denied, err := store.Validate(renewed.Token, "https://app.example.com", "accounting", time.Hour); err != nil || denied.Outcome != "forbidden" {
		t.Fatalf("revoked role = %+v, %v", denied, err)
	}
	if err := store.SetCredentialEnabled("alice", false); err != nil {
		t.Fatal(err)
	}
	if disabled, err := store.Validate(renewed.Token, "https://app.example.com", "reports", time.Hour); err != nil || disabled.Outcome != "invalid" {
		t.Fatalf("disabled credential = %+v, %v", disabled, err)
	}
	if err := store.SetCredentialEnabled("alice", true); err != nil {
		t.Fatal(err)
	}
	if err := store.SetPassword("alice", "new secret"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Session(session); err == nil {
		t.Fatal("password change retained the SSO session")
	}
	if _, err := store.authenticate("alice", "correct horse battery staple"); err == nil {
		t.Fatal("old password remained valid")
	}
}

func TestRegisterSiteRejectsAmbiguousOrigins(t *testing.T) {
	store, _ := testStore(t)
	for _, origin := range []string{"http://app.example.com", "https://app*.example.com", "https://*.*.example.com", "https://*.127.0.0.1", "https://app.example.com@evil.test", "https://app.example.com/%2f/evil", "https://app.example.com?next=evil"} {
		if err := store.RegisterSite(origin); err == nil {
			t.Errorf("accepted origin %q", origin)
		}
	}
	for _, pattern := range []string{"https://*.HOME.example.com:443/", "https://*.internal.example.com:8443"} {
		if err := store.RegisterSite(pattern); err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range []struct {
		origin  string
		allowed bool
	}{
		{"https://app.example.com", true},
		{"https://accounting.home.example.com", true},
		{"https://other.home.example.com", true},
		{"https://home.example.com", false},
		{"https://deep.accounting.home.example.com", false},
		{"https://accounting.home.example.com.evil.test", false},
		{"https://accounting.otherhome.example.com", false},
		{"https://accounting.home.example.com:8443", false},
		{"https://accounting.internal.example.com:8443", true},
		{"https://accounting.internal.example.com", false},
		{"https://*.home.example.com", false},
	} {
		t.Run(test.origin, func(t *testing.T) {
			allowed, err := store.siteAllowed(test.origin)
			if err != nil || allowed != test.allowed {
				t.Fatalf("site allowed = %t, %v; want %t", allowed, err, test.allowed)
			}
		})
	}
}

package authsvc

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/argon2"
)

const (
	ssolifetime  = 12 * time.Hour
	codeLifetime = time.Minute
)

var (
	errForbidden          = errors.New("forbidden")
	errCapacity           = errors.New("authorization capacity reached")
	errInvalidCredentials = errors.New("invalid credentials")
	errSessionExpired     = errors.New("session expired")
)

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite3", path+"?_foreign_keys=on&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db}
	if _, err := db.Exec(`PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS credentials (id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, salt BLOB NOT NULL, password_hash BLOB NOT NULL, enabled INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS roles (name TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS credential_roles (credential_id INTEGER NOT NULL REFERENCES credentials(id) ON DELETE CASCADE, role TEXT NOT NULL REFERENCES roles(name) ON DELETE CASCADE, PRIMARY KEY(credential_id, role));
CREATE TABLE IF NOT EXISTS sites (origin TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, credential_id INTEGER NOT NULL REFERENCES credentials(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL);
		CREATE TABLE IF NOT EXISTS codes (code TEXT PRIMARY KEY, session_token TEXT NOT NULL REFERENCES sessions(token) ON DELETE CASCADE, origin TEXT NOT NULL, callback TEXT NOT NULL, state TEXT NOT NULL, role TEXT NOT NULL, challenge TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS grants (token TEXT PRIMARY KEY, session_token TEXT NOT NULL REFERENCES sessions(token) ON DELETE CASCADE, origin TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS grants_session ON grants(session_token);
CREATE INDEX IF NOT EXISTS codes_expiry ON codes(expires_at);
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);`); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) AddCredential(name, password string) error {
	if name == "" || password == "" {
		return errors.New("name and password are required")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	hash := argon2.IDKey([]byte(password), salt, 2, 64*1024, 2, 32)
	_, err := s.db.Exec("INSERT INTO credentials(name,salt,password_hash) VALUES(?,?,?)", name, salt, hash)
	return err
}

func (s *Store) SetPassword(name, password string) error {
	if name == "" || password == "" {
		return errors.New("name and password are required")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	hash := argon2.IDKey([]byte(password), salt, 2, 64*1024, 2, 32)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec("UPDATE credentials SET salt=?, password_hash=? WHERE name=?", salt, hash, name)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed == 0 {
		return errors.New("credential not found")
	}
	if _, err := tx.Exec("DELETE FROM sessions WHERE credential_id=(SELECT id FROM credentials WHERE name=?)", name); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) SetCredentialEnabled(name string, enabled bool) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec("UPDATE credentials SET enabled=? WHERE name=?", enabled, name)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed == 0 {
		return errors.New("credential not found")
	}
	if !enabled {
		if _, err = tx.Exec("DELETE FROM sessions WHERE credential_id=(SELECT id FROM credentials WHERE name=?)", name); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) AddRole(role string) error {
	if role == "" {
		return errors.New("role is required")
	}
	_, err := s.db.Exec("INSERT INTO roles(name) VALUES(?)", role)
	return err
}

func (s *Store) RemoveRole(role string) error {
	result, err := s.db.Exec("DELETE FROM roles WHERE name=?", role)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed == 0 {
		return errors.New("role not found")
	}
	return nil
}

func (s *Store) AssignRole(name, role string) error {
	result, err := s.db.Exec(`INSERT INTO credential_roles(credential_id,role)
SELECT id,? FROM credentials WHERE name=?`, role, name)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed == 0 {
		return errors.New("credential or role not found")
	}
	return nil
}

func (s *Store) RemoveMembership(name, role string) error {
	result, err := s.db.Exec(`DELETE FROM credential_roles WHERE role=? AND credential_id=(SELECT id FROM credentials WHERE name=?)`, role, name)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed == 0 {
		return errors.New("membership not found")
	}
	return nil
}

func (s *Store) RegisterSite(origin string) error {
	canonical, err := canonicalOrigin(origin)
	if err != nil {
		return err
	}
	return s.registerCanonicalSite(canonical)
}

func (s *Store) registerCanonicalSite(canonical string) error {
	_, err := s.db.Exec("INSERT INTO sites(origin) VALUES(?) ON CONFLICT DO NOTHING", canonical)
	return err
}

func canonicalOrigin(origin string) (string, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || strings.Contains(u.Host, "%") {
		return "", errors.New("origin must be an explicit HTTPS origin")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.Contains(host, "*") || strings.Contains(host, "\\") {
		return "", errors.New("origin host must be explicit")
	}
	if net.ParseIP(host) == nil {
		for _, char := range host {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' || char == '.') {
				return "", errors.New("origin host must use an ASCII DNS name")
			}
		}
		for _, label := range strings.Split(host, ".") {
			if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", errors.New("invalid origin host")
			}
		}
	}
	port := u.Port()
	if port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return "", errors.New("invalid origin port")
		}
		if port == "443" {
			port = ""
		}
	}
	if net.ParseIP(host) != nil {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return "https://" + host, nil
}

func (s *Store) authenticate(name, password string) (int64, error) {
	var id int64
	var salt, expected []byte
	var enabled bool
	err := s.db.QueryRow("SELECT id,salt,password_hash,enabled FROM credentials WHERE name=?", name).Scan(&id, &salt, &expected, &enabled)
	if errors.Is(err, sql.ErrNoRows) {
		salt = []byte("caddy-auth-dummy")
		expected = make([]byte, 32)
	} else if err != nil {
		return 0, err
	}
	actual := argon2.IDKey([]byte(password), salt, 2, 64*1024, 2, uint32(len(expected)))
	if errors.Is(err, sql.ErrNoRows) || !enabled || !equal(actual, expected) {
		return 0, errInvalidCredentials
	}
	return id, nil
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func (s *Store) CreateSession(credentialID int64) (string, time.Time, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return "", time.Time{}, err
	}
	defer tx.Rollback()
	var count int
	if err := tx.QueryRow("SELECT count(*) FROM sessions").Scan(&count); err != nil {
		return "", time.Time{}, err
	}
	if count >= 100000 {
		return "", time.Time{}, errCapacity
	}
	token, err := randomToken(32)
	if err != nil {
		return "", time.Time{}, err
	}
	expires := time.Now().Add(ssolifetime)
	if _, err = tx.Exec("INSERT INTO sessions(token,credential_id,expires_at) VALUES(?,?,?)", token, credentialID, expires.Unix()); err != nil {
		return "", time.Time{}, err
	}
	return token, expires, tx.Commit()
}

func (s *Store) Session(token string) (int64, time.Time, error) {
	var id, expires int64
	err := s.db.QueryRow("SELECT credential_id,expires_at FROM sessions WHERE token=?", token).Scan(&id, &expires)
	if err != nil {
		return 0, time.Time{}, err
	}
	if time.Now().Unix() >= expires {
		if _, err := s.db.Exec("DELETE FROM sessions WHERE token=?", token); err != nil {
			return 0, time.Time{}, err
		}
		return 0, time.Time{}, errSessionExpired
	}
	return id, time.Unix(expires, 0), nil
}

func (s *Store) HasRole(credentialID int64, role string) (bool, error) {
	var found int
	err := s.db.QueryRow(`SELECT count(*) FROM credentials c JOIN credential_roles cr ON c.id=cr.credential_id
WHERE c.id=? AND c.enabled=1 AND cr.role=?`, credentialID, role).Scan(&found)
	return found == 1, err
}

func (s *Store) IssueCode(session, origin, callback, state, role, challenge string) (string, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var registered int
	if err := tx.QueryRow("SELECT count(*) FROM sites WHERE origin=?", origin).Scan(&registered); err != nil {
		return "", err
	}
	if registered != 1 {
		return "", errors.New("unregistered site origin")
	}
	if len(callback) > 2048 || state == "" || role == "" || challenge == "" {
		return "", errors.New("invalid login request")
	}
	var count int
	if err := tx.QueryRow("SELECT count(*) FROM codes").Scan(&count); err != nil {
		return "", err
	}
	if count >= 100000 {
		return "", errCapacity
	}
	code, err := randomToken(32)
	if err != nil {
		return "", err
	}
	if _, err = tx.Exec("INSERT INTO codes(code,session_token,origin,callback,state,role,challenge,expires_at) VALUES(?,?,?,?,?,?,?,?)", code, session, origin, callback, state, role, challenge, time.Now().Add(codeLifetime).Unix()); err != nil {
		return "", err
	}
	return code, tx.Commit()
}

func (s *Store) ExchangeCode(code, verifier, callback, site, state, role string, ttl time.Duration) (string, time.Time, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return "", time.Time{}, err
	}
	defer tx.Rollback()
	var session, origin, expectedCallback, expectedState, expectedRole, challenge string
	var expires int64
	err = tx.QueryRow("SELECT session_token,origin,callback,state,role,challenge,expires_at FROM codes WHERE code=?", code).Scan(&session, &origin, &expectedCallback, &expectedState, &expectedRole, &challenge, &expires)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", time.Time{}, err
	}
	if errors.Is(err, sql.ErrNoRows) || time.Now().Unix() >= expires || expectedCallback != callback || origin != site || expectedState != state || expectedRole != role || ttl < time.Second || ttl > 24*time.Hour {
		return "", time.Time{}, errors.New("invalid authorization code")
	}
	sum := sha256Base64(verifier)
	if !equal([]byte(sum), []byte(challenge)) {
		return "", time.Time{}, errors.New("invalid PKCE verifier")
	}
	var id, ssoExpiry int64
	err = tx.QueryRow("SELECT c.id,s.expires_at FROM sessions s JOIN credentials c ON c.id=s.credential_id WHERE s.token=? AND c.enabled=1", session).Scan(&id, &ssoExpiry)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", time.Time{}, err
	}
	if errors.Is(err, sql.ErrNoRows) || time.Now().Unix() >= ssoExpiry {
		return "", time.Time{}, errors.New("invalid session")
	}
	var roleCount int
	if err := tx.QueryRow("SELECT count(*) FROM credential_roles WHERE credential_id=? AND role=?", id, role).Scan(&roleCount); err != nil {
		return "", time.Time{}, err
	}
	if roleCount == 0 {
		return "", time.Time{}, errForbidden
	}
	var grantCount int
	if err := tx.QueryRow("SELECT count(*) FROM grants").Scan(&grantCount); err != nil {
		return "", time.Time{}, err
	}
	if grantCount >= 1000000 {
		return "", time.Time{}, errCapacity
	}
	if _, err := tx.Exec("DELETE FROM codes WHERE code=?", code); err != nil {
		return "", time.Time{}, err
	}
	token, err := randomToken(32)
	if err != nil {
		return "", time.Time{}, err
	}
	_, err = tx.Exec("INSERT INTO grants(token,session_token,origin,created_at) VALUES(?,?,?,?)", token, session, origin, time.Now().Unix())
	if err == nil {
		err = tx.Commit()
	}
	return token, time.Unix(ssoExpiry, 0), err
}

type Validation struct {
	Outcome string `json:"outcome"`
	Token   string `json:"token,omitempty"`
}

func (s *Store) Validate(token, site, role string, ttl time.Duration) (Validation, error) {
	var session, origin string
	var created int64
	err := s.db.QueryRow(`SELECT g.session_token,g.origin,g.created_at FROM grants g WHERE g.token=?`, token).Scan(&session, &origin, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return Validation{Outcome: "invalid"}, nil
	} else if err != nil {
		return Validation{}, err
	}
	var credentialID int64
	credentialID, _, err = s.Session(session)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, errSessionExpired) {
			return Validation{Outcome: "invalid"}, nil
		}
		return Validation{}, err
	}
	hasRequiredRole, err := s.HasRole(credentialID, role)
	if err != nil {
		return Validation{}, err
	}
	if origin != site || !hasRequiredRole {
		return Validation{Outcome: "forbidden"}, nil
	}
	if ttl < time.Second || ttl > 24*time.Hour {
		return Validation{}, errors.New("invalid ttl")
	}
	if time.Now().Unix()-created >= int64(ttl.Seconds()) {
		newToken, err := randomToken(32)
		if err != nil {
			return Validation{}, err
		}
		tx, err := s.db.Begin()
		if err != nil {
			return Validation{}, err
		}
		defer tx.Rollback()
		var grantCount int
		if err := tx.QueryRow("SELECT count(*) FROM grants").Scan(&grantCount); err != nil {
			return Validation{}, err
		}
		if grantCount >= 1000000 {
			return Validation{}, errCapacity
		}
		if _, err = tx.Exec("INSERT INTO grants(token,session_token,origin,created_at) VALUES(?,?,?,?)", newToken, session, origin, time.Now().Unix()); err != nil {
			return Validation{}, err
		}
		if _, err = tx.Exec("DELETE FROM grants WHERE token=?", token); err != nil {
			return Validation{}, err
		}
		if err := tx.Commit(); err != nil {
			return Validation{}, err
		}
		return Validation{Outcome: "renewal_required", Token: newToken}, nil
	}
	return Validation{Outcome: "authorized"}, nil
}

func (s *Store) RevokeSession(token string) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE token=?", token)
	return err
}

func (s *Store) Cleanup() error {
	now := time.Now().Unix()
	if _, err := s.db.Exec("DELETE FROM codes WHERE expires_at<?", now); err != nil {
		return err
	}
	_, err := s.db.Exec("DELETE FROM sessions WHERE expires_at<?", now)
	return err
}

func randomToken(size int) (string, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func sha256Base64(value string) string {
	return base64.RawURLEncoding.EncodeToString(sha256Sum([]byte(value)))
}

func sha256Sum(data []byte) []byte {
	digest := sha256.Sum256(data)
	return digest[:]
}

package web

import (
	"context"
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/harness-demo/vault/internal/store"
	_ "modernc.org/sqlite"
)

// shareURLRe extracts the /share/{token} URL from the generate fragment. The token is a
// URL-safe base64 string (crypto.RandomToken uses base64.RawURLEncoding: [A-Za-z0-9_-]).
var shareURLRe = regexp.MustCompile(`/share/([A-Za-z0-9_-]+)`)

// newShareTestServer is newTestServer but hands back the underlying store so tests can
// inspect the persisted share row directly (the store is encryption-agnostic).
func newShareTestServer(t *testing.T) (*httptest.Server, *http.Client, *store.Store, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "vault.db")
	st, err := store.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	ts := httptest.NewServer(New(st, WithStrictCookie(true)))
	t.Cleanup(ts.Close)

	jar, _ := cookiejar.New(nil)
	return ts, &http.Client{Jar: jar}, st, dbPath
}

// openDB opens the vault's SQLite file directly for read-only inspection of persisted
// rows (the store is encryption-agnostic; the test asserts what landed on disk).
func openDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// setupWithSecret sets up the vault (which logs in) and creates one secret, returning its
// path id (the first secret is id 1) and its plaintext value.
func setupWithSecret(t *testing.T, ts *httptest.Server, c *http.Client) (id string, value string) {
	t.Helper()
	postForm(t, c, ts.URL+"/setup", url.Values{"password": {"masterpw12"}})
	value = "s3cr3t-value"
	code, _ := postForm(t, c, ts.URL+"/secrets", url.Values{
		"name": {"prod-db"}, "tag": {"database"}, "value": {value},
	})
	if code != http.StatusOK {
		t.Fatalf("create secret code=%d", code)
	}
	return "1", value
}

// TestShareCreateReturnsShareURL encodes specs/share-links.md "Behavior → Generate": the
// generate control "returns an htmx fragment showing the full share URL (/share/{token})
// with a copy-to-clipboard button", and "Token": the URL is /share/{token} with a
// URL-safe base64 32-byte token.
func TestShareCreateReturnsShareURL(t *testing.T) {
	ts, c, _, _ := newShareTestServer(t)
	id, _ := setupWithSecret(t, ts, c)

	code, body := postForm(t, c, ts.URL+"/secrets/"+id+"/share", url.Values{})
	if code != http.StatusOK {
		t.Fatalf("share create code=%d body=%s", code, body)
	}

	m := shareURLRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no /share/{token} URL in fragment:\n%s", body)
	}
	token := m[1]
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("token %q is not URL-safe base64: %v", token, err)
	}
	if len(raw) != 32 {
		t.Fatalf("token decodes to %d bytes, want 32", len(raw))
	}
	// The fragment must offer a copy-to-clipboard control.
	if !strings.Contains(strings.ToLower(body), "copy") {
		t.Fatalf("fragment has no copy-to-clipboard control:\n%s", body)
	}
}

// TestShareCreatePersistsHashAndSealedBlobNotPlaintext encodes specs/share-links.md
// "Token" ("The database stores only SHA-256(token)") and "Model" ("No column ever holds
// the plaintext secret value or the raw token"), plus "Why a public endpoint can decrypt
// anything at all" (the plaintext is re-sealed, so the stored ciphertext is not plaintext).
func TestShareCreatePersistsHashAndSealedBlobNotPlaintext(t *testing.T) {
	ts, c, _, dbPath := newShareTestServer(t)
	id, value := setupWithSecret(t, ts, c)

	code, body := postForm(t, c, ts.URL+"/secrets/"+id+"/share", url.Values{})
	if code != http.StatusOK {
		t.Fatalf("share create code=%d body=%s", code, body)
	}
	token := shareURLRe.FindStringSubmatch(body)[1]

	// Read the raw share row straight out of SQLite (the store is encryption-agnostic;
	// we go around the API to assert what actually landed on disk).
	db := openDB(t, dbPath)
	var tokenHash, salt, ciphertext []byte
	var name string
	err := db.QueryRowContext(context.Background(),
		`SELECT token_hash, salt, ciphertext, name FROM shares`).
		Scan(&tokenHash, &salt, &ciphertext, &name)
	if err != nil {
		t.Fatalf("read share row: %v", err)
	}

	// token_hash is SHA-256(token), never the raw token.
	want := sha256.Sum256([]byte(token))
	if !bytes.Equal(tokenHash, want[:]) {
		t.Fatalf("token_hash is not SHA-256(token)")
	}
	if strings.Contains(string(tokenHash), token) {
		t.Fatalf("raw token stored in token_hash")
	}
	// The re-sealed ciphertext must not be (or contain) the plaintext value.
	if strings.Contains(string(ciphertext), value) {
		t.Fatalf("plaintext value leaked into ciphertext column")
	}
	// The name snapshot is the secret's name.
	if name != "prod-db" {
		t.Fatalf("name snapshot = %q, want prod-db", name)
	}
	if len(salt) == 0 {
		t.Fatalf("salt column empty")
	}
}

// TestShareCreateWritesAuditEntry encodes specs/share-links.md "Audit": "share-create — a
// share link was generated (target = secret name)."
func TestShareCreateWritesAuditEntry(t *testing.T) {
	ts, c, st, _ := newShareTestServer(t)
	id, _ := setupWithSecret(t, ts, c)

	code, _ := postForm(t, c, ts.URL+"/secrets/"+id+"/share", url.Values{})
	if code != http.StatusOK {
		t.Fatalf("share create code=%d", code)
	}

	entries, err := st.RecentAudit(context.Background(), 50)
	if err != nil {
		t.Fatalf("recent audit: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Action == "share-create" {
			if e.Target != "prod-db" {
				t.Fatalf("share-create target = %q, want prod-db", e.Target)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("no share-create audit entry written: %+v", entries)
	}
}

// TestShareCreateRequiresAuth encodes specs/share-links.md "Behavior → Generate": "This
// endpoint requires the existing session auth like the rest of the secret routes." — an
// unauthenticated request is redirected to /login, not served.
func TestShareCreateRequiresAuth(t *testing.T) {
	ts, c, _, _ := newShareTestServer(t)
	setupWithSecret(t, ts, c)

	// A bare client with no session cookie must be bounced to /login (303), like the
	// other /secrets/* routes.
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := noFollow.PostForm(ts.URL+"/secrets/1/share", url.Values{})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Fatalf("want 303 -> /login, got %d -> %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

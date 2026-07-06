package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// mintShare sets up the vault, creates one secret, generates a one-time share link, and
// returns the raw token from the /share/{token} URL plus the secret's plaintext value.
// Generation goes through the authenticated handler (the sibling "generate" slice), so
// these reveal tests exercise the real end-to-end snapshot, not a hand-built row.
func mintShare(t *testing.T, ts *httptest.Server, c *http.Client) (token, secretName, value string) {
	t.Helper()
	id, val := setupWithSecret(t, ts, c)
	code, body := postForm(t, c, ts.URL+"/secrets/"+id+"/share", url.Values{})
	if code != http.StatusOK {
		t.Fatalf("share create code=%d body=%s", code, body)
	}
	m := shareURLRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no /share/{token} URL in generate fragment:\n%s", body)
	}
	return m[1], "prod-db", val
}

// getNoCookie performs GET url with a fresh client that carries NO session cookie and does
// not follow redirects, returning the status code and body. It proves the reveal route is
// reachable publicly (specs/share-links.md "Reveal": reachable with no session cookie).
func getNoCookie(t *testing.T, url string) (int, string) {
	t.Helper()
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	code, body := get(t, c, url)
	return code, body
}

// TestShareRevealPublicNoSessionSucceeds encodes specs/share-links.md "Behavior → Reveal":
// "GET /share/{token} — a public route, reachable with no session cookie, and therefore
// not wrapped by the session auth middleware", and step 5 (render the secret name and its
// plaintext value). A sessionless GET of a valid token returns 200 with the name+value.
func TestShareRevealPublicNoSessionSucceeds(t *testing.T) {
	ts, c, _, _ := newShareTestServer(t)
	token, name, value := mintShare(t, ts, c)

	// A brand-new client with no session cookie must reach the value.
	code, body := getNoCookie(t, ts.URL+"/share/"+token)
	if code != http.StatusOK {
		t.Fatalf("reveal code=%d, want 200; body=%s", code, body)
	}
	if !strings.Contains(body, value) {
		t.Fatalf("reveal did not show the plaintext value %q:\n%s", value, body)
	}
	if !strings.Contains(body, name) {
		t.Fatalf("reveal did not show the secret name %q:\n%s", name, body)
	}
}

// TestShareRevealStatesLinkDestroyed encodes specs/share-links.md "Behavior → Reveal"
// step 5: the page states "plainly that the link has now been destroyed and cannot be
// used again."
func TestShareRevealStatesLinkDestroyed(t *testing.T) {
	ts, c, _, _ := newShareTestServer(t)
	token, _, _ := mintShare(t, ts, c)

	code, body := getNoCookie(t, ts.URL+"/share/"+token)
	if code != http.StatusOK {
		t.Fatalf("reveal code=%d, want 200; body=%s", code, body)
	}
	low := strings.ToLower(body)
	if !strings.Contains(low, "destroy") {
		t.Fatalf("reveal page does not state the link is destroyed:\n%s", body)
	}
}

// TestShareRevealSingleUse encodes specs/share-links.md "Behavior → Reveal" steps 2–3 and
// the closing paragraph: the row is deleted in the same transaction that read it, so "a
// second request for the same token ... finds no row and gets the identical 404". The
// first GET succeeds; a second GET for the same token is 404.
func TestShareRevealSingleUse(t *testing.T) {
	ts, c, _, _ := newShareTestServer(t)
	token, _, value := mintShare(t, ts, c)

	code, body := getNoCookie(t, ts.URL+"/share/"+token)
	if code != http.StatusOK {
		t.Fatalf("first reveal code=%d, want 200; body=%s", code, body)
	}

	code2, body2 := getNoCookie(t, ts.URL+"/share/"+token)
	if code2 != http.StatusNotFound {
		t.Fatalf("second reveal code=%d, want 404 (single-use); body=%s", code2, body2)
	}
	if strings.Contains(body2, value) {
		t.Fatalf("second reveal leaked the plaintext value:\n%s", body2)
	}
}

// TestShareRevealConcurrentExactlyOneWins encodes specs/share-links.md "Behavior →
// Reveal" closing paragraph: "exactly one concurrent request can win the row" because the
// delete happens in the same transaction as the read. Many concurrent GETs of one token
// yield exactly one 200 and the rest 404.
func TestShareRevealConcurrentExactlyOneWins(t *testing.T) {
	ts, c, _, _ := newShareTestServer(t)
	token, _, _ := mintShare(t, ts, c)

	const n = 8
	var wg sync.WaitGroup
	codes := make([]int, n)
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			codes[i], _ = getNoCookie(t, ts.URL+"/share/"+token)
		}(i)
	}
	close(start)
	wg.Wait()

	ok, notFound := 0, 0
	for _, code := range codes {
		switch code {
		case http.StatusOK:
			ok++
		case http.StatusNotFound:
			notFound++
		default:
			t.Fatalf("unexpected status %d among concurrent revealers", code)
		}
	}
	if ok != 1 {
		t.Fatalf("want exactly one concurrent revealer to win (200), got %d wins / %d 404s", ok, notFound)
	}
	if notFound != n-1 {
		t.Fatalf("want %d losers to 404, got %d (wins=%d)", n-1, notFound, ok)
	}
}

// TestShareRevealExpired404NeverDecrypts encodes specs/share-links.md "Behavior → Reveal"
// step 2: "or the row's expires_at has passed, responds 404 Not Found with no secret
// content ... Expiry must 404 and never decrypt." We age the row's expires_at into the
// past directly in SQLite (the store is encryption-agnostic; the fixed 1h expiry can't be
// reached through the generate handler), then a public GET must 404 without the value.
func TestShareRevealExpired404NeverDecrypts(t *testing.T) {
	ts, c, _, dbPath := newShareTestServer(t)
	token, _, value := mintShare(t, ts, c)

	// Force the share to be already expired.
	db := openDB(t, dbPath)
	if _, err := db.ExecContext(context.Background(),
		`UPDATE shares SET expires_at = ?`, time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatalf("expire share: %v", err)
	}

	code, body := getNoCookie(t, ts.URL+"/share/"+token)
	if code != http.StatusNotFound {
		t.Fatalf("expired reveal code=%d, want 404; body=%s", code, body)
	}
	if strings.Contains(body, value) {
		t.Fatalf("expired reveal leaked the plaintext value (must never decrypt):\n%s", body)
	}
}

// TestShareRevealExpiredRowDeleted encodes specs/share-links.md "Behavior → Reveal" step
// 2: "An expired row found this way is deleted before responding." After a GET of an
// expired token, no share row remains in the database.
func TestShareRevealExpiredRowDeleted(t *testing.T) {
	ts, c, _, dbPath := newShareTestServer(t)
	token, _, _ := mintShare(t, ts, c)

	db := openDB(t, dbPath)
	if _, err := db.ExecContext(context.Background(),
		`UPDATE shares SET expires_at = ?`, time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatalf("expire share: %v", err)
	}

	if code, body := getNoCookie(t, ts.URL+"/share/"+token); code != http.StatusNotFound {
		t.Fatalf("expired reveal code=%d, want 404; body=%s", code, body)
	}

	var count int
	if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM shares`).Scan(&count); err != nil {
		t.Fatalf("count shares: %v", err)
	}
	if count != 0 {
		t.Fatalf("expired share row was not deleted before responding: %d row(s) remain", count)
	}
}

// TestShareRevealWrongUsedExpiredIndistinguishable encodes specs/share-links.md "Behavior
// → Reveal" closing paragraph: "Wrong, already-used, and expired tokens are
// indistinguishable to the caller: all three produce the same 404 with no content." The
// status and body must be byte-identical across the three cases.
func TestShareRevealWrongUsedExpiredIndistinguishable(t *testing.T) {
	ts, c, _, dbPath := newShareTestServer(t)

	// Wrong: a syntactically valid but never-issued token.
	wrongCode, wrongBody := getNoCookie(t, ts.URL+"/share/"+strings.Repeat("A", 43))

	// Used: mint, reveal once (200), then reveal again (should 404).
	usedToken, _, _ := mintShare(t, ts, c)
	if code, _ := getNoCookie(t, ts.URL+"/share/"+usedToken); code != http.StatusOK {
		t.Fatalf("priming reveal did not succeed: %d", code)
	}
	usedCode, usedBody := getNoCookie(t, ts.URL+"/share/"+usedToken)

	// Expired: mint a second share, age it, then reveal.
	expToken, _, _ := mintShare(t, ts, c)
	db := openDB(t, dbPath)
	if _, err := db.ExecContext(context.Background(),
		`UPDATE shares SET expires_at = ?`, time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatalf("expire share: %v", err)
	}
	expCode, expBody := getNoCookie(t, ts.URL+"/share/"+expToken)

	if wrongCode != http.StatusNotFound || usedCode != http.StatusNotFound || expCode != http.StatusNotFound {
		t.Fatalf("all three must be 404: wrong=%d used=%d expired=%d", wrongCode, usedCode, expCode)
	}
	if wrongBody != usedBody || wrongBody != expBody {
		t.Fatalf("404 bodies differ (must be indistinguishable):\nwrong=%q\nused=%q\nexpired=%q",
			wrongBody, usedBody, expBody)
	}
}

// TestShareRevealWritesAuditEntry encodes specs/share-links.md "Behavior → Reveal" step 4
// and "Audit": "share-reveal — a share link was revealed and burned (target = secret
// name)." A successful reveal writes a share-reveal audit entry with target = the share's
// stored secret name.
func TestShareRevealWritesAuditEntry(t *testing.T) {
	ts, c, st, _ := newShareTestServer(t)
	token, name, _ := mintShare(t, ts, c)

	if code, body := getNoCookie(t, ts.URL+"/share/"+token); code != http.StatusOK {
		t.Fatalf("reveal code=%d, want 200; body=%s", code, body)
	}

	entries, err := st.RecentAudit(context.Background(), 50)
	if err != nil {
		t.Fatalf("recent audit: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Action == "share-reveal" {
			if e.Target != name {
				t.Fatalf("share-reveal target = %q, want %q", e.Target, name)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("no share-reveal audit entry written: %+v", entries)
	}
}

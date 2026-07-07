package web

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// These tests exercise the two share-link HTTP seams end-to-end with httptest:
// POST /secrets/{id}/share (authenticated generate) and GET /share/{token} (public
// reveal-and-burn). They pin the HTTP contract from specs/share-links.md — status codes,
// the exposed token shape, single-use semantics, and the audit trail.

// shareURLRe extracts the /share/{token} URL from the generate fragment.
var shareURLRe = regexp.MustCompile(`/share/([A-Za-z0-9_-]+)`)

// setupWithSecret sets up a vault, creates one secret with the given value, and returns
// the authenticated client, the base URL, and the secret id (always 1 for the first).
func setupWithSecret(t *testing.T, value string) (base string, c *http.Client) {
	t.Helper()
	ts, c := newTestServer(t)
	postForm(t, c, ts.URL+"/setup", url.Values{"password": {"masterpw12"}})
	code, _ := postForm(t, c, ts.URL+"/secrets", url.Values{
		"name": {"prod-db"}, "tag": {"database"}, "value": {value},
	})
	if code != http.StatusOK {
		t.Fatalf("create secret code=%d", code)
	}
	return ts.URL, c
}

// generateShare posts to the share endpoint and returns the response body containing the
// share URL fragment. Fails the test if the status is not 200.
func generateShare(t *testing.T, base string, c *http.Client, id string) string {
	t.Helper()
	code, body := postForm(t, c, base+"/secrets/"+id+"/share", url.Values{})
	if code != http.StatusOK {
		t.Fatalf("generate share code=%d body=%s", code, body)
	}
	return body
}

func extractShareURL(t *testing.T, body string) string {
	t.Helper()
	m := shareURLRe.FindString(body)
	if m == "" {
		t.Fatalf("no /share/{token} URL in fragment:\n%s", body)
	}
	return m
}

// share-links.md "Generating a share (authenticated)": calling POST /secrets/{id}/share
// through the existing auth middleware — the caller must hold a valid session.
func TestGenerateShareRequiresSession(t *testing.T) {
	ts, _ := newTestServer(t)
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

// share-links.md "Generating a share": It generates a token: 32 bytes from crypto/rand,
// URL-safe base64 ... the full share URL /share/{token} ... is the only place the raw
// token is ever exposed.
func TestGenerateShareReturnsURLWith32ByteToken(t *testing.T) {
	base, c := setupWithSecret(t, "hunter2")
	body := generateShare(t, base, c, "1")

	m := shareURLRe.FindStringSubmatch(extractShareURL(t, body))
	token := m[1]
	// 32 raw bytes in URL-safe base64 (no padding) is 43 characters.
	if len(token) != 43 {
		t.Fatalf("token length = %d (%q), want 43 chars for 32 URL-safe-base64 bytes", len(token), token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("token %q is not URL-safe base64: %v", token, err)
	}
	if len(raw) != 32 {
		t.Fatalf("decoded token = %d bytes, want 32", len(raw))
	}
}

// share-links.md "Generating a share": It records a share-create audit entry.
func TestGenerateShareWritesAuditEntry(t *testing.T) {
	base, c := setupWithSecret(t, "hunter2")
	generateShare(t, base, c, "1")

	_, vault := get(t, c, base+"/vault")
	if !strings.Contains(vault, "share-create") {
		t.Fatalf("expected share-create audit entry on vault page:\n%s", vault)
	}
}

// share-links.md "Revealing a share (public, no session)": this route is exempt from the
// auth middleware — reachable with no session cookie at all ... shows the secret's name
// and decrypted value ... records a share-reveal audit entry.
func TestRevealShareReturnsPlaintextWithoutSession(t *testing.T) {
	base, c := setupWithSecret(t, "hunter2")
	shareURL := extractShareURL(t, generateShare(t, base, c, "1"))

	// A brand-new client with NO cookie jar — no session at all.
	public := &http.Client{}
	resp, err := public.Get(base + shareURL)
	if err != nil {
		t.Fatalf("public get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("public reveal code=%d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "hunter2") {
		t.Fatalf("public reveal missing plaintext value:\n%s", body)
	}
	if !strings.Contains(string(body), "prod-db") {
		t.Fatalf("public reveal missing secret name:\n%s", body)
	}

	// The reveal must have written a share-reveal audit entry (visible to the owner).
	_, vault := get(t, c, base+"/vault")
	if !strings.Contains(vault, "share-reveal") {
		t.Fatalf("expected share-reveal audit entry on vault page:\n%s", vault)
	}
}

// share-links.md "Revealing a share": the row was already consumed ... returns 404 with
// no secret content. All three cases are indistinguishable.
func TestRevealShareSecondTimeIs404NoContent(t *testing.T) {
	base, c := setupWithSecret(t, "hunter2")
	shareURL := extractShareURL(t, generateShare(t, base, c, "1"))

	public := &http.Client{}
	// First reveal consumes the link.
	first, err := public.Get(base + shareURL)
	if err != nil {
		t.Fatalf("first get: %v", err)
	}
	first.Body.Close()
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first reveal code=%d", first.StatusCode)
	}

	// Second reveal must be 404 with no secret content.
	second, err := public.Get(base + shareURL)
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	body, _ := io.ReadAll(second.Body)
	second.Body.Close()
	if second.StatusCode != http.StatusNotFound {
		t.Fatalf("second reveal code=%d, want 404", second.StatusCode)
	}
	if strings.Contains(string(body), "hunter2") {
		t.Fatalf("consumed share leaked plaintext on second reveal:\n%s", body)
	}
}

// share-links.md "Revealing a share": if no row matches ... All three cases are
// indistinguishable to the caller — same status, same body shape.
func TestRevealShareUnknownAndConsumedIndistinguishable(t *testing.T) {
	base, c := setupWithSecret(t, "hunter2")
	shareURL := extractShareURL(t, generateShare(t, base, c, "1"))

	public := &http.Client{}
	// Consume the real link.
	r1, err := public.Get(base + shareURL)
	if err != nil {
		t.Fatalf("consume get: %v", err)
	}
	r1.Body.Close()

	// A reveal of the now-consumed token.
	consumed, err := public.Get(base + shareURL)
	if err != nil {
		t.Fatalf("consumed get: %v", err)
	}
	consumedBody, _ := io.ReadAll(consumed.Body)
	consumed.Body.Close()

	// A reveal of a token that never existed (same length, valid base64).
	unknownToken := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	unknown, err := public.Get(base + "/share/" + unknownToken)
	if err != nil {
		t.Fatalf("unknown get: %v", err)
	}
	unknownBody, _ := io.ReadAll(unknown.Body)
	unknown.Body.Close()

	if consumed.StatusCode != http.StatusNotFound || unknown.StatusCode != http.StatusNotFound {
		t.Fatalf("want both 404: consumed=%d unknown=%d", consumed.StatusCode, unknown.StatusCode)
	}
	if string(consumedBody) != string(unknownBody) {
		t.Fatalf("consumed and unknown responses differ (must be indistinguishable):\nconsumed=%q\nunknown=%q", consumedBody, unknownBody)
	}
}

// share-links.md "Atomicity": under concurrent first requests for the same token,
// exactly one succeeds and every other caller gets the not-found outcome.
func TestRevealShareConcurrentExactlyOneSuccess(t *testing.T) {
	base, c := setupWithSecret(t, "hunter2")
	shareURL := extractShareURL(t, generateShare(t, base, c, "1"))

	const n = 12
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok200, missing := 0, 0
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			public := &http.Client{}
			resp, err := public.Get(base + shareURL)
			if err != nil {
				return
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			mu.Lock()
			defer mu.Unlock()
			switch resp.StatusCode {
			case http.StatusOK:
				if strings.Contains(string(body), "hunter2") {
					ok200++
				}
			case http.StatusNotFound:
				missing++
			}
		}()
	}
	wg.Wait()
	if ok200 != 1 {
		t.Fatalf("concurrent reveals with plaintext = %d, want exactly 1", ok200)
	}
	if missing != n-1 {
		t.Fatalf("concurrent 404s = %d, want %d", missing, n-1)
	}
}

// share-links.md "Model": A share is a snapshot ... Later edits to the underlying secret
// do not update or invalidate an already-generated, unexpired share.
func TestRevealShareIsSnapshotOfSecretAtGeneration(t *testing.T) {
	base, c := setupWithSecret(t, "hunter2")
	shareURL := extractShareURL(t, generateShare(t, base, c, "1"))

	// Edit the secret's value AFTER generating the share.
	code, _ := postForm(t, c, base+"/secrets/1", url.Values{
		"name": {"prod-db"}, "tag": {"database"}, "value": {"rotated-new-value"},
	})
	if code != http.StatusSeeOther && code != http.StatusOK {
		t.Fatalf("update code=%d", code)
	}

	public := &http.Client{}
	resp, err := public.Get(base + shareURL)
	if err != nil {
		t.Fatalf("reveal get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reveal code=%d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "hunter2") {
		t.Fatalf("share should snapshot the value at generation (hunter2):\n%s", body)
	}
	if strings.Contains(string(body), "rotated-new-value") {
		t.Fatalf("share leaked the edited value; it must be a snapshot:\n%s", body)
	}
}

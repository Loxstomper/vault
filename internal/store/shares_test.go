package store

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// TestInsertShareRoundTrips encodes specs/share-links.md "Model": a share row holds
// token_hash, salt, ciphertext (nonce||ciphertext), the secret's name at generation time,
// expires_at, and created_at — and the store persists them faithfully as opaque blobs.
func TestInsertShareRoundTrips(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	tokenHash := []byte("this-stands-in-for-sha256-of-token")
	salt := []byte("per-share-salt00")
	ciphertext := []byte("nonce||sealed-snapshot-bytes")
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)

	sh, err := st.InsertShare(ctx, tokenHash, salt, ciphertext, "prod-db", expires)
	if err != nil {
		t.Fatalf("insert share: %v", err)
	}
	if sh.ID == 0 {
		t.Fatalf("expected a non-zero id, got %+v", sh)
	}
	if !bytes.Equal(sh.TokenHash, tokenHash) {
		t.Fatalf("token_hash not persisted: got %q want %q", sh.TokenHash, tokenHash)
	}
	if !bytes.Equal(sh.Salt, salt) {
		t.Fatalf("salt not persisted: got %q want %q", sh.Salt, salt)
	}
	if !bytes.Equal(sh.Ciphertext, ciphertext) {
		t.Fatalf("ciphertext not persisted: got %q want %q", sh.Ciphertext, ciphertext)
	}
	if sh.Name != "prod-db" {
		t.Fatalf("name snapshot not persisted: got %q", sh.Name)
	}
	if !sh.ExpiresAt.Equal(expires) {
		t.Fatalf("expires_at not persisted: got %v want %v", sh.ExpiresAt, expires)
	}
	if sh.CreatedAt.IsZero() {
		t.Fatalf("created_at not set: %+v", sh)
	}
}

// TestInsertShareStoresNoPlaintext encodes specs/share-links.md "Model": "No column ever
// holds the plaintext secret value or the raw token." The store is encryption-agnostic —
// it must persist exactly the opaque blob handed to it and nothing derived from plaintext.
func TestInsertShareStoresNoPlaintext(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	tokenHash := []byte("hashed-token-bytes-0000000000000")
	salt := []byte("per-share-salt00")
	ciphertext := []byte("opaque-sealed-blob")
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)

	if _, err := st.InsertShare(ctx, tokenHash, salt, ciphertext, "prod-db", expires); err != nil {
		t.Fatalf("insert share: %v", err)
	}

	// Scan every text/blob column of the shares table; none may contain a plaintext
	// secret value. (The store never receives plaintext, so this proves the seam.)
	rows, err := st.db.QueryContext(ctx, `SELECT token_hash, salt, ciphertext, name FROM shares`)
	if err != nil {
		t.Fatalf("query shares: %v", err)
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var th, sa, ct []byte
		var name string
		if err := rows.Scan(&th, &sa, &ct, &name); err != nil {
			t.Fatalf("scan: %v", err)
		}
		seen++
		if !bytes.Equal(ct, ciphertext) {
			t.Fatalf("ciphertext column altered: got %q want %q", ct, ciphertext)
		}
	}
	if seen != 1 {
		t.Fatalf("expected exactly one share row, got %d", seen)
	}
}

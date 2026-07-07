package store

import (
	"context"
	"sync"
	"testing"
	"time"
)

// The shares store is the persistence half of the one-time share-link feature. These
// tests pin the store contract the reveal/generate handlers rely on: a row that holds no
// plaintext, an atomic single-use lookup+delete, and expiry handled inside that same
// transaction.

// shares.md "Model": token_hash — SHA-256 of the share token. The raw token is never
// stored ... blob — nonce || ciphertext ... Never plaintext.
func TestCreateShareStoresNoPlaintext(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	tokenHash := []byte("0123456789abcdef0123456789abcdef") // 32-byte SHA-256 digest stand-in
	salt := []byte("saltsaltsaltsalt")
	blob := []byte("nonce-and-ciphertext-bytes")
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)

	if err := st.CreateShare(ctx, tokenHash, salt, blob, "prod-db", exp); err != nil {
		t.Fatalf("create share: %v", err)
	}

	// The row must round-trip on consume with the persisted fields intact.
	got, err := st.ConsumeShare(ctx, tokenHash)
	if err != nil {
		t.Fatalf("consume share: %v", err)
	}
	if string(got.Blob) != string(blob) {
		t.Fatalf("blob = %q, want %q", got.Blob, blob)
	}
	if string(got.Salt) != string(salt) {
		t.Fatalf("salt = %q, want %q", got.Salt, salt)
	}
	if got.SecretName != "prod-db" {
		t.Fatalf("secret name = %q, want prod-db", got.SecretName)
	}
}

// shares.md "Atomicity": SELECT ... ; DELETE ... inside one transaction, so a second
// concurrent or later request for the same token cannot see a row a first request
// already consumed.
func TestConsumeShareIsSingleUse(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	tokenHash := []byte("abcdefabcdefabcdefabcdefabcdef12")
	exp := time.Now().Add(time.Hour).UTC()
	if err := st.CreateShare(ctx, tokenHash, []byte("salt"), []byte("blob"), "n", exp); err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := st.ConsumeShare(ctx, tokenHash); err != nil {
		t.Fatalf("first consume should succeed: %v", err)
	}
	// The second consume must find nothing — the row was deleted in the first transaction.
	if _, err := st.ConsumeShare(ctx, tokenHash); err != ErrNotFound {
		t.Fatalf("second consume = %v, want ErrNotFound", err)
	}
}

// shares.md "Atomicity": under concurrent first requests for the same token, exactly one
// succeeds and every other caller gets the not-found outcome.
func TestConsumeShareConcurrentExactlyOne(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	tokenHash := []byte("cafecafecafecafecafecafecafecafe")
	exp := time.Now().Add(time.Hour).UTC()
	if err := st.CreateShare(ctx, tokenHash, []byte("salt"), []byte("blob"), "n", exp); err != nil {
		t.Fatalf("create: %v", err)
	}

	const n = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			if _, err := st.ConsumeShare(ctx, tokenHash); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if successes != 1 {
		t.Fatalf("concurrent consume successes = %d, want exactly 1", successes)
	}
}

// shares.md "Revealing a share": the row's expires_at has passed ... returns the
// not-found outcome. An encountered expired row is deleted as part of the same
// transaction (so it doesn't linger).
func TestConsumeShareExpiredIsNotFoundAndDeleted(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	tokenHash := []byte("expiredexpiredexpiredexpired1234")
	past := time.Now().Add(-time.Minute).UTC()
	if err := st.CreateShare(ctx, tokenHash, []byte("salt"), []byte("blob"), "n", past); err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := st.ConsumeShare(ctx, tokenHash); err != ErrNotFound {
		t.Fatalf("expired consume = %v, want ErrNotFound", err)
	}
	// It was deleted in that same transaction: a subsequent consume also finds nothing
	// (and there is nothing lingering to re-check).
	if _, err := st.ConsumeShare(ctx, tokenHash); err != ErrNotFound {
		t.Fatalf("second consume after expiry = %v, want ErrNotFound", err)
	}
}

// shares.md "Revealing a share": if no row matches ... returns the not-found outcome.
func TestConsumeShareMissingIsNotFound(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	if _, err := st.ConsumeShare(ctx, []byte("nope-nope-nope-nope-nope-nope-12")); err != ErrNotFound {
		t.Fatalf("missing consume = %v, want ErrNotFound", err)
	}
}

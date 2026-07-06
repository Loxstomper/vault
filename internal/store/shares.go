package store

import (
	"context"
	"time"
)

// Share is one one-time share link's persisted row. It is encryption-agnostic like the
// rest of the store: TokenHash is SHA-256(token) (never the raw token), Ciphertext is the
// nonce||ciphertext blob produced by re-sealing the plaintext under the token-derived key,
// and Name is the secret's name snapshot at generation time. No field ever holds the
// plaintext secret value or the raw token.
type Share struct {
	ID         int64
	TokenHash  []byte
	Salt       []byte
	Ciphertext []byte
	Name       string
	ExpiresAt  time.Time
	CreatedAt  time.Time
}

// InsertShare persists a one-time share row and returns it. The store never sees the raw
// token, the derivation key, or the plaintext — only the opaque hash, salt, and blob.
func (s *Store) InsertShare(ctx context.Context, tokenHash, salt, ciphertext []byte, name string, expiresAt time.Time) (Share, error) {
	// Skeleton only — the implementor writes the parameterized INSERT and the shares
	// schema. Returns a zero row so the acceptance tests fail on their assertions
	// (not a compile error), per the red contract.
	return Share{}, nil
}

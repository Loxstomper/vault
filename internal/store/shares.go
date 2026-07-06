package store

import (
	"context"
	"crypto/subtle"
	"fmt"
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
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO shares (token_hash, salt, ciphertext, name, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		tokenHash, salt, ciphertext, name, expiresAt, now)
	if err != nil {
		return Share{}, fmt.Errorf("store: insert share: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Share{}, fmt.Errorf("store: insert share id: %w", err)
	}
	return Share{
		ID:         id,
		TokenHash:  tokenHash,
		Salt:       salt,
		Ciphertext: ciphertext,
		Name:       name,
		ExpiresAt:  expiresAt,
		CreatedAt:  now,
	}, nil
}

// ConsumeShare implements the reveal-and-burn seam (specs/share-links.md "Behavior →
// Reveal" steps 1–3): it hashes-then-compares the presented token in constant time
// against every stored token_hash — a plain SQL "WHERE token_hash = ?" would let SQLite's
// own byte comparison short-circuit on the first differing byte, which is exactly the
// timing tell the spec forbids — and reads-then-deletes the matching row in one
// transaction, so a second or concurrent caller for the same token finds no row. An
// expired-but-found row is deleted before returning ErrNotFound, per "An expired row
// found this way is deleted before responding." No row (wrong token), an expired row, and
// a raced/already-used token are all reported identically as ErrNotFound.
func (s *Store) ConsumeShare(ctx context.Context, tokenHash []byte) (Share, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Share{}, fmt.Errorf("store: consume share begin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	rows, err := tx.QueryContext(ctx,
		`SELECT id, token_hash, salt, ciphertext, name, expires_at, created_at FROM shares`)
	if err != nil {
		return Share{}, fmt.Errorf("store: consume share query: %w", err)
	}
	var match Share
	found := false
	for rows.Next() {
		var sh Share
		if err := rows.Scan(&sh.ID, &sh.TokenHash, &sh.Salt, &sh.Ciphertext, &sh.Name, &sh.ExpiresAt, &sh.CreatedAt); err != nil {
			_ = rows.Close()
			return Share{}, fmt.Errorf("store: consume share scan: %w", err)
		}
		if subtle.ConstantTimeCompare(sh.TokenHash, tokenHash) == 1 {
			match = sh
			found = true
			// Keep iterating (and comparing) the remaining rows so the loop's total
			// work does not itself become a timing signal for "found at row N".
		}
	}
	if err := rows.Err(); err != nil {
		return Share{}, fmt.Errorf("store: consume share iterate: %w", err)
	}
	if err := rows.Close(); err != nil {
		return Share{}, fmt.Errorf("store: consume share close: %w", err)
	}

	if !found {
		if err := tx.Commit(); err != nil {
			return Share{}, fmt.Errorf("store: consume share commit: %w", err)
		}
		return Share{}, ErrNotFound
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM shares WHERE id = ?`, match.ID); err != nil {
		return Share{}, fmt.Errorf("store: consume share delete: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Share{}, fmt.Errorf("store: consume share commit: %w", err)
	}

	if match.ExpiresAt.Before(time.Now().UTC()) {
		return Share{}, ErrNotFound
	}
	return match, nil
}

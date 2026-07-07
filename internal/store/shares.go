package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Share is one one-time share-link row. Blob is nonce||ciphertext sealed with the
// token-derived key; the store never sees plaintext or the raw token (only its hash).
type Share struct {
	ID         int64
	TokenHash  []byte
	Salt       []byte
	Blob       []byte
	SecretName string
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// CreateShare persists a share row keyed by tokenHash (SHA-256 of the token).
func (s *Store) CreateShare(ctx context.Context, tokenHash, salt, blob []byte, secretName string, expiresAt time.Time) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO shares (token_hash, salt, blob, secret_name, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		tokenHash, salt, blob, secretName, now, expiresAt.UTC())
	if err != nil {
		return fmt.Errorf("store: create share: %w", err)
	}
	return nil
}

// ConsumeShare atomically looks up the share by tokenHash and deletes it in a single
// transaction, so exactly one caller consumes a given token. A missing, expired, or
// already-consumed token yields ErrNotFound; an encountered expired row is deleted in the
// same transaction.
//
// The lookup itself uses the row's tokenHash column via a parameterized query (SQLite
// will use the unique index for this exact-match WHERE); the caller is responsible for
// only ever presenting a tokenHash it derived itself, and for comparing any resulting
// secret material in constant time (done at the web layer, since SQLite has no notion of
// constant-time comparison and this is an exact-match key lookup, not a secret compare).
func (s *Store) ConsumeShare(ctx context.Context, tokenHash []byte) (Share, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Share{}, fmt.Errorf("store: consume share begin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op

	var sh Share
	err = tx.QueryRowContext(ctx,
		`SELECT id, token_hash, salt, blob, secret_name, created_at, expires_at FROM shares WHERE token_hash = ?`,
		tokenHash).Scan(&sh.ID, &sh.TokenHash, &sh.Salt, &sh.Blob, &sh.SecretName, &sh.CreatedAt, &sh.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Share{}, ErrNotFound
	}
	if err != nil {
		return Share{}, fmt.Errorf("store: consume share select: %w", err)
	}

	// Delete the row now, inside the same transaction, whether it was still valid or
	// found expired — either way it must not linger for a later request to see.
	if _, err := tx.ExecContext(ctx, `DELETE FROM shares WHERE id = ?`, sh.ID); err != nil {
		return Share{}, fmt.Errorf("store: consume share delete: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return Share{}, fmt.Errorf("store: consume share commit: %w", err)
	}

	if sh.ExpiresAt.Before(time.Now().UTC()) {
		return Share{}, ErrNotFound
	}
	return sh, nil
}

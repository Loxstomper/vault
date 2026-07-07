package store

import (
	"context"
	"errors"
	"time"
)

// errShareNotImplemented is the placeholder error returned by the un-implemented share
// store methods so each test fails on its own assertion rather than a panic aborting the
// whole package test binary.
var errShareNotImplemented = errors.New("store: shares not implemented")

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
	return errShareNotImplemented
}

// ConsumeShare atomically looks up the share by tokenHash and deletes it in a single
// transaction, so exactly one caller consumes a given token. A missing, expired, or
// already-consumed token yields ErrNotFound; an encountered expired row is deleted in the
// same transaction.
func (s *Store) ConsumeShare(ctx context.Context, tokenHash []byte) (Share, error) {
	return Share{}, errShareNotImplemented
}

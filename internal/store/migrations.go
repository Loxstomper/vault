package store

import (
	"context"
	"fmt"
)

// schema is the full set of tables. It is intentionally idempotent (IF NOT EXISTS) so
// Open can run it on every boot; this demo has no incremental-migration machinery.
const schema = `
CREATE TABLE IF NOT EXISTS users (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	username      TEXT    NOT NULL UNIQUE,
	password_hash TEXT    NOT NULL,
	kdf_salt      BLOB    NOT NULL,
	created_at    TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS secrets (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT NOT NULL,
	tag        TEXT NOT NULL DEFAULT '',
	ciphertext BLOB NOT NULL,
	expires_at TIMESTAMP,
	created_at TIMESTAMP NOT NULL,
	updated_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_secrets_updated ON secrets (updated_at DESC);

CREATE TABLE IF NOT EXISTS audit_log (
	id     INTEGER PRIMARY KEY AUTOINCREMENT,
	action TEXT NOT NULL,
	target TEXT NOT NULL DEFAULT '',
	at     TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log (at DESC);

-- shares holds one-time share-link snapshots (specs/share-links.md "Model"). It is
-- encryption-agnostic like the rest of the store: token_hash is SHA-256(token) (never the
-- raw token), ciphertext is nonce||ciphertext re-sealed under a token-derived key, and
-- name is the secret's name snapshot at generation time.
CREATE TABLE IF NOT EXISTS shares (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	token_hash BLOB NOT NULL,
	salt       BLOB NOT NULL,
	ciphertext BLOB NOT NULL,
	name       TEXT NOT NULL,
	expires_at TIMESTAMP NOT NULL,
	created_at TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_shares_token_hash ON shares (token_hash);
`

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	return nil
}

# One-time share links

A secret's owner can mint a **single-use, expiring public link** for that secret's
current value. Anyone holding the link can reveal the value **exactly once**, without a
session; after that reveal (or after one hour, whichever comes first) the link is dead
forever. This spec covers generation, storage, reveal, and the audit trail. It follows the
binding engineering conventions in [conventions.md](conventions.md) (layering, SQL
parameterization, `crypto/rand`-only randomness, constant-time comparisons, htmx fragment
conventions, no new dependencies) and complements [secrets.md](secrets.md) (the secret
model being shared) and [audit.md](audit.md) (the log this feature writes to).

## Why a public endpoint can decrypt anything at all

The vault's AES key is derived from the master password and lives only in the owner's
session (see [auth.md](auth.md)); a sessionless request can never see it. So a share is not
a pointer into the encrypted secret store — it is its **own encrypted snapshot**:

- At **generate** time (owner authenticated, session key available), the handler opens the
  secret with `crypto.Open` and the session key, then **re-seals the plaintext** with a key
  derived (via the existing `crypto.DeriveKey` Argon2id derivation) from the share token
  itself, salted with a fresh random salt generated for that share (`crypto.NewSalt`).
- At **reveal** time (no session), the handler derives the same key from the token
  presented in the URL and the stored salt, and opens the share's own blob with
  `crypto.Open`. No session, no master password, and no plaintext at rest are ever
  required or stored.
- A share is therefore a **snapshot**: subsequent edits to the underlying secret never
  change an already-generated share.

Reuse the existing primitives in `internal/crypto` (`Seal`, `Open`, `DeriveKey`, `NewSalt`,
`RandomToken`) — do not add new cryptographic primitives.

## Token

- The token is `crypto.RandomToken(32)`: 32 bytes from `crypto/rand`, URL-safe base64.
- The share URL is `/share/{token}`.
- The database stores **only `SHA-256(token)`**, never the token itself. Looking up a
  presented token hashes it and compares against `token_hash` using
  `subtle.ConstantTimeCompare` — a leaked database contains no usable links.

## Model

A share row holds: `token_hash`, `salt` (the per-share Argon2id salt), `ciphertext`
(`nonce||ciphertext` from re-sealing the plaintext under the token-derived key), the
secret's `name` at generation time, `expires_at`, and `created_at`. No column ever holds
the plaintext secret value or the raw token.

## Behavior

- **Generate** — a "share" control on a secret's row in `/vault` (owner authenticated via
  the existing session). It decrypts the secret, mints a token and salt, re-seals the
  plaintext under the token-derived key, inserts the share row with `expires_at` = now +
  1 hour, appends a `share-create` audit entry (target = secret name), and returns an htmx
  fragment showing the full share URL (`/share/{token}`) with a copy-to-clipboard button.
  This endpoint requires the existing session auth like the rest of the secret routes.
- **Reveal** (`GET /share/{token}`) — a public route, reachable with **no session cookie**,
  and therefore **not** wrapped by the session `auth` middleware that guards `/secrets/*`
  and `/vault/*`. It:
  1. Hashes the presented token and looks up a share row by `token_hash` in constant time.
  2. If no row matches, **or** the row's `expires_at` has passed, responds `404 Not Found`
     with no secret content. An expired row found this way is deleted before responding.
  3. Otherwise, atomically **deletes the row in the same transaction that read it**, then
     derives the key from the token + stored salt and opens the ciphertext.
  4. Appends a `share-reveal` audit entry (target = the share's stored secret name).
  5. Renders a bare page — styled like the login page — showing the secret name and its
     plaintext value, and stating plainly that the link has now been destroyed and cannot
     be used again.

  Because the delete happens in the same transaction as the read, a second request for the
  same token — or a concurrent racing request — finds no row and gets the identical 404 as
  a wrong or expired token; exactly one concurrent request can win the row. Wrong, already-
  used, and expired tokens are **indistinguishable** to the caller: all three produce the
  same 404 with no content and no timing tell beyond the constant-time hash comparison.

## Audit

Two new append-only actions, consistent with [audit.md](audit.md):

- `share-create` — a share link was generated (target = secret name).
- `share-reveal` — a share link was revealed and burned (target = secret name).

Both show up in the existing dashboard activity feed like any other audit entry.

## Out of scope

- Rate limiting the generate or reveal endpoints.
- Any share listing, management, or manual revocation UI.
- Configurable expiry (it is fixed at 1 hour).
- Multi-use links.
- Email or other notification of the link.
- Password-protected shares.
- Any change to existing secret create/edit/delete/reveal behavior.

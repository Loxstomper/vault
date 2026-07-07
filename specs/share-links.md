# Share links

A share link lets the vault owner generate a **one-time, single-use** URL for a single
secret's current value. Anyone holding the link can reveal the value **exactly once**,
without an authenticated session; after that reveal (or after 1 hour, whichever comes
first) the link is permanently dead. This spec follows the binding conventions in
[conventions.md](conventions.md) (layering, parameterized SQL only, `crypto/rand` only,
constant-time comparisons, no new dependencies) and cross-references
[secrets.md](secrets.md) and [audit.md](audit.md).

## Model

A share is a row in a `shares` table (or equivalent), holding:

- `token_hash` — SHA-256 of the share token. The raw token is **never** stored.
- `salt` — random salt used to derive the share's encryption key from the token.
- `blob` — `nonce || ciphertext` of the secret's plaintext value, sealed with the
  token-derived key (see Crypto below). Never plaintext.
- `secret_name` — snapshot of the secret's name at generation time, for display and
  audit target.
- `created_at`, `expires_at` (`created_at` + 1 hour).

A share is a **snapshot**: it captures the secret's value at generation time. Later
edits to the underlying secret do not update or invalidate an already-generated,
unexpired share; deleting the underlying secret does not delete an outstanding share.

## Generating a share (authenticated)

- Entry point: an affordance on the secret's row in the vault list (see
  [secrets.md](secrets.md)), calling `POST /secrets/{id}/share` through the existing
  `auth` middleware — the caller must hold a valid session.
- The handler decrypts the secret's stored value with the **session's** derived key
  (`crypto.Open`), exactly as the existing reveal path does.
- It generates a token: 32 bytes from `crypto/rand`, URL-safe base64 (reuse
  `crypto.RandomToken` or equivalent — do not add a new primitive).
- It derives a fresh per-share salt (`crypto/rand`) and a key from the **token** via the
  existing Argon2id derivation (`crypto.DeriveKey`), then re-seals the plaintext with
  that key (`crypto.Seal`) — never the session/master key. The re-sealed blob is what's
  persisted; the plaintext and the session key are not stored.
- It stores the row keyed by `SHA-256(token)`, not the token itself.
- It sets `expires_at = now + 1 hour`.
- It records a `share-create` audit entry (target = secret name; see
  [audit.md](audit.md)).
- The handler returns (as an htmx fragment, swapped into the row) the full share URL
  `/share/{token}` and a copy-to-clipboard control. This is the **only** place the raw
  token is ever exposed.

## Revealing a share (public, no session)

- Route: `GET /share/{token}`. This route is **exempt from the `auth` middleware** — it
  must be reachable with no session cookie at all, since the whole point is to hand the
  link to someone without vault credentials.
- The handler computes `SHA-256(token)` and looks up the row by that hash using a
  constant-time comparison (`subtle.ConstantTimeCompare`) — never a raw `==` or a query
  that could leak timing information about partial matches.
- **Atomicity:** the lookup, expiry check, delete, and read must happen as a single
  store-layer transaction: `SELECT ... ; DELETE ...` (delete-and-return) inside one
  transaction, so that:
  - a second concurrent or later request for the same token cannot see a row that a
    first request already consumed;
  - under concurrent first requests for the same token, **exactly one** succeeds and
    every other caller — concurrent or later — gets the not-found outcome.
- If no row matches, the row's `expires_at` has passed, or the row was already consumed,
  the endpoint returns **404** with no secret content. All three cases are
  **indistinguishable** to the caller — same status, same body shape. An encountered
  expired row is deleted as part of the same transaction (so it doesn't linger).
- On a genuine hit: derive the key from the presented token + the row's stored `salt`
  (`crypto.DeriveKey`), open the blob (`crypto.Open`), delete the row (already done
  atomically above), record a `share-reveal` audit entry (target = `secret_name`
  snapshotted on the row, not a live lookup of the current secret), and render the
  public reveal page.
- The public reveal page is a bare, unauthenticated page styled like the login page
  (see [auth.md](auth.md)): it shows the secret's name and decrypted value, and states
  plainly that the link has now been permanently destroyed and cannot be reused.

## Security properties

- The vault's master-derived AES key never leaves the owner's session; it is not needed
  to open a share blob, and a leaked share row alone (without the raw token) cannot be
  decrypted since the row holds only `token_hash`, never the token.
- A leaked database dump contains no usable link: reproducing a valid token from its
  SHA-256 is infeasible, matching the vault's usual crypto conventions in
  [conventions.md](conventions.md).
- No plaintext secret value is ever written to the `shares` row.

## Out of scope

- Rate limiting the reveal endpoint.
- Share revocation or a share-management/listing UI.
- Configurable expiry (fixed at 1 hour).
- Multi-use or re-issuable links.
- Email/notification delivery of the link.
- Password-protecting a share on top of the token.
- Any change to existing secret create/edit/delete/reveal behavior.

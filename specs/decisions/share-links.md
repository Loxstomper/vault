# Decisions: Add one-time, single-use secret share links (/share/{token})

_Provenance for the spec authored or refined via the wizard. The spec is the source
of truth; this records the decisions behind it. Git history of this file is the
decision-evolution log — there is no separate status or supersession machinery._

- Share token format & storage → Store SHA-256(token) only — 32 bytes crypto/rand, URL-safe base64; only SHA-256 of token stored; constant-time lookup so a DB leak yields no usable links.
- How does a sessionless reveal decrypt without the master key? — At generate time, re-seal plaintext under a key derived (Argon2id) from the token itself with a per-share random salt; reveal derives the same key from the presented token — no session or master key needed.
- Share row contents — token_hash, salt, nonce||ciphertext, secret name snapshot, expires_at, created_at — no plaintext, no raw token.
- Single-use enforcement — Reveal atomically deletes the row in the same transaction as the read, so races/reuse land on the same 404 path.
- Expiry duration — Fixed 1 hour after generation, not configurable; expired token deleted on encounter and 404s identically to wrong/used.
- Audit coverage — New actions share-create (on generate) and share-reveal (on reveal, target=secret name), per specs/audit.md's append-only convention.
- UI scope — Row-level 'share' affordance (htmx fragment) returning URL + copy button; bare public reveal page styled like login; no share listing/management/revocation UI.
- Out of scope items — Rate limiting, revocation UI, configurable expiry, multi-use links, notifications, password-protected shares, changes to existing secret CRUD — explicitly excluded.
- Seed granularity (epic mode) — Epic integration mode requires exactly one root seed issue; decomposition planner fans it into store/crypto/generate + reveal/UI work.

Conversation transcript: `sha256:9f2f98950a7da94629be74876866104faa8d6f92c417cb15bdd3b6ea22d0a19a`

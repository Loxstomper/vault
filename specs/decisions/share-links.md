# Decisions: Add one-time, single-use secret share links (/share/{token}) with token-derived encryption, atomic burn-on-reveal, 1-hour expiry, and audit logging

_Provenance for the spec authored or refined via the wizard. The spec is the source
of truth; this records the decisions behind it. Git history of this file is the
decision-evolution log — there is no separate status or supersession machinery._

- Token generation & storage → Store SHA-256 hash only, constant-time compare — 32 bytes crypto/rand, URL-safe base64, DB stores only SHA-256 of token; constant-time compare so a leaked DB yields no usable links.
- How is the share blob encrypted given the session key is unavailable at reveal time? → Re-seal with token-derived key (Argon2id, per-share salt) — At generate time, decrypt with session key then re-seal with a key derived (Argon2id) from the token itself + per-share random salt; reveal derives the same key from the presented token. No session/master key needed to reveal.
- Single-use & expiry semantics → Atomic read+delete, 1hr TTL, indistinguishable 404s — Reveal atomically deletes the row in the same transaction as the read; 1-hour expiry; expired/used/wrong tokens all 404 identically and expired rows are deleted on encounter.
- Audit coverage for share feature — share-create on generate, share-reveal on reveal (target = secret name), consistent with audit.md's append-only, complete-record rule.
- UI scope — Minimal: share affordance + copy-URL htmx fragment on secret row; bare public reveal page styled like login page stating the link is now destroyed; no management/listing UI.
- Out of scope items — No rate limiting, revocation UI, configurable expiry, multi-use links, notifications, password-protected shares, or changes to existing secret CRUD.
- Spec organization — New specs/share-links.md linked from README and from secrets.md/audit.md; audit.md and README edited in place to reference it.

Conversation transcript: `sha256:8cb74d46cf5dd2328b5a11a80450fffdfef8b6c9e3e3b3dc59baa9f183738155`

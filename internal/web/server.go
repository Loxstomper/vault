// Package web is the vault's HTTP layer: session-cookie auth, the secrets CRUD + reveal
// endpoints (htmx fragments), and the audit feed. It holds the per-session encryption key
// and seals/opens secret values, keeping the store encryption-agnostic.
package web

import (
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/harness-demo/vault/internal/crypto"
	"github.com/harness-demo/vault/internal/store"
	"github.com/harness-demo/vault/internal/web/views"
)

// shareTTL is the fixed, non-configurable lifetime of a share link (specs/share-links.md:
// "Configurable expiry" is explicitly out of scope).
const shareTTL = time.Hour

//go:embed static
var staticFS embed.FS

const sessionTTL = 30 * time.Minute

// Server wires the store and session table behind the HTTP routes.
type Server struct {
	st   *store.Store
	sess *sessions
	mux  *http.ServeMux
	// strictCookie hardens the session cookie to SameSite=Strict. It defaults to false
	// because this app is a *demo artifact* whose primary job is to be shown live inside
	// the presentation deck's cross-site iframe — and SameSite=Strict cookies are dropped
	// on cross-site frame loads, which would leave the framed app permanently logged out.
	// So the shipped default is the iframe-friendly SameSite=None; Secure. Set this (via
	// VAULT_STRICT_COOKIE) to restore the hardened posture for a non-embedded deployment.
	strictCookie bool
}

// Option configures a Server.
type Option func(*Server)

// WithStrictCookie hardens the session cookie to SameSite=Strict instead of the default
// embeddable SameSite=None; Secure. Use it for a standalone (non-iframe) deployment.
func WithStrictCookie(v bool) Option { return func(s *Server) { s.strictCookie = v } }

// New returns a Server backed by st with its routes registered.
func New(st *store.Store, opts ...Option) *Server {
	s := &Server{st: st, sess: newSessions(sessionTTL), mux: http.NewServeMux()}
	for _, opt := range opts {
		opt(s)
	}
	s.routes()
	return s
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func (s *Server) routes() {
	s.mux.Handle("GET /static/", http.FileServerFS(staticFS))

	s.mux.HandleFunc("GET /", s.handleIndex)
	s.mux.HandleFunc("GET /setup", s.handleSetupForm)
	s.mux.HandleFunc("POST /setup", s.handleSetup)
	s.mux.HandleFunc("GET /login", s.handleLoginForm)
	s.mux.HandleFunc("POST /login", s.handleLogin)
	s.mux.HandleFunc("POST /logout", s.handleLogout)

	s.mux.HandleFunc("GET /vault", s.auth(s.handleVault))
	s.mux.HandleFunc("GET /vault/search", s.auth(s.handleSearch))
	s.mux.HandleFunc("GET /secrets/new", s.auth(s.handleNewForm))
	s.mux.HandleFunc("POST /secrets", s.auth(s.handleCreate))
	s.mux.HandleFunc("GET /secrets/{id}/edit", s.auth(s.handleEditForm))
	s.mux.HandleFunc("POST /secrets/{id}", s.auth(s.handleUpdate))
	s.mux.HandleFunc("DELETE /secrets/{id}", s.auth(s.handleDelete))
	s.mux.HandleFunc("GET /secrets/{id}/reveal", s.auth(s.handleReveal))
	s.mux.HandleFunc("POST /secrets/{id}/share", s.auth(s.handleShareCreate))

	// The public reveal endpoint is deliberately NOT wrapped in s.auth: it must be
	// reachable with no session cookie at all (see specs/share-links.md).
	s.mux.HandleFunc("GET /share/{token}", s.handleShareReveal)
}

// handleShareCreate generates a one-time share link for a secret (specs/share-links.md
// "Generating a share (authenticated)"). It decrypts with the session key exactly as
// handleReveal does, then re-seals under a fresh token-derived key so the persisted row
// never depends on the session/master key.
func (s *Server) handleShareCreate(w http.ResponseWriter, r *http.Request, sess session) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	sec, err := s.st.SecretByID(r.Context(), id)
	if err != nil {
		s.notFoundOrError(w, err)
		return
	}
	plain, err := crypto.Open(sess.key, sec.Ciphertext)
	if err != nil {
		// The secret cannot be opened with this session's key — a data/state problem
		// (e.g. a secret sealed under a different master key than the current login
		// derives), not a bug in this handler. Log which secret so it is diagnosable.
		log.Printf("vault: share: cannot decrypt secret %d (%q) with session key: %v", sec.ID, sec.Name, err)
		http.Error(w, "cannot decrypt", http.StatusInternalServerError)
		return
	}

	token, err := crypto.RandomToken(32)
	if err != nil {
		s.serverError(w, err)
		return
	}
	salt, err := crypto.NewSalt()
	if err != nil {
		s.serverError(w, err)
		return
	}
	shareKey := crypto.DeriveKey(token, salt)
	blob, err := crypto.Seal(shareKey, plain)
	if err != nil {
		s.serverError(w, err)
		return
	}
	tokenHash := sha256.Sum256([]byte(token))
	expiresAt := time.Now().UTC().Add(shareTTL)
	if err := s.st.CreateShare(r.Context(), tokenHash[:], salt, blob, sec.Name, expiresAt); err != nil {
		s.serverError(w, err)
		return
	}
	_ = s.st.AppendAudit(r.Context(), "share-create", sec.Name)
	s.render(w, r, views.ShareLink("/share/"+token))
}

// handleShareReveal reveals-and-burns a share link (specs/share-links.md "Revealing a
// share (public, no session)"). It is deliberately not wrapped in s.auth: it must work
// with no session cookie. Missing, expired, and already-consumed tokens are all
// indistinguishable 404s.
func (s *Server) handleShareReveal(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	tokenHash := sha256.Sum256([]byte(token))
	sh, err := s.st.ConsumeShare(r.Context(), tokenHash[:])
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, err)
		return
	}
	// Defense in depth: confirm the row we got back really matches the presented token's
	// hash, in constant time, even though the store already selected by exact hash match
	// (specs/share-links.md: "using a constant-time comparison (subtle.ConstantTimeCompare)
	// — never a raw =="). A mismatch here cannot legitimately happen, but if it somehow
	// did, treat it as not-found rather than trusting the row.
	if subtle.ConstantTimeCompare(sh.TokenHash, tokenHash[:]) != 1 {
		http.NotFound(w, r)
		return
	}
	shareKey := crypto.DeriveKey(token, sh.Salt)
	plain, err := crypto.Open(shareKey, sh.Blob)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	_ = s.st.AppendAudit(r.Context(), "share-reveal", sh.SecretName)
	s.render(w, r, views.SharePage(sh.SecretName, string(plain)))
}

// --- auth middleware ---

// auth wraps a handler, requiring a valid session and passing it to the handler.
func (s *Server) auth(next func(http.ResponseWriter, *http.Request, session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		sess, ok := s.sess.get(c.Value)
		if !ok {
			s.clearCookie(w)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r, sess)
	}
}

// --- auth pages ---

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	n, err := s.st.CountUsers(r.Context())
	if err != nil {
		s.serverError(w, err)
		return
	}
	if n == 0 {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/vault", http.StatusSeeOther)
}

func (s *Server) handleSetupForm(w http.ResponseWriter, r *http.Request) {
	if n, _ := s.st.CountUsers(r.Context()); n > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, r, views.SetupPage())
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if n, _ := s.st.CountUsers(r.Context()); n > 0 {
		http.Error(w, "vault already initialized", http.StatusConflict)
		return
	}
	password := r.FormValue("password")
	if len(password) < 8 {
		s.render(w, r, views.SetupPage())
		return
	}
	hash, err := crypto.HashPassword(password)
	if err != nil {
		s.serverError(w, err)
		return
	}
	salt, err := crypto.NewSalt()
	if err != nil {
		s.serverError(w, err)
		return
	}
	if _, err := s.st.CreateUser(r.Context(), "owner", hash, salt); err != nil {
		s.serverError(w, err)
		return
	}
	s.startSession(w, r, "owner", crypto.DeriveKey(password, salt), "login")
}

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, views.LoginPage(""))
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	password := r.FormValue("password")
	u, err := s.st.UserByUsername(r.Context(), "owner")
	if errors.Is(err, store.ErrNotFound) {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if err != nil {
		s.serverError(w, err)
		return
	}
	if !crypto.VerifyPassword(password, u.PasswordHash) {
		w.WriteHeader(http.StatusUnauthorized)
		s.render(w, r, views.LoginPage("Incorrect master password."))
		return
	}
	s.startSession(w, r, u.Username, crypto.DeriveKey(password, u.KDFSalt), "login")
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sess.destroy(c.Value)
	}
	s.clearCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, username string, key []byte, auditAction string) {
	id, err := s.sess.create(username, key)
	if err != nil {
		s.serverError(w, err)
		return
	}
	_ = s.st.AppendAudit(r.Context(), auditAction, "")
	s.setCookie(w, id, sessionTTL)
	http.Redirect(w, r, "/vault", http.StatusSeeOther)
}

// --- vault pages ---

func (s *Server) handleVault(w http.ResponseWriter, r *http.Request, _ session) {
	ctx := r.Context()
	secrets, err := s.st.ListSecrets(ctx, "")
	if err != nil {
		s.serverError(w, err)
		return
	}
	audit, err := s.st.RecentAudit(ctx, 10)
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.render(w, r, views.VaultPage(toSecretViews(secrets), toAuditViews(audit), "", computeStats(secrets, audit)))
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request, _ session) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	secrets, err := s.st.ListSecrets(r.Context(), q)
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.render(w, r, views.SecretList(toSecretViews(secrets)))
}

func (s *Server) handleNewForm(w http.ResponseWriter, r *http.Request, _ session) {
	s.render(w, r, views.SecretForm("New secret", views.Secret{}, ""))
}

func (s *Server) handleEditForm(w http.ResponseWriter, r *http.Request, _ session) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	sec, err := s.st.SecretByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.serverError(w, err)
		return
	}
	s.render(w, r, views.SecretForm("Edit secret", toSecretView(sec), ""))
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request, sess session) {
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		s.render(w, r, views.SecretForm("New secret", views.Secret{Tag: r.FormValue("tag")}, "Name is required."))
		return
	}
	expires, err := parseExpiry(r.FormValue("expires"))
	if err != nil {
		s.render(w, r, views.SecretForm("New secret", views.Secret{Name: name, Tag: r.FormValue("tag")}, "Expiry must be YYYY-MM-DD."))
		return
	}
	ct, err := crypto.Seal(sess.key, []byte(r.FormValue("value")))
	if err != nil {
		s.serverError(w, err)
		return
	}
	if _, err := s.st.CreateSecret(r.Context(), name, strings.TrimSpace(r.FormValue("tag")), ct, expires); err != nil {
		s.serverError(w, err)
		return
	}
	_ = s.st.AppendAudit(r.Context(), "create", name)
	http.Redirect(w, r, "/vault", http.StatusSeeOther)
}

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request, sess session) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	expires, err := parseExpiry(r.FormValue("expires"))
	if err != nil {
		http.Error(w, "expiry must be YYYY-MM-DD", http.StatusBadRequest)
		return
	}
	ct, err := crypto.Seal(sess.key, []byte(r.FormValue("value")))
	if err != nil {
		s.serverError(w, err)
		return
	}
	if err := s.st.UpdateSecret(r.Context(), id, name, strings.TrimSpace(r.FormValue("tag")), ct, expires); err != nil {
		s.notFoundOrError(w, err)
		return
	}
	_ = s.st.AppendAudit(r.Context(), "update", name)
	http.Redirect(w, r, "/vault", http.StatusSeeOther)
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request, _ session) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	sec, err := s.st.SecretByID(r.Context(), id)
	if err != nil {
		s.notFoundOrError(w, err)
		return
	}
	if err := s.st.DeleteSecret(r.Context(), id); err != nil {
		s.notFoundOrError(w, err)
		return
	}
	_ = s.st.AppendAudit(r.Context(), "delete", sec.Name)
	w.WriteHeader(http.StatusOK) // htmx swaps the row out with the empty body
}

func (s *Server) handleReveal(w http.ResponseWriter, r *http.Request, sess session) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	sec, err := s.st.SecretByID(r.Context(), id)
	if err != nil {
		s.notFoundOrError(w, err)
		return
	}
	plain, err := crypto.Open(sess.key, sec.Ciphertext)
	if err != nil {
		log.Printf("vault: reveal: cannot decrypt secret %d (%q) with session key: %v", sec.ID, sec.Name, err)
		http.Error(w, "cannot decrypt", http.StatusInternalServerError)
		return
	}
	_ = s.st.AppendAudit(r.Context(), "reveal", sec.Name)
	s.render(w, r, views.RevealValue(string(plain)))
}

// --- helpers ---

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return 0, false
	}
	return id, true
}

func parseExpiry(s string) (*time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *Server) notFoundOrError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	s.serverError(w, err)
}

func (s *Server) serverError(w http.ResponseWriter, err error) {
	// Log the underlying cause: the client only ever sees a generic 500, so without this
	// an internal error is invisible and undiagnosable from the outside.
	log.Printf("vault: internal error: %v", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

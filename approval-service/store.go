// store.go — all database operations in one place.
package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Approval represents one access request and its current state.
type Approval struct {
	Token               string
	Status              string // pending | approved | rejected | expired
	Requester           string
	RequesterEmail      string
	ManagerEmail        string
	ADGroup             string
	Reason              string
	PipelineExecutionID string
	CreatedAt           time.Time
	ExpiresAt           time.Time
	DecidedAt           *time.Time
	DecidedBy           *string // verified SSO email of the person who actioned
	DecidedFromIP       *string
}

// EmailReference is what goes in the email URL — never the real token.
// The real token is looked up server-side after SSO verifies the manager.
// Short-lived and single-use: once clicked and verified, it is deleted.
type EmailReference struct {
	Reference string
	Token     string    // the real approval token — never exposed in URLs
	ExpiresAt time.Time // short window — manager must act within this time
}

// SSOState links an SSO state param back to an email reference.
// Created on email link click, deleted after callback.
type SSOState struct {
	State     string
	Reference string
}

type store struct {
	db *sql.DB
}

func newStore(path string) (*store, error) {
	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL")
	if err != nil {
		return nil, err
	}
	s := &store{db: db}
	return s, s.migrate()
}

func (s *store) close() { s.db.Close() }

func (s *store) migrate() error {
	_, err := s.db.Exec(`
		-- csrf_tokens: one-time tokens that tie the review form POST back to the
		-- verified manager identity from the SSO callback.
		-- Prevents the form being submitted from another tab or forged externally.
		CREATE TABLE IF NOT EXISTS csrf_tokens (
			token       TEXT NOT NULL,
			manager     TEXT NOT NULL,
			expires_at  DATETIME NOT NULL,
			used        INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (token, manager)
		);
	`)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
		CREATE TABLE IF NOT EXISTS approvals (
			token                 TEXT PRIMARY KEY,
			status                TEXT NOT NULL DEFAULT 'pending',
			requester             TEXT NOT NULL,
			requester_email       TEXT NOT NULL,
			manager_email         TEXT NOT NULL,
			ad_group              TEXT NOT NULL,
			reason                TEXT NOT NULL,
			pipeline_execution_id TEXT NOT NULL,
			created_at            DATETIME NOT NULL,
			expires_at            DATETIME NOT NULL,
			decided_at            DATETIME,
			decided_by            TEXT,
			decided_from_ip       TEXT
		);

		-- email_references: what goes in the email URL.
		-- The real token never appears in a URL or email body.
		-- expires_at is short (configurable, default 4 hours) so a leaked
		-- reference from email logs is useless after that window.
		CREATE TABLE IF NOT EXISTS email_references (
			reference  TEXT PRIMARY KEY,
			token      TEXT NOT NULL,
			expires_at DATETIME NOT NULL,
			used       INTEGER NOT NULL DEFAULT 0
		);

		-- sso_states: transient records linking an SSO flow back to a reference.
		-- Created on email link click, deleted after the SSO callback returns.
		CREATE TABLE IF NOT EXISTS sso_states (
			state      TEXT PRIMARY KEY,
			reference  TEXT NOT NULL,
			created_at DATETIME NOT NULL
		);

		-- audit_log: append-only, hash-chained.
		-- Each record includes the SHA-256 hash of the previous record.
		-- Any tampering with a record breaks every hash after it — detectable.
		-- Never UPDATE or DELETE from this table.
		CREATE TABLE IF NOT EXISTS audit_log (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			event         TEXT NOT NULL,
			data          TEXT NOT NULL,
			timestamp     TEXT NOT NULL,
			previous_hash TEXT NOT NULL,
			hash          TEXT NOT NULL
		);
	`)
	return err
}

// ─────────────────────────────────────────────────────────────
// Approval operations
// ─────────────────────────────────────────────────────────────

func (s *store) Create(
	requester, requesterEmail, managerEmail, adGroup, reason, pipelineID string,
	ttlHours int,
) (*Approval, error) {
	token := newUUID()
	now := time.Now().UTC()
	expires := now.Add(time.Duration(ttlHours) * time.Hour)

	_, err := s.db.Exec(`
		INSERT INTO approvals
		(token, requester, requester_email, manager_email, ad_group, reason,
		 pipeline_execution_id, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		token, requester, requesterEmail, managerEmail, adGroup, reason,
		pipelineID, now, expires,
	)
	if err != nil {
		return nil, fmt.Errorf("insert approval: %w", err)
	}
	return &Approval{
		Token: token, Status: "pending",
		Requester: requester, RequesterEmail: requesterEmail,
		ManagerEmail: managerEmail, ADGroup: adGroup,
		Reason: reason, PipelineExecutionID: pipelineID,
		CreatedAt: now, ExpiresAt: expires,
	}, nil
}

func (s *store) Get(token string) (*Approval, error) {
	row := s.db.QueryRow(`
		SELECT token, status, requester, requester_email, manager_email,
		       ad_group, reason, pipeline_execution_id,
		       created_at, expires_at, decided_at, decided_by, decided_from_ip
		FROM approvals WHERE token = ?`, token)

	a := &Approval{}
	var decidedAt sql.NullTime
	var decidedBy, decidedFromIP sql.NullString

	err := row.Scan(
		&a.Token, &a.Status, &a.Requester, &a.RequesterEmail, &a.ManagerEmail,
		&a.ADGroup, &a.Reason, &a.PipelineExecutionID,
		&a.CreatedAt, &a.ExpiresAt, &decidedAt, &decidedBy, &decidedFromIP,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("not found")
	}
	if err != nil {
		return nil, err
	}
	if decidedAt.Valid {
		t := decidedAt.Time
		a.DecidedAt = &t
	}
	if decidedBy.Valid {
		a.DecidedBy = &decidedBy.String
	}
	if decidedFromIP.Valid {
		a.DecidedFromIP = &decidedFromIP.String
	}
	if a.Status == "pending" && time.Now().UTC().After(a.ExpiresAt) {
		a.Status = "expired"
		s.db.Exec(`UPDATE approvals SET status = 'expired' WHERE token = ?`, token)
	}
	return a, nil
}

// Decide records the decision. Uses WHERE status='pending' so it is idempotent
// and a second click on the same link does nothing.
func (s *store) Decide(token, decision, decidedBy, ip string) error {
	res, err := s.db.Exec(`
		UPDATE approvals
		SET status = ?, decided_at = ?, decided_by = ?, decided_from_ip = ?
		WHERE token = ? AND status = 'pending'`,
		decision, time.Now().UTC(), decidedBy, ip, token,
	)
	if err != nil {
		return err
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("already decided or not found")
	}
	return nil
}

// ─────────────────────────────────────────────────────────────
// Email reference operations
// Fix 1: token never appears in a URL
// ─────────────────────────────────────────────────────────────

// CreateReference generates a short-lived opaque reference for the email link.
// ttlHours should be short (e.g. 4) — this is the window for the email link,
// not the overall approval window (which is longer).
func (s *store) CreateReference(token string, ttlHours int) (*EmailReference, error) {
	ref := newUUID()
	expires := time.Now().UTC().Add(time.Duration(ttlHours) * time.Hour)
	_, err := s.db.Exec(`
		INSERT INTO email_references (reference, token, expires_at)
		VALUES (?, ?, ?)`, ref, token, expires,
	)
	if err != nil {
		return nil, err
	}
	return &EmailReference{Reference: ref, Token: token, ExpiresAt: expires}, nil
}

// PeekReference checks a reference is valid without consuming it.
// Used in the review handler to validate before redirecting to SSO.
func (s *store) PeekReference(reference string) (*EmailReference, error) {
	row := s.db.QueryRow(`
		SELECT reference, token, expires_at, used
		FROM email_references WHERE reference = ?`, reference)
	var ref EmailReference
	var used int
	if err := row.Scan(&ref.Reference, &ref.Token, &ref.ExpiresAt, &used); err != nil {
		return nil, fmt.Errorf("not found")
	}
	if used == 1 {
		return nil, fmt.Errorf("already used")
	}
	if time.Now().UTC().After(ref.ExpiresAt) {
		return nil, fmt.Errorf("expired")
	}
	return &ref, nil
}

// UseReference retrieves the real token for a reference and marks it used.
// Single-use: a second call with the same reference returns an error.
func (s *store) UseReference(reference string) (*EmailReference, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	row := tx.QueryRow(`
		SELECT reference, token, expires_at, used
		FROM email_references WHERE reference = ?`, reference)

	var ref EmailReference
	var used int
	if err := row.Scan(&ref.Reference, &ref.Token, &ref.ExpiresAt, &used); err != nil {
		return nil, fmt.Errorf("reference not found")
	}
	if used == 1 {
		return nil, fmt.Errorf("reference already used")
	}
	if time.Now().UTC().After(ref.ExpiresAt) {
		return nil, fmt.Errorf("reference expired")
	}
	if _, err := tx.Exec(`UPDATE email_references SET used = 1 WHERE reference = ?`, reference); err != nil {
		return nil, err
	}
	return &ref, tx.Commit()
}

// ─────────────────────────────────────────────────────────────
// SSO state operations
// ─────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────
// CSRF operations
// ─────────────────────────────────────────────────────────────

// CreateCSRF generates a one-time token for the review form.
// Bound to a specific approval token + manager email — cannot be reused
// for a different request or by a different person.
func (s *store) CreateCSRF(approvalToken, managerEmail string) string {
	csrf := newUUID()
	expires := time.Now().UTC().Add(30 * time.Minute)
	s.db.Exec(`
		INSERT INTO csrf_tokens (token, manager, expires_at) VALUES (?, ?, ?)`,
		approvalToken+":"+csrf, managerEmail, expires,
	)
	return csrf
}

// ValidateCSRF verifies a CSRF token is valid, unexpired, and single-use.
// Returns the verified manager email so the decide handler knows who is acting.
func (s *store) ValidateCSRF(approvalToken, csrf string) (string, error) {
	key := approvalToken + ":" + csrf
	row := s.db.QueryRow(`
		SELECT manager, expires_at, used FROM csrf_tokens WHERE token = ?`, key)
	var manager string
	var expiresAt time.Time
	var used int
	if err := row.Scan(&manager, &expiresAt, &used); err != nil {
		return "", fmt.Errorf("invalid csrf")
	}
	if used == 1 {
		return "", fmt.Errorf("csrf already used")
	}
	if time.Now().UTC().After(expiresAt) {
		return "", fmt.Errorf("csrf expired")
	}
	s.db.Exec(`UPDATE csrf_tokens SET used = 1 WHERE token = ?`, key)
	return manager, nil
}

func (s *store) SaveState(state, reference string) error {
	_, err := s.db.Exec(`
		INSERT INTO sso_states (state, reference, created_at) VALUES (?, ?, ?)`,
		state, reference, time.Now().UTC(),
	)
	return err
}

func (s *store) PopState(state string) (*SSOState, error) {
	row := s.db.QueryRow(`SELECT state, reference FROM sso_states WHERE state = ?`, state)
	ss := &SSOState{}
	if err := row.Scan(&ss.State, &ss.Reference); err != nil {
		return nil, fmt.Errorf("state not found or expired")
	}
	s.db.Exec(`DELETE FROM sso_states WHERE state = ?`, state)
	return ss, nil
}

// ─────────────────────────────────────────────────────────────
// Audit log — hash-chained, append-only
// Fix 3: tamper-evident audit trail
// ─────────────────────────────────────────────────────────────

// WriteAudit appends one audit event.
// The hash field = SHA-256(event + data + timestamp + previous_hash).
// Any modification to any past record breaks the chain from that point forward.
func (s *store) WriteAudit(event string, fields map[string]string) error {
	data, _ := json.Marshal(fields)
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	prevHash := s.lastAuditHash()

	content := event + string(data) + timestamp + prevHash
	hash := sha256hex(content)

	_, err := s.db.Exec(`
		INSERT INTO audit_log (event, data, timestamp, previous_hash, hash)
		VALUES (?, ?, ?, ?, ?)`,
		event, string(data), timestamp, prevHash, hash,
	)
	return err
}

// VerifyChain walks the entire audit log and checks every hash link.
// Returns the number of records verified, or an error if tampering is detected.
// Call this from a compliance job or the /audit/verify endpoint.
func (s *store) VerifyChain() (int, error) {
	rows, err := s.db.Query(`
		SELECT id, event, data, timestamp, previous_hash, hash
		FROM audit_log ORDER BY id ASC`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	prevHash := ""
	count := 0

	for rows.Next() {
		var id int64
		var event, data, timestamp, storedPrevHash, storedHash string
		if err := rows.Scan(&id, &event, &data, &timestamp, &storedPrevHash, &storedHash); err != nil {
			return count, err
		}

		// Check the previous_hash field matches what we computed
		if storedPrevHash != prevHash {
			return count, fmt.Errorf("chain broken at record id=%d: expected previous_hash=%s got=%s",
				id, prevHash, storedPrevHash)
		}

		// Recompute this record's hash and check it matches
		content := event + data + timestamp + storedPrevHash
		expectedHash := sha256hex(content)
		if storedHash != expectedHash {
			return count, fmt.Errorf("hash mismatch at record id=%d: record was tampered with", id)
		}

		prevHash = storedHash
		count++
	}
	return count, rows.Err()
}

func (s *store) lastAuditHash() string {
	var hash string
	s.db.QueryRow(`SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&hash)
	return hash // empty string for the first record — that is correct
}

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}


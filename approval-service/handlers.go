// handlers.go — one function per HTTP endpoint.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type handlers struct {
	store *store
	cfg   config
}

// ─────────────────────────────────────────────────────────────
// Pipeline-facing endpoints (internal, X-Internal-Key required)
// ─────────────────────────────────────────────────────────────

type createRequest struct {
	Requester           string `json:"requester"`
	RequesterEmail      string `json:"requester_email"`
	ManagerEmail        string `json:"manager_email"`
	ADGroup             string `json:"ad_group"`
	Reason              string `json:"reason"`
	PipelineExecutionID string `json:"pipeline_execution_id"`
}

// create — pipeline calls this at start.
// Returns the real token (for polling) and a review_url (for the email).
// The review_url contains a short-lived reference, NOT the real token.
func (h *handlers) create(w http.ResponseWriter, r *http.Request) {
	if !h.validInternalKey(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var req createRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request body", http.StatusBadRequest)
		return
	}
	if req.Requester == "" || req.ManagerEmail == "" || req.ADGroup == "" {
		http.Error(w, "requester, manager_email and ad_group are required", http.StatusBadRequest)
		return
	}

	approval, err := h.store.Create(
		req.Requester, req.RequesterEmail,
		strings.ToLower(strings.TrimSpace(req.ManagerEmail)),
		req.ADGroup, req.Reason, req.PipelineExecutionID,
		h.cfg.TokenTTLHours,
	)
	if err != nil {
		log.Printf("ERROR create approval: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Generate a short-lived email reference.
	// This is what goes in the email URL — never the real token.
	ref, err := h.store.CreateReference(approval.Token, h.cfg.RefTTLHours)
	if err != nil {
		log.Printf("ERROR create reference: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	h.store.WriteAudit("APPROVAL_CREATED", map[string]string{
		"token_prefix":          approval.Token[:8],
		"requester":             approval.Requester,
		"ad_group":              approval.ADGroup,
		"pipeline_execution_id": approval.PipelineExecutionID,
		"ref_expires_at":        ref.ExpiresAt.Format("2006-01-02T15:04:05Z"),
	})

	reviewURL := h.cfg.BaseURL + "/approval/review/" + ref.Reference

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"token":      approval.Token,   // pipeline uses this for /status polling
		"review_url": reviewURL,        // pipeline puts this in the email — no raw token
		"expires_at": approval.ExpiresAt.Format("2006-01-02T15:04:05Z"),
	})
}

// status — pipeline polls this every 60 seconds.
func (h *handlers) status(w http.ResponseWriter, r *http.Request) {
	if !h.validInternalKey(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	token := r.PathValue("token")
	approval, err := h.store.Get(token)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"token":           approval.Token,
		"status":          approval.Status,
		"requester":       approval.Requester,
		"ad_group":        approval.ADGroup,
		"decided_by":      approval.DecidedBy,
		"decided_at":      approval.DecidedAt,
		"decided_from_ip": approval.DecidedFromIP,
	})
}

// ─────────────────────────────────────────────────────────────
// Manager-facing endpoints (public, SSO-gated)
// The email contains /approval/review/{reference}.
// The reference is opaque — it does not reveal the token or the decision.
// ─────────────────────────────────────────────────────────────

// review — manager clicks the link in their email.
// Validates the reference is still valid, then redirects to SSO.
// No state change here — GET is always read-only.
func (h *handlers) review(w http.ResponseWriter, r *http.Request) {
	reference := r.PathValue("reference")

	// Peek at the reference without consuming it
	ref, err := h.store.PeekReference(reference)
	if err != nil {
		renderHTML(w, expiredLinkPage())
		return
	}

	approval, err := h.store.Get(ref.Token)
	if err != nil || approval.Status != "pending" {
		renderHTML(w, alreadyDecidedPage(approval.Status))
		return
	}

	// Dev mode: no SSO configured — skip identity and show review page directly
	if h.cfg.SSOAuthURL == "" {
		log.Println("WARN: dev mode — skipping SSO")
		h.store.UseReference(reference)
		renderHTML(w, reviewPage(approval, reference, "dev-csrf"))
		return
	}

	// Save SSO state so the callback knows which reference this flow is for
	state := newUUID()
	if err := h.store.SaveState(state, reference); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	ssoURL := fmt.Sprintf(
		"%s?client_id=%s&response_type=code&scope=openid+email+profile&redirect_uri=%s&state=%s",
		h.cfg.SSOAuthURL,
		url.QueryEscape(h.cfg.SSOClientID),
		url.QueryEscape(h.cfg.BaseURL+"/approval/callback"),
		url.QueryEscape(state),
	)
	http.Redirect(w, r, ssoURL, http.StatusFound)
}

// ssoCallback — SSO provider sends the manager here after login.
// Verifies identity, then renders the review page (not a decision yet).
// The manager sees the request details and clicks Approve or Reject on a form.
func (h *handlers) ssoCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	pending, err := h.store.PopState(state)
	if err != nil {
		http.Error(w, "Session expired. Please click the email link again.", http.StatusBadRequest)
		return
	}

	managerEmail, err := h.exchangeCodeForEmail(code)
	if err != nil {
		log.Printf("ERROR SSO exchange: %v", err)
		http.Error(w, "SSO authentication failed. Please try again.", http.StatusBadGateway)
		return
	}

	// Consume the reference (single use)
	ref, err := h.store.UseReference(pending.Reference)
	if err != nil {
		renderHTML(w, expiredLinkPage())
		return
	}

	approval, err := h.store.Get(ref.Token)
	if err != nil || approval.Status != "pending" {
		renderHTML(w, alreadyDecidedPage(approval.Status))
		return
	}

	// Identity check: authenticated SSO user must be the designated manager
	if managerEmail != approval.ManagerEmail {
		h.store.WriteAudit("IDENTITY_MISMATCH", map[string]string{
			"token_prefix":     ref.Token[:8],
			"expected_manager": approval.ManagerEmail,
			"authenticated_as": managerEmail,
			"ip":               clientIP(r),
		})
		renderHTML(w, identityMismatchPage())
		return
	}

	// Generate a CSRF token tied to this token + manager so the decide POST
	// cannot be forged from another origin or replayed
	csrf := h.store.CreateCSRF(ref.Token, managerEmail)

	// Show the review page — manager clicks Approve or Reject here
	renderHTML(w, reviewPage(approval, ref.Token, csrf))
}

// decide — manager submits the review form (POST).
// This is the only place the approval status changes.
func (h *handlers) decide(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	token := r.FormValue("token")
	decision := r.FormValue("decision")
	csrf := r.FormValue("csrf")

	if decision != "approved" && decision != "rejected" {
		http.Error(w, "invalid decision", http.StatusBadRequest)
		return
	}

	// Validate CSRF — ensures the POST came from our review page
	managerEmail, err := h.store.ValidateCSRF(token, csrf)
	if err != nil {
		h.store.WriteAudit("CSRF_REJECTED", map[string]string{
			"token_prefix": token[:8], "ip": clientIP(r),
		})
		http.Error(w, "Invalid or expired session. Please click the email link again.", http.StatusForbidden)
		return
	}

	approval, err := h.store.Get(token)
	if err != nil || approval.Status != "pending" {
		renderHTML(w, alreadyDecidedPage(approval.Status))
		return
	}

	if err := h.store.Decide(token, decision, managerEmail, clientIP(r)); err != nil {
		http.Error(w, "Failed to record decision.", http.StatusInternalServerError)
		return
	}

	h.store.WriteAudit("APPROVAL_"+strings.ToUpper(decision), map[string]string{
		"token_prefix":          token[:8],
		"requester":             approval.Requester,
		"ad_group":              approval.ADGroup,
		"decided_by":            managerEmail,
		"decided_from_ip":       clientIP(r),
		"pipeline_execution_id": approval.PipelineExecutionID,
	})

	renderHTML(w, decisionPage(decision, approval.Requester, approval.ADGroup, managerEmail))
}

// auditVerify — internal endpoint for compliance team to verify the audit chain.
func (h *handlers) auditVerify(w http.ResponseWriter, r *http.Request) {
	if !h.validInternalKey(r) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	count, err := h.store.VerifyChain()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]any{
			"valid":            false,
			"records_verified": count,
			"error":            err.Error(),
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"valid":            true,
		"records_verified": count,
	})
}

func (h *handlers) health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ─────────────────────────────────────────────────────────────
// OAuth2 code exchange — plain net/http, easy to follow
// ─────────────────────────────────────────────────────────────

func (h *handlers) exchangeCodeForEmail(code string) (string, error) {
	resp, err := http.PostForm(h.cfg.SSOTokenURL, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {h.cfg.BaseURL + "/approval/callback"},
		"client_id":     {h.cfg.SSOClientID},
		"client_secret": {h.cfg.SSOClientSecret},
	})
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil || tokenResp.AccessToken == "" {
		return "", fmt.Errorf("could not parse access token")
	}

	req, _ := http.NewRequest("GET", h.cfg.SSOUserInfoURL, nil)
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	uiResp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("userinfo request: %w", err)
	}
	defer uiResp.Body.Close()

	body, _ := io.ReadAll(uiResp.Body)
	var info struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(body, &info); err != nil || info.Email == "" {
		return "", fmt.Errorf("could not parse email from userinfo")
	}
	return strings.ToLower(strings.TrimSpace(info.Email)), nil
}

// ─────────────────────────────────────────────────────────────
// Small helpers
// ─────────────────────────────────────────────────────────────

func (h *handlers) validInternalKey(r *http.Request) bool {
	if h.cfg.InternalAPIKey == "" {
		return true
	}
	return r.Header.Get("X-Internal-Key") == h.cfg.InternalAPIKey
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.Split(fwd, ",")[0]
	}
	return r.RemoteAddr
}

func renderHTML(w http.ResponseWriter, html string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
}

// ─────────────────────────────────────────────────────────────
// HTML pages
// ─────────────────────────────────────────────────────────────

// reviewPage shows the manager the full request details before they decide.
// The decision is made via a POST form — not a link — so there is no
// approve/reject in any URL anywhere.
func reviewPage(a *Approval, token, csrf string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Access Request Review</title></head>
<body style="font-family:sans-serif;max-width:560px;margin:60px auto">
<h2 style="color:#0052cc">Access Request — Your Approval Needed</h2>
<table style="width:100%%;border-collapse:collapse;margin:24px 0">
  <tr><td style="color:#666;padding:8px 0;width:140px">Requester</td>
      <td style="font-weight:bold">%s</td></tr>
  <tr><td style="color:#666;padding:8px 0">Email</td>
      <td>%s</td></tr>
  <tr><td style="color:#666;padding:8px 0">AD Group</td>
      <td style="font-weight:bold">%s</td></tr>
  <tr><td style="color:#666;padding:8px 0">Reason</td>
      <td>%s</td></tr>
  <tr><td style="color:#666;padding:8px 0">Requested</td>
      <td>%s</td></tr>
</table>
<form method="POST" action="/approval/decide">
  <input type="hidden" name="token" value="%s">
  <input type="hidden" name="csrf"  value="%s">
  <button name="decision" value="approved"
    style="background:#1a7f37;color:#fff;border:none;padding:12px 28px;
           font-size:15px;font-weight:bold;border-radius:4px;cursor:pointer;margin-right:12px">
    Approve
  </button>
  <button name="decision" value="rejected"
    style="background:#cf222e;color:#fff;border:none;padding:12px 28px;
           font-size:15px;font-weight:bold;border-radius:4px;cursor:pointer">
    Reject
  </button>
</form>
<p style="color:#aaa;font-size:12px;margin-top:32px">
  Your decision is recorded with your verified identity and timestamp.
</p>
</body></html>`,
		a.Requester, a.RequesterEmail, a.ADGroup, a.Reason,
		a.CreatedAt.Format("2006-01-02 15:04 UTC"),
		token, csrf,
	)
}

func decisionPage(decision, requester, adGroup, approver string) string {
	color, icon, verb := "#cf222e", "✗", "rejected"
	if decision == "approved" {
		color, icon, verb = "#1a7f37", "✓", "approved"
	}
	return fmt.Sprintf(`<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Request %s</title></head>
<body style="font-family:sans-serif;max-width:500px;margin:60px auto;text-align:center">
<div style="font-size:64px;color:%s">%s</div>
<h2 style="color:%s">Request %s</h2>
<p>Access to <strong>%s</strong> has been %s for <strong>%s</strong>.</p>
<p style="color:#666;font-size:13px">Actioned by: %s</p>
<p style="color:#aaa;font-size:12px;margin-top:40px">You can close this window.</p>
</body></html>`, verb, color, icon, color, verb, adGroup, verb, requester, approver)
}

func alreadyDecidedPage(status string) string {
	return fmt.Sprintf(`<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Already %s</title></head>
<body style="font-family:sans-serif;max-width:500px;margin:60px auto;text-align:center">
<div style="font-size:64px;color:#666">⏳</div>
<h2>Already %s</h2>
<p>This request has already been <strong>%s</strong>. No action needed.</p>
</body></html>`, status, status, status)
}

func expiredLinkPage() string {
	return `<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Link Expired</title></head>
<body style="font-family:sans-serif;max-width:500px;margin:60px auto;text-align:center">
<div style="font-size:64px;color:#666">⌛</div>
<h2>Link Expired</h2>
<p>This approval link has expired. The requester will need to submit a new request.</p>
<p style="color:#aaa;font-size:12px">Contact platform-support@company.com if you need help.</p>
</body></html>`
}

func identityMismatchPage() string {
	return `<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Not Authorised</title></head>
<body style="font-family:sans-serif;max-width:500px;margin:60px auto;text-align:center">
<div style="font-size:64px;color:#cf222e">⚠</div>
<h2 style="color:#cf222e">Not Authorised</h2>
<p>This approval was sent to a different manager.<br>
Only the designated approver can action this request.</p>
<p style="color:#aaa;font-size:12px">Contact platform-support@company.com if you think this is an error.</p>
</body></html>`
}

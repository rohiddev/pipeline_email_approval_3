# Pipeline Email Approval — Go Implementation

## What This Does

User requests AD group access via IDP.
Manager gets an email with Approve / Reject links.
Manager clicks a link, logs in via SSO — that is it.
Harness pipeline detects the decision and adds the user to the group.

No Harness account needed for the manager.
No manual steps needed for the platform team.

---

## Files

```
approval-service/
  main.go      — starts the server, registers routes
  store.go     — SQLite: create/get/decide/sso-state
  handlers.go  — one function per endpoint
  util.go      — env helpers
  go.mod       — two dependencies: uuid + sqlite3
  Dockerfile   — multi-stage Go build

pipelines/
  ad_group_access_request.yaml  — Harness pipeline (6 stages)
```

---

## How It Works — Step by Step

```
1. User submits IDP form
        │
        ▼
2. Harness Pipeline starts
   Stage 1: POST /approval/create  →  Go service returns UUID token
   Stage 2: Email sent to manager with two links:
              /approval/approve/{token}
              /approval/reject/{token}
   Stage 3: Shell script polls /approval/status/{token} every 60s
        │
        │  (manager receives email)
        ▼
3. Manager clicks Approve
   GET /approval/approve/{token}   ← no state change yet
        │
        ▼
4. Service redirects to SSO (Okta / Azure AD)
   Manager logs in with corporate credentials
        │
        ▼
5. SSO redirects back: GET /approval/callback?code=xxx&state=yyy
   Service exchanges code → access token → verified email
   Checks: verified email == manager_email on the token
   Records: status=approved, decided_by=manager@company.com, IP, timestamp
        │
        ▼
6. Harness poll detects "approved"
   Stage 4: Adds user to AD group via AD API
   Stage 5: Emails user — "you now have access"
```

---

## Security

| Control | How |
|---|---|
| Manager must be the right person | SSO verified email must match `manager_email` stored on token |
| Token cannot be reused | `Decide()` uses `WHERE status = 'pending'` — second click does nothing |
| Token is not guessable | UUID v4 = 122 bits entropy |
| State change only via POST | GET endpoints are read-only redirects |
| Audit trail | Every event logged as structured JSON with token prefix, email, IP |
| No static credentials | Delegate uses K8s service account to get short-lived Vault token |
| Internal endpoints protected | `X-Internal-Key` required on `/create` and `/status` |

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `INTERNAL_API_KEY` | prod | Key Harness sends on internal calls |
| `BASE_URL` | yes | Public base URL of this service |
| `DB_PATH` | no | SQLite file path (default `./approvals.db`) |
| `TOKEN_TTL_HOURS` | no | How long before token expires (default 48) |
| `SSO_AUTH_URL` | prod | SSO /authorize endpoint |
| `SSO_TOKEN_URL` | prod | SSO /token endpoint |
| `SSO_USERINFO_URL` | prod | SSO /userinfo endpoint |
| `SSO_CLIENT_ID` | prod | OAuth2 client ID |
| `SSO_CLIENT_SECRET` | prod | OAuth2 client secret |

Without SSO variables set, the service runs in dev mode (no identity check).

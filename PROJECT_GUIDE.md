# Project Guide — Phishing Awareness Dashboard

Quick-reference for what this repo is, how it fits together, and what's changed recently. See [PROJECT_REQUIREMENTS.md](PROJECT_REQUIREMENTS.md) for the full original spec (note: that doc describes an earlier Azure Functions version; the current code is a containerized Flask app — see "Drift from PROJECT_REQUIREMENTS.md" below).

## What this is

An internal tool for running **authorized phishing-simulation campaigns** for employee security-awareness training: send realistic phishing emails to a recipient list, track opens/clicks via a tracking pixel + fake Microsoft 365 login landing page, and report results per campaign. Explicitly for internal, authorized use only.

## Architecture

| File | Responsibility |
|---|---|
| [app.py](app.py) | Flask app — all HTTP routes: campaign CRUD, recipient management, send/resend, tracking pixel + click endpoints, landing page, CSV reports, dashboard stats, AI email generation, image upload, health check. |
| [config.py](config.py) | Loads all settings from env vars (email provider, SendGrid/SMTP, Gemini AI, Clerk keys, base URL). |
| [phishing_campaign_service.py](phishing_campaign_service.py) | SQLite data layer — `campaigns`, `recipients`, `events` tables; stats aggregation, CSV export, dedup/failure handling. |
| [gemini_service.py](gemini_service.py) | AI-generated phishing email content via Google Gemini (Vertex AI, service-account auth). |
| [auth_clerk.py](auth_clerk.py) | Clerk-based login for the admin dashboard — verifies a Clerk session, stores profile+role in the Flask session. |
| [static/admin_ui.html](static/admin_ui.html) | Single-page admin dashboard UI (served at `/api/phish/ui`). |
| [landing_page/index.html](landing_page/index.html) | Fake Microsoft 365 login page shown to phished users after they click. |
| [Dockerfile](Dockerfile) / [docker-compose.yml](docker-compose.yml) | Container build + local run config; `gunicorn` with a single worker (SQLite serializes writes at the file level, so extra workers would just cause "database is locked" errors, not real concurrency). |

## Campaign lifecycle (data flow)

1. **Create campaign** (`POST /api/phish/campaigns`) — name, subject, HTML body, redirect URL.
2. **Add recipients** (`POST .../recipients`) — each gets a unique tracking token.
3. **Send** (`POST .../send`) — dispatches via SendGrid or SMTP (Gmail/Outlook), background job with status polling (`.../send/status`), retries with backoff, optional DNS/SMTP pre-send validation.
4. **Track**:
   - `GET /api/track/open/<token>` — invisible pixel, marks `opened`.
   - `GET /api/track/click/<token>` / `/r/<token>` — marks `clicked`, redirects to the fake landing page.
   - `GET /api/phish/landing/<token>` — serves `landing_page/index.html`.
   - Bot/scanner detection (`_is_bot_request`, `_is_ms_scanner_ip`) filters out automated prefetches so stats reflect real human opens/clicks.
5. **Report** — `.../report` (CSV), `.../device-stats`, `/api/phish/dashboard` (aggregate stats).

## Auth model — current state

This is the part that's been actively changing (see git history below).

- Login is via **Clerk**. `POST /api/auth/clerk/session` verifies the browser's Clerk session and stores `{id, name, email, role}` in the Flask session.
- **Any signed-in Clerk user now defaults to the `admin` role** (`auth_clerk.py`, `role = ... or "admin"`). Per-user restriction is opt-in: set `public_metadata: {"role": "operator"|"auditor"|"template_author"}` on a specific user in the Clerk Dashboard to reduce their access.
- The permission scaffolding itself is still intact in `app.py` (`_ROLE_PERMISSIONS`, `_ROLE_LABELS`, `_can()`), it's just no longer restrictive by default — RBAC exists but isn't enforced unless configured per-user in Clerk.
- Session check header: requests must send `X-Admin-Key: clerk` plus a valid Flask session cookie (`_get_session_info` in [app.py:473](app.py:473)).

## Recent activity (git log)

The last 7 commits on `main` are a sequence titled **"Remove completely[2-7] role-based authentication"**, following an initial "Remove role-based authentication" commit. Net effect across them:
- `static/admin_ui.html` — UI-side role gating relaxed/removed.
- `auth_clerk.py` — default role changed to always resolve to `admin` for any signed-in user.
- `Dockerfile` / `entrypoint.sh` — an `entrypoint.sh` used during the transition was added then deleted again; Dockerfile now runs `gunicorn` directly as its `CMD`.
- `phishing_campaign_service.py` — a large simplification pass (~400 lines removed) alongside the auth changes.
- `config.py` / `requirements.txt` — a few settings/deps tied to the old auth flow were dropped.

Net result: the app moved from a per-role access model toward "any authenticated user is a full admin by default, with optional per-user downgrade via Clerk."

## Drift from PROJECT_REQUIREMENTS.md

The requirements doc (v2.0, July 2025) describes an **Azure Functions** deployment (`function_app.py`, Azure Storage Queue, Microsoft Graph email sender, `local.settings.json`). The current codebase is a **containerized Flask app** (`app.py`, Docker/gunicorn, SendGrid/SMTP direct send, `.env`-based config, Clerk auth instead of Entra SSO). If you're onboarding from that doc, treat it as historical context, not the current deployment target.

## Running locally

```bash
pip install -r requirements.txt
python app.py
```
Needs a `.env` (gitignored) with at minimum: `EMAIL_PROVIDER`, one of the SendGrid/SMTP credential sets, `PHISHING_BASE_URL`, `CLERK_PUBLISHABLE_KEY` + `CLERK_SECRET_KEY`, `SECRET_KEY`. Optional: `GOOGLE_SERVICE_ACCOUNT_JSON` (AI email generation).

Or via Docker:
```bash
docker-compose up --build
```

## Uncommitted local changes

`.claude/launch.json` and `.claude/settings.local.json` currently show uncommitted diffs, but they're unrelated to this app — they're Claude Code tool config that picked up entries from a different, unrelated project (a Flutter app called `tvt-website`/`true_value_talks`) sharing the same machine. Safe to leave alone or revert; not part of this project's functionality.

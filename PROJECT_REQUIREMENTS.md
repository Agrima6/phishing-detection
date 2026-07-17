# Phishing Awareness Dashboard
## Technical Requirements Document

**Version:** 2.0
**Date:** July 2025
**Prepared for:** External / Onboarding Team

---

## 1. Project Overview

The **Phishing Awareness Dashboard** is an internal security tool built on **Azure Functions (Python v2)**. It enables the security team to:

- Create and manage phishing simulation email campaigns
- Send phishing-style awareness emails to targeted employees via Microsoft Graph
- Track email opens (invisible pixel) and link clicks (built-in server-side landing page)
- View real-time statistics: sent, opened, clicked, failed, and duplicate send counts
- Download CSV reports per campaign
- Manage multiple admin users with role-based access
- Resend campaigns to recipients, clear failed/duplicate counters

> This tool is intended **solely** for authorized internal security awareness training. Do not use against targets without explicit written authorization.

---

## 2. Project Structure

```
Spam_mail_Project/
├── function_app.py              # All Azure Function routes (Python v2 decorator model)
├── phishing_campaign_service.py # SQLite service layer (all DB operations)
├── config.py                    # App settings loader
├── host.json                    # Azure Functions host config
├── local.settings.json          # Local dev environment variables (DO NOT commit)
├── requirements.txt             # Python dependencies
├── start-dev.bat                # Local development startup script
├── azure-pipeline.yaml          # CI/CD pipeline definition
├── azure_app_settings.json      # Production app settings reference
├── landing_page/
│   └── index.html               # Fake Microsoft 365 login page template (served by Azure Function)
└── static/
    └── admin_ui.html            # Single-page Admin Dashboard (served by /api/phish/ui)
```

---

## 3. Infrastructure Requirements

### 3.1 Azure Functions App
| Property | Value |
|---|---|
| Runtime | Python 3.10 or 3.11 |
| Azure Functions Version | v4 (Python programming model v2) |
| Hosting Plan | Consumption Plan (or App Service Plan) |
| Region | Central US (or as per org policy) |
| Auth Level | ANONYMOUS (auth handled by session cookie + admin key) |

All API endpoints, the Admin UI, and the phishing landing page are served from this single Function App.

---

### 3.2 Azure Storage Account
| Property | Requirement |
|---|---|
| Type | General Purpose v2 |
| Service Used | **Azure Storage Queue** |
| Queue Name | `phishing-send-queue` (configurable) |
| Purpose | Message pipe for async email dispatch (one message per recipient) |
| Local Dev | Azurite emulator (`UseDevelopmentStorage=true`) |

**Note:** In **local development**, the queue trigger is **disabled** (see `AzureWebJobs.phishing_email_dispatcher.Disabled`). Emails are dispatched inline synchronously. In **Azure production**, the queue trigger is enabled and processes each email asynchronously.

---

### 3.3 Graph Email API (Microsoft Graph Sender)
| Property | Value |
|---|---|
| Type | Existing Azure Function App (.NET) |
| Local Port | `http://localhost:7072/api/SendGraphEmailAdmin` |
| Production URL | `https://graphemailhttpfunctionqa-fxc4aaavf0c2gxgy.centralus-01.azurewebsites.net/api/SendGraphEmailAdmin` |
| Authentication | Function-level API key via `code` query param |

**Purpose:** The phishing dashboard does **not** send emails directly. It calls this Microsoft Graph sender function which delivers emails using the organization's Microsoft 365 / Exchange.

**Request payload sent by this app:**
```json
{
  "To": "recipient@company.com",
  "Subject": "Your email subject",
  "Body": "<html>...email body with tracking pixel and phishing link...</html>",
  "IsHtml": true
}
```

> **Important:** If this Azure Function App is stopped, email delivery will fail silently. Always ensure it is **Running** before sending campaigns.

---

### 3.4 Local Data Storage (SQLite)
| Property | Value |
|---|---|
| Type | SQLite (built-in Python `sqlite3`) |
| File | `phishing_data.db` (auto-created on first run) |
| Location | Function App project root |
| Schema migration | Auto-applied via `ALTER TABLE ... IF NOT EXISTS` on startup |
| Tables | `campaigns`, `recipients`, `events`, `users` |

**Schema — `campaigns` table:**
| Column | Type | Notes |
|---|---|---|
| `id` | TEXT PK | UUID |
| `name` | TEXT | Campaign name |
| `subject` | TEXT | Email subject |
| `body_html` | TEXT | Email HTML body |
| `redirect_url` | TEXT | Where to redirect after landing page interaction |
| `status` | TEXT | `draft` / `sending` / `sent` |
| `created_at` | TEXT | ISO timestamp |
| `total_sent` | INTEGER | Total emails dispatched |
| `total_opened` | INTEGER | Unique opens |
| `total_clicked` | INTEGER | Unique clicks |
| `total_failed` | INTEGER | Send failures |
| `total_duplicates` | INTEGER | Duplicate send count |

**Schema — `recipients` table:**
| Column | Type | Notes |
|---|---|---|
| `id` | TEXT PK | UUID |
| `campaign_id` | TEXT FK | → `campaigns.id` |
| `email` | TEXT | Recipient email |
| `name` | TEXT | Recipient display name |
| `tracking_token` | TEXT | Unique URL-safe 24-byte token |
| `status` | TEXT | `pending` / `sent` / `opened` / `clicked` / `failed` |
| `sent_at` | TEXT | ISO timestamp of last send |
| `opened_at` | TEXT | ISO timestamp of first open |
| `open_count` | INTEGER | Total pixel loads |
| `clicked_at` | TEXT | ISO timestamp of first click |
| `click_count` | INTEGER | Total landing page hits |
| `failed_at` | TEXT | ISO timestamp of send failure |
| `fail_reason` | TEXT | Error message from Graph API |
| `send_count` | INTEGER | Total times email was dispatched (for duplicate detection) |

**Schema — `events` table:**
| Column | Type | Notes |
|---|---|---|
| `id` | TEXT PK | UUID |
| `campaign_id` | TEXT | |
| `recipient_email` | TEXT | |
| `event_type` | TEXT | `open` / `click` / `sent` |
| `token` | TEXT | |
| `timestamp` | TEXT | ISO timestamp |

**Schema — `users` table:**
| Column | Type | Notes |
|---|---|---|
| `id` | TEXT PK | UUID |
| `username` | TEXT UNIQUE | |
| `password_hash` | TEXT | bcrypt hash |
| `role` | TEXT | `admin` / `operator` / `auditor` / `template_author` |
| `created_by` | TEXT | |
| `created_at` | TEXT | ISO timestamp |

> **Production Note:** SQLite is not persistent on Azure Consumption Plan (ephemeral local filesystem). For production, migrate to **Azure SQL**, **Azure Cosmos DB**, or **Azure Table Storage**.

---

## 4. Application Settings (Environment Variables)

Configure in **Azure Portal → Function App → Configuration → Application Settings** for production, or in `local.settings.json` for local development.

| Setting Name | Local Dev Value | Required | Description |
|---|---|---|---|
| `AzureWebJobsStorage` | `UseDevelopmentStorage=true` | Yes | Required by Azure Functions host; use Azurite locally |
| `FUNCTIONS_WORKER_RUNTIME` | `python` | Yes | Azure Functions Python runtime |
| `PHISHING_STORAGE_CONNECTION` | `UseDevelopmentStorage=true` | Yes | Storage Queue connection string |
| `PHISHING_SEND_QUEUE` | `phishing-send-queue` | Yes | Name of the Azure Storage Queue for email dispatch |
| `PHISHING_BASE_URL` | `http://localhost:7071` | Yes | Base URL of this Function App — injected into tracking pixel and landing page URLs in emails |
| `GRAPH_EMAIL_API_URL` | `http://localhost:7072/api/SendGraphEmailAdmin` | Yes | Endpoint of the Graph Email sender (include `?code=...` for production) |
| `PHISHING_ADMIN_KEY` | `localdev` | Yes | Legacy admin key (still accepted for backward compatibility) |
| `PHISHING_OPERATOR_KEY` | `operator123` | No | Role key for operator role |
| `PHISHING_AUDITOR_KEY` | `auditor123` | No | Role key for auditor role |
| `PHISHING_TEMPLATE_AUTHOR_KEY` | `template123` | No | Role key for template author role |
| `PHISHING_ADMIN_USERNAME` | `admin` | Yes | Default admin login username |
| `PHISHING_ADMIN_PASSWORD` | `Admin@123` | Yes | Default admin login password |
| `PHISHING_GITHUB_PAGES_URL` | *(empty or URL)* | No | **Legacy override only.** If set, email links point to an external GitHub Pages page instead of the built-in landing page. Leave blank to use the built-in `/api/phish/landing/{token}` page. |
| `AzureWebJobs.phishing_email_dispatcher.Disabled` | `true` | Local only | **DO NOT add to Azure.** Disables queue trigger locally so emails dispatch inline. Remove from Azure settings. |

---

## 5. Security Requirements

| Area | Requirement |
|---|---|
| Session Auth | All admin API calls require a valid session cookie obtained via `POST /api/phish/auth/login` |
| Admin Key (legacy) | `X-Admin-Key` header still accepted for backward-compatible tooling |
| Admin Key Strength | Minimum 32 random characters in production |
| HTTPS | All production traffic over HTTPS (enforced by Azure) |
| Tracking Token | Each recipient gets a 24-byte URL-safe cryptographic token (`secrets.token_urlsafe(24)`) — unguessable |
| Token Validation | All token parameters validated with `re.fullmatch(r'[A-Za-z0-9_\-]{20,60}', token)` before use |
| Landing Page Security Headers | `X-Frame-Options: DENY`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` |
| Password Hashing | User passwords hashed with **bcrypt** (via `bcrypt` library) |
| `local.settings.json` | **Must NOT** be committed to source control |
| `phishing_data.db` | **Must NOT** be committed to source control |
| `.gitignore` | Must include `*.db`, `local.settings.json`, `__pycache__/` |

---

## 6. Authentication & User Management

The system uses **session-based authentication** with a session cookie (`phishing_session`).

### Default Credentials (local dev)
- **Username:** `admin`
- **Password:** `Admin@123`

### Roles
| Role | Capabilities |
|---|---|
| `admin` | Full access — create/delete users, campaigns, send, view all |
| `operator` | Create/send campaigns, add recipients |
| `auditor` | Read-only — view campaigns, stats, CSV |
| `template_author` | Create email templates only |

### Auth Endpoints
| Endpoint | Method | Description |
|---|---|---|
| `POST /api/phish/auth/login` | POST | Login with `username`/`password` JSON body; sets session cookie |
| `POST /api/phish/auth/logout` | POST | Destroys session |
| `GET /api/phish/me` | GET | Returns current session user info |

---

## 7. Email Tracking Architecture

### 7.1 Open Tracking (1×1 Pixel)
When a campaign email is sent, a hidden tracking pixel is injected into the HTML body:
```html
<img src="https://<PHISHING_BASE_URL>/api/track/open/{token}"
     width="1" height="1" style="display:none" alt="" />
```
When the recipient opens the email, their mail client loads the image. The Function records the `open` event, increments `open_count`, and sets `opened_at` on the first open.

### 7.2 Click Tracking (Built-in Landing Page — Default)
When `PHISHING_GITHUB_PAGES_URL` is **not set**, phishing links in emails point to:
```
https://<PHISHING_BASE_URL>/api/phish/landing/{token}
```
When the recipient clicks the link:
1. The Azure Function **immediately records the click server-side** (no JavaScript needed).
2. The Function serves `landing_page/index.html` — a pixel-perfect fake Microsoft 365 login page.
3. The recipient enters their email and password (or clicks through).
4. A Security Awareness Training warning banner appears (1.5 s delay).
5. Clicking "I Understand" redirects them to the campaign's `redirect_url`.

**Advantages of server-side click recording:**
- Works even if JavaScript is blocked
- Recorded instantly on page load — not after JavaScript execution
- No cross-origin issues

### 7.3 Click Tracking (GitHub Pages — Legacy Override)
If `PHISHING_GITHUB_PAGES_URL` is set, email links append tracking parameters to that external page:
```
https://<github-pages-url>/?t={token}&api=<PHISHING_BASE_URL>&r=<redirect_url>
```
The GitHub Pages page then pings `/api/track/ping/{token}` with JavaScript. This is the legacy approach — **use the built-in landing page instead for better reliability**.

---

## 8. Built-in Landing Page (`landing_page/index.html`)

| Property | Value |
|---|---|
| File location | `landing_page/index.html` (in project root) |
| Served by | `GET /api/phish/landing/{token}` |
| Template placeholders | `__REDIRECT_URL__` and `__ORG_NAME__` — replaced server-side before sending |
| Appearance | Pixel-perfect Microsoft 365 fake login page |
| Flow | Two-step: email input → password input → loading spinner → Security Awareness Training warning |
| After warning | "I Understand" button redirects to `redirect_url` from campaign settings |
| Click recorded | **Server-side on page load** (before HTML is returned to browser) |
| Fallback | If HTML file is missing, returns a `302` redirect directly to `redirect_url` |

The file is loaded at runtime via:
```python
Path(__file__).parent / "landing_page" / "index.html"
```

This file must be included in the Azure deployment package (zip deploy, GitHub Actions, etc.).

---

## 9. Failed Mail Tracking

When the Graph API returns an error:
- Recipient `status` → `failed`, `failed_at` set, `fail_reason` stored
- Campaign `total_failed` incremented

**Clearing:** `DELETE /api/phish/campaigns/{id}/failed` resets all failed recipients back to `pending` and zeroes `total_failed`. Use this before retrying a send.

---

## 10. Duplicate Send Tracking

Each time an email is dispatched, `send_count` increments. If `send_count >= 1` before increment, the send is counted as a **duplicate** and `total_duplicates` increments.

**Clearing:** `DELETE /api/phish/campaigns/{id}/duplicates` zeroes `total_duplicates` and caps `send_count` at 1 for all recipients.

**Resend behavior:** `POST /api/phish/campaigns/{id}/resend` regenerates tracking tokens and resets sent/opened/clicked/failed counts, but **preserves `send_count`** so the subsequent resend is correctly counted as a duplicate.

---

## 11. Complete API Endpoint Reference

### UI & Auth
| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/api/phish/ui` | GET | None | Serves `static/admin_ui.html` — single-page Admin Dashboard |
| `/api/phish/auth/login` | POST | None | Login with `{username, password}` body |
| `/api/phish/auth/logout` | POST | Session | Logout and destroy session |
| `/api/phish/me` | GET | Session | Returns logged-in user info |

### Dashboard
| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/api/phish/dashboard` | GET | Session | Aggregate stats: total campaigns, sent, opened, clicked, failed, duplicates, rates |

### User Management
| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/api/phish/users` | GET | Session (admin) | List all users |
| `/api/phish/users` | POST | Session (admin) | Create new user `{username, password, role}` |
| `/api/phish/users/{user_id}` | DELETE | Session (admin) | Delete user |
| `/api/phish/users/{user_id}` | PATCH | Session (admin) | Update user password or role |

### Campaign Management
| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/api/phish/campaigns` | GET | Session | List all campaigns with stats |
| `/api/phish/campaigns` | POST | Session | Create campaign `{name, subject, body_html, redirect_url}` |
| `/api/phish/campaigns/{id}` | GET | Session | Get campaign detail + recipient list |
| `/api/phish/campaigns/{id}` | DELETE | Session | Delete campaign and all recipients/events (cascade) |

### Recipient Management
| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/api/phish/campaigns/{id}/recipients` | GET | Session | List recipients for a campaign |
| `/api/phish/campaigns/{id}/recipients` | POST | Session | Add recipients (array of `{email, name}`) |
| `/api/phish/campaigns/{id}/recipients/{rid}` | DELETE | Session | Delete a single recipient |

### Campaign Actions
| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/api/phish/campaigns/{id}/send` | POST | Session | Send campaign (dispatches emails to all pending recipients) |
| `/api/phish/campaigns/{id}/resend` | POST | Session | Resend to all recipients (resets tracking tokens, re-dispatches) |
| `/api/phish/campaigns/{id}/failed` | DELETE | Session | Clear all failed recipients (reset to pending, zero `total_failed`) |
| `/api/phish/campaigns/{id}/duplicates` | DELETE | Session | Clear duplicate counter (`total_duplicates`, cap `send_count` at 1) |
| `/api/phish/campaigns/{id}/report` | GET | Session | Download CSV report (all recipient data) |

### Tracking (Public — No Auth)
| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/api/track/open/{token}` | GET | None | Returns 1×1 transparent PNG; records email open event server-side |
| `/api/phish/landing/{token}` | GET | None | **Primary click tracking.** Records click server-side, serves fake M365 login page |
| `/api/track/click/{token}` | GET | None | **Legacy.** Records click and returns `302` redirect to `redirect_url` |
| `/api/track/ping/{token}` | GET/OPTIONS | None | **Legacy (GitHub Pages).** CORS-open beacon endpoint for external pages |

---

## 12. Service Layer Reference (`phishing_campaign_service.py`)

| Method | Description |
|---|---|
| `create_campaign(name, subject, body_html, redirect_url)` | Creates a campaign; returns new campaign dict |
| `get_campaign(campaign_id)` | Returns campaign dict or `None` |
| `delete_campaign(campaign_id)` | Cascade deletes campaign, recipients, events |
| `add_recipients(campaign_id, recipients_list)` | Bulk insert recipients; returns inserted list |
| `delete_recipient(recipient_id)` | Deletes a single recipient |
| `reset_for_resend(campaign_id)` | Regenerates tokens, resets sent/open/click/failed stats; preserves `send_count` |
| `mark_sent(campaign_id, email)` | Increments `send_count`; marks duplicate if already sent |
| `mark_failed(campaign_id, email, reason)` | Sets `status=failed`, records reason, increments `total_failed` |
| `mark_opened(token)` | Increments `open_count`, sets `opened_at` on first open |
| `mark_clicked(token)` | Increments `click_count`, sets `clicked_at` on first click |
| `get_redirect_url_for_token(token)` | Returns `redirect_url` for a tracking token |
| `clear_failed_recipients(campaign_id)` | Resets failed → pending, zeroes `total_failed` |
| `clear_duplicate_count(campaign_id)` | Zeroes `total_duplicates`, caps `send_count` at 1 |
| `get_dashboard_stats(campaign_id)` | Returns aggregate stats dict for a campaign |
| `create_user(username, password, role, created_by)` | Creates user with bcrypt-hashed password |
| `delete_user(user_id)` | Deletes user by ID |
| `reset_user_password(user_id, new_password)` | Updates bcrypt hash |

---

## 13. Admin Dashboard UI (`static/admin_ui.html`)

Single-page application served at `/api/phish/ui`. No external framework dependencies — pure HTML/CSS/JS.

### Dashboard KPIs
- Total Campaigns
- Emails Sent
- Emails Opened
- Average Open Rate
- **Duplicate Sends** (purple)

### Campaign List Table Columns
Name · Subject · Status · Total · Sent · Opened · Clicked · **Failed** (red) · **Duplicates** (purple) · Open Rate · Actions

### Campaign List Actions
View · Send · CSV · 🗑️ Delete Campaign · 🧹 Dups(N) *(when > 0)*

### Campaign Detail KPIs
Total · Sent · Opened · Clicked · **Failed** (red) · **Duplicate Sends** (purple) · Open Rate · Click Rate

### Campaign Detail Header Buttons
Add Recipients · Send Campaign · Resend All · 🧹 Clear Duplicates *(when > 0)* · 🧹 Clear Failed *(when > 0)* · CSV Report · Delete Campaign

### Recipient Table Columns
Email · Name · Status · Sent At · Opened At · Opens · Clicked At · Clicks · **Sends** (purple — shows `N ⚠️` when > 1) · Delete

### Statistics Pie Chart
5 slices: Clicked Link (red) · Opened No Click (amber) · Sent Not Opened (blue) · Pending (gray) · Failed (dark red)

### Auto-Refresh
- Campaign detail page: every **20 seconds**
- Campaigns list page: every **30 seconds**

---

## 14. Local Development Setup

### Prerequisites
| Tool | Version | Notes |
|---|---|---|
| Python | 3.10 or 3.11 | Must match Azure runtime |
| Azure Functions Core Tools | v4 | `npm install -g azure-functions-core-tools@4` |
| Azurite | Latest | `npm install -g azurite` — local Azure Storage emulator |
| .NET 6+ SDK | Optional | Only needed if running Graph Email function locally |

### Steps
```bash
# 1. Start Azurite emulator (Storage Queue)
npx azurite --silent

# 2. (Optional) Start Graph Email function locally
cd ../GraphEmailHttpFunction
func start --port 7072

# 3. Start the Phishing Dashboard function
cd Spam_mail_Project
start-dev.bat        # or: func start --port 7071
```

### Access Points
| URL | Description |
|---|---|
| `http://localhost:7071/api/phish/ui` | Admin Dashboard |
| `http://localhost:7071/api/phish/landing/{token}` | Landing page preview |
| `http://localhost:7071/api/track/open/{token}` | Tracking pixel test |

---

## 15. Azure Deployment Notes

### Deployment Checklist
- [ ] Set `PHISHING_BASE_URL` to `https://<funcapp>.azurewebsites.net` in Azure App Settings
- [ ] Set `GRAPH_EMAIL_API_URL` to production URL including `?code=<function-key>`
- [ ] Set `PHISHING_STORAGE_CONNECTION` to real Azure Storage connection string
- [ ] Set `PHISHING_ADMIN_PASSWORD` to a strong password in App Settings
- [ ] **Remove** `AzureWebJobs.phishing_email_dispatcher.Disabled` from production App Settings
- [ ] Include `landing_page/index.html` in the deployment zip
- [ ] **Do not deploy** `local.settings.json` or `phishing_data.db`
- [ ] Enable HTTPS-only in Azure Function App settings
- [ ] Review SQLite persistence — consider migration to Azure SQL or Cosmos DB for production

### File Inclusion in Deployment
The `landing_page/` folder must be part of the deployment package. When using zip deploy or GitHub Actions, ensure your `.funcignore` / `zipDeploy` settings do **not** exclude this folder.

---

## 16. Known Limitations & Production Considerations

| Issue | Detail | Recommendation |
|---|---|---|
| SQLite persistence | Azure Consumption Plan has ephemeral local storage — DB lost on cold start / scale-out | Migrate to Azure SQL or Cosmos DB |
| Open tracking | Many modern email clients block external images by default | Cannot be avoided; only opens with image loading enabled are tracked |
| Click tracking reliability | Server-side click at page load time — very reliable | No action needed |
| PHISHING_BASE_URL | Must be public URL for tracking to work; localhost only works for local UI testing | Set to Azure Function URL in production |
| Queue trigger | Disabled locally (`AzureWebJobs...Disabled=true`) — always remove this from Azure settings | Do not copy `local.settings.json` to Azure |
| Gemini AI templates | If `GEMINI_API_KEY` is not set, template generation in the UI will silently fail | Set in App Settings if AI campaign generation is needed |

---

## 17. Dependencies Summary

| Dependency | Type | Mandatory | Notes |
|---|---|---|---|
| Azure Functions v4 | Platform | Yes | Python 3.10/3.11 runtime |
| Azure Storage Account | Cloud Service | Yes | For Storage Queue |
| Graph Email API (existing .NET function) | External Azure Function | Yes | Must be running and reachable |
| SQLite (`sqlite3`) | Built-in Python library | Yes | Zero installation needed |
| `azure-functions` | Python package | Yes | Azure Functions SDK |
| `azure-storage-queue` | Python package | Yes | Queue client for async email dispatch |
| `requests` | Python package | Yes | HTTP client for Graph API calls |
| `bcrypt` | Python package | Yes | Password hashing for user accounts |
| `landing_page/index.html` | Static HTML template | Yes | Phishing landing page served by the Function |
| `static/admin_ui.html` | Static HTML | Yes | Admin Dashboard single-page app |

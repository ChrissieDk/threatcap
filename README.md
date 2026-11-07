# Threatwatch

Threatwatch is a free, self-hosted developer security intelligence dashboard. It ingests vulnerability advisories and vendor incident feeds from public sources, normalizes and de-duplicates them, scores and ranks them, and tells you what matters for the technologies and dependencies **you** actually use, in the app and through outbound alerts.

No paid services are required. Everything runs on PostgreSQL, a .NET API and a Next.js frontend.

## Contents

- [Features](#features)
- [How it works](#how-it-works)
- [Monorepo layout](#monorepo-layout)
- [Setup](#prerequisites)
- [Configuration](#environment-variables)
- [Projects](#projects-dependency-matching) and [Alerts](#alerts)
- [Notifications](#notifications)
- [Severity and priority scoring](#severity-and-priority-scoring)
- [Data retention](#data-retention)
- [Deploying](#deploying-free-self-hosted)
- [API](#api)
- [Development and tests](#development-and-tests)
- [Data sources](#data-sources)
- [Roadmap](#roadmap)

## Features

- **Vulnerability explorer.** Browse, search and filter advisories (CVE, GHSA, RUSTSEC, Go, malicious-package `MAL-` entries and more) by severity, ecosystem, technology and known-exploited status, with a detail page per advisory showing affected packages, fixed versions, aliases, references and a timeline of events.
- **Priority ranking.** Every advisory gets a priority score combining CVSS, EPSS exploit probability and CISA KEV status, so the most urgent items rise to the top.
- **Act now.** A ranked list of the highest-priority issues in your stack over the last 7 days, including findings from your projects.
- **Overview dashboard.** Summary counts, a daily activity chart and your project findings at a glance.
- **Technology catalog and following.** Follow specific technologies or whole ecosystems; every feed (Act now, incidents, notifications, alerts) is scoped to what you follow.
- **Vendor incidents.** Outages and security incidents from public status pages (GitHub, npm, PyPI, Cloudflare, Docker), filtered to what you follow.
- **Projects.** Drop in `package.json`, lockfiles, `.csproj`, `go.mod`, SBOMs and more (or paste them) and see which advisories hit the exact versions you run, with the version to upgrade to. Backend and frontend projects are supported.
- **Outbound alerts.** Web Push, ntfy (phone), email and webhooks, with a guided one-click setup, idempotent delivery, batching or daily digests, and SSRF protection.
- **In-app notification bell.** A short, ranked list of what needs attention, shown with the reason it matters, that never nags twice about the same thing.
- **Accounts.** Email-and-password accounts with lockout, email verification and HttpOnly sessions.
- **Self-managing data.** Scheduled retention keeps the database bounded; one-time repairs fix historical data.

## How it works

```
 CISA KEV ─┐
 OSV.dev ──┼─► ingestion workers ─► normalize / de-dupe / score ─► PostgreSQL ─► .NET API ─► Next.js UI
 EPSS ─────┤                                                          │
 Status    │                                                          └─► alert dispatcher ─► push / ntfy / email / webhook
 pages ────┘
```

1. **Ingestion workers** poll each provider on an interval and upsert advisories keyed on a canonical ID, merging aliases (a CVE and its GHSA become one record).
2. **Scoring** computes the CVSS base score, applies EPSS and KEV, and stores a priority score.
3. **Matching** links advisories to technologies (by product/package) and to project dependencies (by ecosystem, package name and version range).
4. **Delivery** happens in two ways: the API serves the UI, and the alert dispatcher pushes matches to your channels.
5. **Retention** prunes stale data daily.

The browser only ever talks to the Next.js server on its own origin. That server attaches the API key and forwards the session cookie, so the API key never reaches the browser.

## Monorepo layout

- `web/`: Next.js 16 frontend (React, TypeScript, Tailwind, shadcn/ui; pnpm)
- `api/`: .NET 8 backend
  - `api/src/Threatwatch.Core`: entities, EF Core `ThreatwatchDbContext` and migrations, query and domain services (alerts, projects, notifications, scoring)
  - `api/src/Threatwatch.Ingestion`: providers (CISA KEV, OSV, EPSS, status pages), the alert dispatcher and background workers (ingestion, severity repair, retention)
  - `api/src/Threatwatch.Api`: ASP.NET Core Web API (controllers, auth, OpenAPI)
  - `api/tests/Threatwatch.Tests`: xUnit tests (EF Core InMemory)
- `docker-compose.yml`: PostgreSQL 17 and Mailpit (local mail catcher)

## Prerequisites

- Node.js 20+ and pnpm
- .NET 8 SDK
- PostgreSQL 15+ — or Docker (a `docker-compose.yml` with PostgreSQL 17 is included)

## Setup

1. **Start PostgreSQL** (or use an existing instance):

   ```sh
   docker compose up -d
   ```

   Or create the database manually:

   ```sh
   psql -U postgres -c "CREATE USER threatwatch WITH PASSWORD 'threatwatch';"
   psql -U postgres -c "CREATE DATABASE threatwatch OWNER threatwatch;"
   ```

2. **Create a local API key** (gitignored; the API will not start without it):

   ```sh
   KEY=$(openssl rand -base64 32)
   mkdir -p api/src/Threatwatch.Api
   printf '{\n  "Auth": { "ApiKey": "%s" }\n}\n' "$KEY" > api/src/Threatwatch.Api/appsettings.Development.local.json
   printf 'API_URL=http://localhost:5080\nAPI_KEY=%s\n' "$KEY" > web/.env.local
   ```

3. **Run the EF Core migration**:

   ```sh
   cd api && dotnet ef database update --project src/Threatwatch.Core --startup-project src/Threatwatch.Api
   ```

4. **Run the API**:

   ```sh
   cd api && dotnet run --project src/Threatwatch.Api
   ```

   The API listens on http://localhost:5080. On startup it seeds the technology catalog and the ingestion worker begins syncing CISA KEV and OSV advisories modified in the last 90 days. Every `/api/v1` route requires the API key. Signed-in user routes also require a session cookie.

5. **Run the frontend and create an account**:

   ```sh
   cd web && pnpm dev
   ```

   The frontend is served on http://localhost:3000. Open http://localhost:3000/register and create an account. Browser calls stay on that origin; the Next.js server attaches `API_KEY` and forwards the session cookie. Passwords must be 12–128 characters and include uppercase, lowercase, a number, and a symbol. Email addresses are checked for shape at sign-up; verify yours from Preferences to enable email alerts (requires SMTP).

## Environment variables

| Variable | Where | Description |
|---|---|---|
| `ConnectionStrings__DefaultConnection` | api | PostgreSQL connection string (env-var override for `ConnectionStrings:DefaultConnection`; a local default is in `appsettings.json`) |
| `Auth__ApiKey` | api | Required. Bearer token for every `/api/v1` route. Locally this lives in `api/src/Threatwatch.Api/appsettings.Development.local.json` (gitignored). At least 16 characters. |
| `Ingestion__AutoStart` | api | Optional (default `true`). Start syncing feeds on boot. Set `false` to stay idle until a signed-in user triggers a sync. |
| `Ingestion__PollSeconds` | api | Optional (default `30`). How often the worker checks for due providers. |
| `OSV_BACKFILL_DIR` | api | Optional. Directory of extracted OSV JSON files to import on startup. The worker already pulls advisories modified in the last 90 days from the public GCS bucket. |
| `API_URL` | web | Optional server-side base URL of the API (default: `http://localhost:5080`). Not exposed to the browser. |
| `API_KEY` | web | Required server-side copy of `Auth__ApiKey`, in `web/.env.local` (gitignored). The browser calls same-origin `/api/v1/*`, and Next.js attaches this key. |

Accounts use ASP.NET Core Identity. Passwords are hashed with Identity's PBKDF2 hasher and are not stored. The browser keeps an HttpOnly `threatwatch.session` cookie (SameSite=Lax, 7-day sliding session). Five failed sign-ins lock the account for 15 minutes. Data-protection keys for the cookie are written to `api/src/Threatwatch.Api/data-protection-keys/` and are gitignored.

## Projects (dependency matching)

Under **Projects**, drop in your dependency files and Threatwatch lists the known vulnerabilities that affect the **exact versions you use**, with the version to upgrade to. New advisories that hit a project also trigger your alerts (even for packages you do not follow), and an alert names the project, the package version and the fix.

Supported files: `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` (npm); `requirements.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock` (PyPI); `*.csproj`, `Directory.Packages.props`, `packages.config` (NuGet); `go.mod`; `Cargo.toml`, `Cargo.lock`; `pom.xml` (Maven); and CycloneDX or SPDX JSON SBOMs, which cover any of those ecosystems. You can also paste a file's contents instead of uploading it. A project can combine several files, for example a frontend `package.json` plus its lockfile and a backend `.csproj`. Adding a file with an existing name replaces it.

- **Exact vs declared versions.** A lockfile (or a pinned version) gives an exact result. A manifest alone only gives a range such as `^4.17.0`; Threatwatch checks its lowest version and marks the result as approximate.
- **How matching works.** Versions are compared with each ecosystem's ordering (semver, NuGet, simplified PEP 440, approximated Maven) against the OSV affected ranges stored for each advisory. Advisories whose ranges are only git commits, and dependencies without a version, cannot be checked and are counted as "version unknown".
- **Privacy and safety.** Only the dependency names and versions are stored; the files themselves are discarded. Uploads are capped (10 files, 5 MB each, 20 projects per user), XML is parsed with DTDs disabled, and projects are only visible to their owner.

## Alerts

New users land on **Preferences** after registering, where a three-step setup asks what they follow, how urgent alerts should be (*Only urgent*, *Balanced* or *Everything*, with a custom editor underneath), and where to receive them. A banner nudges anyone who has not connected a channel yet. Alerts only cover technologies the user follows, and a channel never receives items published before its rules were created.

| Channel | Setup for the user | Needs from the operator |
|---|---|---|
| This browser (Web Push) | One click on **Enable**, then accept the browser prompt. Works on desktop and Android; on iOS the site must be added to the home screen first. | Nothing. VAPID keys are generated on first run and stored encrypted in the database. Browsers require https (localhost is fine). |
| Phone (ntfy) | One click on **Set up**, then scan a QR code with the free ntfy app. The server generates a random secret topic. | Nothing (defaults to ntfy.sh). Set `Alerts__NtfyServerUrl` to use your own server. |
| Email | **Verify email**, then **Email me**. | SMTP (`Smtp__*`). Hidden until configured. |
| Webhook / custom ntfy URL | Under **Advanced**. Slack, Discord, Mattermost or any JSON endpoint. | Nothing. |

**Email verification.** With SMTP configured, registration sends a confirmation link (valid 24 hours, built on ASP.NET Identity tokens). Sign-in is never blocked; verification only gates the email channel, so nobody can make the server mail an address they do not own. Users can request a new link from Preferences (limited to one per minute).

**Security.** Destination URLs and push keys are encrypted at rest with ASP.NET Data Protection and never returned by the API (the ntfy topic is shown again only to its owner, for setup). Outbound calls require https, refuse private, loopback and link-local addresses (re-checked at connect time against DNS rebinding), do not follow redirects, and ignore system proxies. Push subscription endpoints get the same checks. A channel that fails eight times in a row, or whose browser subscription was revoked, is disabled. For a self-hosted ntfy on a trusted network, set `Alerts__AllowPrivateTargets=true`.

| Variable | Description |
|---|---|
| `Alerts__WebBaseUrl` | Public URL of the web app, used for links in alerts and verification emails (default `http://localhost:3000`). |
| `Alerts__NtfyServerUrl` | ntfy server for one-click phone alerts (default `https://ntfy.sh`). |
| `Alerts__PushSubject` | Contact for push services, a `mailto:` or `https:` URL. Defaults to `Alerts__WebBaseUrl` when that is https. Set this in production. |
| `Alerts__AllowPrivateTargets` | Allow http and private-network targets (default `false`). |
| `Alerts__PollSeconds` | How often to look for new matches (default `60`). |
| `Smtp__Host`, `Smtp__Port`, `Smtp__Security`, `Smtp__Username`, `Smtp__Password`, `Smtp__From`, `Smtp__FromName` | SMTP settings. `Smtp__Security` is `StartTls` (default), `Ssl` or `None` (e.g. Mailpit locally). |

**Trying email locally.** `docker compose up -d` also starts Mailpit. Add `"Smtp": { "Host": "localhost", "Port": 1025, "Security": "None", "From": "alerts@threatwatch.local" }` to `appsettings.Development.local.json`, restart the API, and read every message at http://localhost:8025.

**Real email.** Point `Smtp__*` at any SMTP server, for example Gmail (`smtp.gmail.com`, port 587, `StartTls`, your address and a Google app password) or a self-hosted server.

Apply pending migrations with `dotnet ef database update` before starting the API.

## Pages

| Page | What it shows |
|---|---|
| Overview | Summary counts, daily activity and project findings |
| Act now | Highest-priority vulnerabilities in your stack over the last 7 days |
| Vulnerabilities | Searchable, filterable explorer plus a detail page per advisory |
| Incidents | Vendor outages and security incidents for the technologies you follow (last 30 days; unresolved ones always shown) |
| Technologies / Following | The catalog, and what you follow |
| Projects | Your dependency files and the advisories that hit your exact versions |
| Preferences | Alert rules and channels, email verification |
| Discussions | Placeholder, not implemented yet |

## Notifications

The bell in the header is derived at read time from your follows, your alert rules and your projects, so there is nothing to clear and no backlog to build up.

- **What qualifies.** A version-checked hit on one of your projects always qualifies and says why (for example "Affects my-app: lodash 4.17.20 (fixed in 4.17.21)"). Otherwise an item must belong to a technology you follow and pass your alert rules (default: High and above, or known-exploited). Follows of a whole ecosystem only count for known-exploited or Critical items.
- **Ranking and cap.** Items are ranked by known-exploited, project match, severity, then recency, and the bell shows the top 10 with a "Top N of M" footer linking to Act now and Preferences.
- **Read state.** Opening the bell marks everything seen. Items that were new when you opened it keep a blue dot until you close it, and the badge caps at "9+".

## Severity and priority scoring

- **CVSS.** CVSS v3.0 and v3.1 base scores are calculated exactly from the vector string (including the 3.1 round-up rule). Severity bands are Critical (9.0+), High (7.0+), Medium (4.0+), Low and None.
- **Fallbacks.** If an advisory has no usable v3 vector, a plain numeric score is used, then the label from the source (for example GitHub's `database_specific.severity`). CVSS v4 vectors cannot be scored locally yet, so a v4-only advisory without a label stays **Unknown**.
- **Priority score.** `base x (1 + EPSS) x (2 if known-exploited)`, where `base` is the CVSS score, else the midpoint of the severity band, else 7.0 for a known-exploited advisory with no rating. Advisories are sorted by this score in Act now.
- **Repair.** Earlier versions stored the CVSS version number as the score, so nothing ever reached High. A one-time repair (`repair.severity.v1`) runs at API start before ingestion: it rescored v3 rows from their vectors, clears bogus v4 scores, recomputes priorities and resets the OSV watermark so labels are re-read on the next sync.

## Data retention

Ingestion only limits what each sync reads, so a `RetentionService` prunes stored data once a day. It starts in **dry-run mode**: it logs what it would remove and deletes nothing until you set `Retention__DryRun=false`.

| Rule | Default | Notes |
|---|---|---|
| Stale advisories | 180 days since last modification | Known-exploited advisories and advisories affecting a package in any user's project are kept. Keep this above `Osv__RetentionDays` so pruned items are not re-imported. |
| Withdrawn advisories | 30 days since last modification | Removed even if otherwise protected. |
| Events | 90 days | Update, fix-available and severity-change events. First-seen and known-exploited events are kept. |
| Resolved incidents | 180 days after resolution | Open incidents are never removed. |
| Alert deliveries | 30 days | Handled by the alert dispatcher. |

Deleting an advisory also removes its packages, aliases, references and events.

| Variable | Default | Description |
|---|---|---|
| `Retention__Enabled` | `true` | Turn the worker off entirely. |
| `Retention__DryRun` | `true` | Log only; set `false` to actually delete. |
| `Retention__AdvisoryDays` | `180` | Stale advisory limit. |
| `Retention__WithdrawnDays` | `30` | Withdrawn advisory limit. |
| `Retention__EventDays` | `90` | Event limit. |
| `Retention__ResolvedIncidentDays` | `180` | Resolved incident limit. |
| `Retention__IntervalHours` | `24` | How often it runs. |
| `Osv__RetentionDays` | `90` | How far back each OSV sync reads. |

## API

In the Development environment the OpenAPI document is at http://localhost:5080/openapi/v1.json, with a Swagger UI at http://localhost:5080/openapi. Every route requires the API key as a bearer token; signed-in routes also need the session cookie.

| Area | Routes under `/api/v1` |
|---|---|
| Auth | `auth/register`, `auth/login`, `auth/logout`, `auth/me`, `auth/verify-email/send`, `auth/verify-email/confirm` |
| Vulnerabilities | `vulnerabilities`, `vulnerabilities/{id}` |
| Dashboard | `dashboard/summary`, `dashboard/daily`, `dashboard/act-now` |
| Incidents | `incidents` |
| Technologies and follows | `technologies`, `technologies/{slug}`, `follows` (GET, POST, `POST/DELETE follows/{slug}`) |
| Projects | `projects`, `projects/overview`, `projects/supported-files`, `projects/{id}` (GET, DELETE), `projects/{id}/files` (PUT) |
| Alerts | `alerts`, `alerts/preferences`, `alerts/channels` (+ `push`, `{id}`, `{id}/setup`, `{id}/test`) |
| Notifications | `notifications`, `notifications/read` |
| Ingestion and health | `ingestion/sync` (GET, POST), `health/providers` |

## Deploying (free, self-hosted)

The production stack is `docker-compose.prod.yml`: Postgres, the API, the web app and Caddy. Caddy is the only service that publishes ports (80 and 443); it fetches and renews a Let's Encrypt certificate automatically. It fits an always-free VM (for example Oracle Cloud Always Free ARM). Any DNS provider works, since only an A record is needed.

1. **VM.** Create an Ubuntu VM with a reserved public IP, install Docker, enable automatic security updates, allow SSH only with keys (`PasswordAuthentication no`, `PermitRootLogin no`), and open only ports 22, 80 and 443 (in the cloud security list and the host firewall).
2. **DNS.** Add an `A` record for your hostname (for example `threatwatch.example.co.za`) pointing to the VM's IP. If you also have an AAAA record, point it at the VM or remove it.
3. **Configure.** `cp .env.production.example .env`, fill it in (`openssl rand -base64 32` for the passwords and API key), and `chmod 600 .env`.
4. **Start.** `docker compose -f docker-compose.prod.yml up -d --build`. The API applies migrations on start (`Database__MigrateOnStartup`).
5. **First account.** Sign-up is closed by default. Set `REGISTRATION_OPEN=true` (optionally with `INVITE_CODE=...`), restart, register, then close it again if the site is private.
6. **Retention.** Check the log for the dry-run line, then set `Retention__DryRun=false` in the compose file's API environment.
7. **Backups.** Schedule `deploy/backup.sh` with cron. It writes an encrypted `pg_dump` plus the Data Protection keys (without the keys, sessions and encrypted alert channels cannot be recovered) and copies them off the server with rclone if configured.

**Built-in hardening.** Containers run read-only with all capabilities dropped and `no-new-privileges`; the API and database are reachable only on the internal Docker network; the web app sets HSTS, a strict CSP, `frame-ancestors 'none'`, `nosniff`, a referrer policy and a permissions policy; session cookies are HttpOnly, SameSite=Lax and Secure; login and sign-up are rate limited per client address (Caddy sets the forwarded address and drops client-supplied ones); invite codes are compared in constant time. CI runs the tests, type-check, lint and a dependency audit, and Dependabot opens weekly update PRs.

Cloudflare's free plan (DDoS protection, WAF, tunnel) would add a layer in front of this, but it does not accept every domain, including `.co.za`. Without it, consider `fail2ban` on the host for SSH.

| Variable | Description |
|---|---|
| `Auth__RegistrationOpen` | Allow new accounts (default `true`; the production compose file defaults to `false`). |
| `Auth__InviteCode` | If set, sign-up requires this code. |
| `Database__MigrateOnStartup` | Apply EF migrations when the API starts (default `false`). |
| `Cors__Origin` | Public web origin (default `http://localhost:3000`). |

## Development and tests

```sh
cd api && dotnet test          # xUnit, EF Core InMemory
cd web && pnpm test            # vitest
cd web && pnpm exec tsc --noEmit && pnpm lint
```

Add a migration with `dotnet ef migrations add <Name> --project src/Threatwatch.Core --startup-project src/Threatwatch.Api` (run from `api/`). Apply pending migrations before starting the API, or pages that need new tables will fail to load.

## Data sources

- [OSV.dev](https://osv.dev/): open vulnerability database. Each sync reads advisories modified in the last 90 days (configurable).
- [CISA Known Exploited Vulnerabilities (KEV) Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog): vulnerabilities known to be actively exploited in the wild.
- [EPSS](https://www.first.org/epss/): daily exploit-probability scores from FIRST.
- Public [Atlassian Statuspage](https://www.atlassian.com/software/statuspage) JSON (`/api/v2/incidents.json`) for GitHub, npm, PyPI, Cloudflare and Docker. No API key. AWS Health and NuGet are omitted because they have no equivalent free public feed.

## Roadmap

Implemented: ingestion (KEV, OSV, EPSS, status pages), scoring and prioritisation, accounts, follows, project dependency matching, outbound alerts, notifications, retention.

Not implemented yet:

- CVSS v4 base-score calculation (v4-only advisories without a source label stay Unknown)
- NVD and GitHub Advisory enrichment
- Discussions and comments on advisories
- A "High and above" severity filter in the vulnerability explorer (the current filter matches one level exactly)

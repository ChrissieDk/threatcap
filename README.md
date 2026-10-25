# Threatwatch

Threatwatch is a developer security intelligence dashboard: it ingests vulnerability data from public feeds, normalizes and deduplicates it, and presents it through a web UI so developers can see what affects the technologies they use.

## Monorepo layout

- `web/` — Next.js frontend (React, TypeScript)
- `api/` — .NET 8 backend
  - `api/src/Threatwatch.Core` — entities, EF Core `ThreatwatchDbContext`, seed data
  - `api/src/Threatwatch.Ingestion` — ingestion providers and background workers (CISA KEV, OSV)
  - `api/src/Threatwatch.Api` — ASP.NET Core Web API
  - `api/tests/Threatwatch.Tests` — xUnit tests (EF Core InMemory)

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

   The frontend is served on http://localhost:3000. Open http://localhost:3000/register and create an account. Browser calls stay on that origin; the Next.js server attaches `API_KEY` and forwards the session cookie. Passwords must be 12–128 characters and include uppercase, lowercase, a number, and a symbol. Email addresses are checked for shape only — no verification message is sent.

## Environment variables

| Variable | Where | Description |
|---|---|---|
| `ConnectionStrings__DefaultConnection` | api | PostgreSQL connection string (env-var override for `ConnectionStrings:DefaultConnection`; a local default is in `appsettings.json`) |
| `Auth__ApiKey` | api | Required. Bearer token for every `/api/v1` route. Locally this lives in `api/src/Threatwatch.Api/appsettings.Development.local.json` (gitignored). At least 16 characters. |
| `OSV_BACKFILL_DIR` | api | Optional. Directory of extracted OSV JSON files to import on startup. The worker already pulls advisories modified in the last 90 days from the public GCS bucket. |
| `API_URL` | web | Optional server-side base URL of the API (default: `http://localhost:5080`). Not exposed to the browser. |
| `API_KEY` | web | Required server-side copy of `Auth__ApiKey`, in `web/.env.local` (gitignored). The browser calls same-origin `/api/v1/*`, and Next.js attaches this key. |

Accounts use ASP.NET Core Identity. Passwords are hashed with Identity's PBKDF2 hasher and are not stored. The browser keeps an HttpOnly `threatwatch.session` cookie (SameSite=Lax, 7-day sliding session). Five failed sign-ins lock the account for 15 minutes. Data-protection keys for the cookie are written to `api/src/Threatwatch.Api/data-protection-keys/` and are gitignored.

## API documentation

In the Development environment the OpenAPI document is available at http://localhost:5080/openapi/v1.json, with a Swagger UI at http://localhost:5080/openapi.

## Data sources

- [OSV.dev](https://osv.dev/) — open vulnerability database. Only advisories modified in the last 90 days are stored.
- [CISA Known Exploited Vulnerabilities (KEV) Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — vulnerabilities known to be actively exploited in the wild
- Public [Atlassian Statuspage](https://www.atlassian.com/software/statuspage) JSON (`/api/v2/incidents.json`) for GitHub, npm, PyPI, Cloudflare, and Docker. No API key. AWS Health and NuGet are omitted because they have no equivalent free public feed.

## Current status / roadmap

Threatwatch is in **Phase 1**: vulnerability ingestion (CISA KEV + OSV), deduplication/upsert logic, email-and-password accounts, followable technologies, and the dashboard UI for browsing advisories.

Accounts are stored in the `Users` table (`Id`, `Email`, `DisplayName`, `CreatedAt`, plus Identity columns). Follows are stored in `UserFollows`.

Planned for future phases (not implemented yet):

- NVD and GitHub Advisory enrichment
- Discussions/comments on advisories

# ClickToKnow - Web Technology Detection and Attack Vector Mapping

Passive web analysis platform that accepts a target URL, detects technology stack signals, discovers endpoints, and maps possible attack vectors per endpoint.

Use only on systems you are authorized to assess.

## What It Does
- Accepts a target URL and starts an automated scan.
- Detects stack signals for:
  - Frontend technologies (HTML, CSS, JavaScript, React, Angular, Vue, Next.js, Nuxt.js, Svelte, jQuery, Bootstrap, TailwindCSS, Material UI, etc.)
  - Backend technologies (Node.js, Java/Spring, Python, PHP/Laravel/WordPress, .NET, Rails, Go, etc.)
  - Server technologies (Nginx, Apache, IIS, Tomcat, Cloudflare, etc.)
  - Possible database signals (MySQL, PostgreSQL, Oracle, MongoDB, SQL Server)
- Discovers endpoints from:
  - Page URLs (links/navigation)
  - API paths and GraphQL routes
  - Form actions
  - JavaScript-discovered routes
  - File upload routes
  - WebSocket routes
- Maps possible attack vectors by category (heuristic/passive):
  - Injection
  - Authentication and Access
  - Web Security
  - Architecture Risks
  - Infrastructure
  - Cloud Security
- Runs advanced passive recon in `fun()`:
  - `robots.txt` and sitemap harvesting
  - DNS resolution profile
  - TLS certificate profile (for HTTPS targets)
  - security header posture scoring
  - content profile (forms/scripts/external domains)
  - endpoint insight analytics (methods, sources, parameter frequency, risky endpoints)

## Tech Stack
- Backend: FastAPI + Playwright (Python)
- Frontend: Static HTML/CSS/JavaScript

## Setup

### Backend
1. `cd backend`
2. `pip install -r requirements.txt`
3. `playwright install chromium`
4. `python main.py`
5. API runs on `http://localhost:8000`

### Frontend
1. Open `frontend/index.html` in a browser (or serve the folder with any static server).
2. Ensure backend is running at `http://localhost:8000`.

## API
- `POST /scan` starts background scanning and returns a `scan_id`.
- `GET /scan/{scan_id}` returns in-progress/final results.
- `POST /fun` runs the enhanced core analysis workflow directly and returns:
  - detected technologies
  - `technology_details` (confidence + evidence signals for each detected language/framework/server/database)
  - discovered endpoints
  - endpoint catalog (`pages`, `api`, `forms`, `js_routes`, `file_upload`, `websocket`)
  - possible attack vectors per endpoint
  - `capability_matrix` (50-feature scan capability status list with evidence)
  - summary breakdown
  - advanced recon data (`dns`, `tls`, `security_headers`, `content_profile`, `discovery`, `endpoint_insights`)

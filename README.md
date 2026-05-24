# Reverse proxy demonstration with RBAC admin panel

Monorepo for a two-server lab (upstream + proxy/RBAC) and two Android TV clients.

| Component | Folder | Host URL | Emulator URL |
|-----------|--------|----------|----------------|
| Upstream API | `upstream-service/` | http://localhost:5001 | http://10.0.2.2:5001 |
| Proxy + RBAC panel | `proxy-gateway/` | http://localhost:5002 | http://10.0.2.2:5002 |
| Reference client (direct upstream) | `reference-client/` | — | uses :5001 |
| Brokered client (via proxy) | `brokered-client/` | — | uses :5002 |

```
  reference-client ──► :5001  upstream-service
                              ▲
  brokered-client ───► :5002  proxy-gateway ──► upstream-service
```

Shared pool credentials for upstream auth (see `proxy-gateway/integrations.py`): `username1234` / `password1234`.

## Quick Start

1. Start backend services:

```bash
docker compose up --build
```

This starts:

- **upstream-service** on http://localhost:5001
- **proxy-gateway** on http://localhost:5002 (admin panel: http://localhost:5002/panel)

2. Open **Android Studio**.

3. Import one client at a time:

- `reference-client/`
- `brokered-client/`

4. Run the app on an **Android emulator** (official AVD).

5. Use these emulator base URLs (already set in each app’s `strings.xml`):

- **Upstream** (reference client): http://10.0.2.2:5001
- **Proxy** (brokered client): http://10.0.2.2:5002

On **Genymotion**, change `api_base_url` in `app/src/main/res/values/strings.xml` to `http://10.0.3.2:5001` or `:5002` as needed.

## Local development (without Docker)

One-time setup from the repo root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r proxy-gateway\requirements.txt
pip install -r upstream-service\requirements.txt
```

**Two terminals** from the repo root (venv activated in each):

| Terminal | Command | URL |
|----------|---------|-----|
| 1 | `python app.py upstream` | http://localhost:5001 |
| 2 | `python app.py proxy` | http://localhost:5002/panel |

Start **upstream** before **proxy**.

macOS/Linux: same commands with `python3 app.py upstream` / `proxy`.

Alternative — run inside each folder:

```powershell
cd upstream-service; $env:PORT="5001"; python app.py
cd proxy-gateway; $env:PORT="5002"; $env:UPSTREAM_API_BASE="http://127.0.0.1:5001"; python app.py
```

## Repository layout

```text
├── docker-compose.yml
├── upstream-service/     Mock provider API
├── proxy-gateway/        Reverse proxy + RBAC admin panel
├── reference-client/     Android — talks to upstream :5001
└── brokered-client/      Android — talks to proxy :5002
```

## Production

See `proxy-gateway/DEPLOYMENT.md`.

## GitHub

https://github.com/Shawns0826/reverse-proxy-demonstration-with-rbac-admin-panel

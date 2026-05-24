# proxy-gateway

Flask reverse proxy, local auth/JWT, hierarchical RBAC admin panel, and credit distribution.

- **Port:** 5002 (host) / `http://proxy-gateway:5002` (Compose network)
- **Panel:** http://localhost:5002/panel
- **Upstream:** `UPSTREAM_API_BASE` → `http://upstream-service:5001` in Docker

See the [repository README](../README.md) for `docker compose up`.

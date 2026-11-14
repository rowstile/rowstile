---
paths:
  - "examples/**"
---

# examples/: the adopters

The three apps built on rowstile's public surface alone, and what their tests need.

- `examples/filemanager/` — the first adopter (uses only the public surface, `check_public_surface.py`):
  `db/` (migrations, `policy.authz`, `migrate.py`), `backend/` (FastAPI, uv), `frontend/` (React, Vite),
  `docker-compose.yml` (rowstile image from this repo, RustFS); `test.sh` runs its tests
- `examples/messenger/` — the second adopter, a WhatsApp-style app built to show what rowstile takes off an app
  (same stack and rules as the file manager: public surface only, `check_public_surface.py`); `test.sh` runs its tests
- `examples/helpdesk/` — the third adopter, several companies' support desks on one database (a multi-tenant
  Next.js app on Prisma and the TypeScript SDK, live updates through Electric; public surface only,
  `check_public_surface.py`); `test.sh` runs its tests
- `examples/public_surface.py` — the one public-surface check every example runs (each one's
  `check_public_surface.py` calls it on its folder): what is public, and how a name is matched

- Adopters' `test.sh` start from an empty database (`docker compose down -v`): migrations must work before the
  first apply (`authz.uid()` doesn't exist yet: use plpgsql bodies).

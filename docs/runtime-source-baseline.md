# 233 runtime source baseline

Captured on 2026-07-26 from the active `netops-platform-api` deployment on server 233.

- Canonical deployed NetOps route: `platform-adapter/anbo_wx/backend/app/routes/netops2026.py`.
- The route is loaded by the existing `anbo_wx` Flask application; it is not a standalone service.
- The root `ops_platform_api.py` remains the module development source and verification companion. Any deployment must reconcile it with the captured canonical route before replacing files on 233.
- The companion navigation, verification and start scripts are stored under `platform-adapter/anbo_wx/backend/`.

No `.env`, `.netops2026.json`, database content, backups, logs, virtual environments, or credentials were copied.

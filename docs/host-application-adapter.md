# Host application adapter

The active Platform API is a Flask blueprint hosted by the NetOps platform host. Its canonical deployable route is stored in `platform-adapter/host-application/backend/app/routes/netops2026.py`.

The historical source host was called `anbo_wx`; that name has deliberately been removed from the repository layout. Production target paths are `/srv/netops/netops-littleProgram` and `/srv/netops/netops-platform-api`.

The adapter uses `/api/netops2026/` only; `/wx/api/netops2026/` is removed during cutover. It must not carry runtime environment files, shared secrets, database passwords, uploads, logs, backups, or virtual environments.

#!/bin/sh
set -eu
BACKEND=/srv/netops/netops-littleProgram/backend
PIDFILE=$BACKEND/logs/netops7001.pid
if test -f "$PIDFILE"; then
  PID=$(cat "$PIDFILE" 2>/dev/null || true)
  if test -n "$PID" && kill -0 "$PID" 2>/dev/null; then
    exit 0
  fi
fi
cd "$BACKEND"
nohup ./.venv/bin/python run.py >> logs/netops7001.log 2>&1 &
echo $! > "$PIDFILE"

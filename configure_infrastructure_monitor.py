"""Add the local infrastructure monitor token to the platform's private config."""
from __future__ import annotations

import json
import os
from pathlib import Path


config_path = Path(os.getenv("NETOPS2026_CONFIG", "/home/yvesyuan/.netops2026.json"))
token_path = Path(os.getenv("NETOPS_INFRASTRUCTURE_TOKEN_FILE", "/home/yvesyuan/.netops-infra-monitor-token"))
payload = json.loads(config_path.read_text(encoding="utf-8"))
payload.setdefault("infrastructure", {})["token"] = token_path.read_text(encoding="utf-8").strip()
temporary = config_path.with_suffix(config_path.suffix + ".infra.tmp")
temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
os.chmod(temporary, 0o600)
temporary.replace(config_path)
print("infrastructure_monitor_configured=true")

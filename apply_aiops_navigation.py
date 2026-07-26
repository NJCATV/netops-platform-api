"""Idempotently seed the unified AIOps navigation and enable task mutations.

Run from the deployed platform backend directory so its ``app`` package and
production configuration are used.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from app import create_app
from app.extensions import db
from app.models import AppMenu


MENU_ROWS = (
    ("netops.aiops", "AIOps 智能运维", "BrainCircuit", "/aiops", "智能运维", "normal_user", 70, "AIOps 看板和运维中心入口"),
    ("netops.ai_assistant", "AI 问答", "Bot", "/ai-assistant", "智能运维", "normal_user", 71, "独立 AI 运维问答入口"),
    ("netops.aiops_knowledge", "知识库", "DatabaseZap", "/aiops/knowledge", "智能运维", "normal_user", 72, "AIOps 故障知识库入口"),
    ("netops.aiops_admin", "AIOps 系统管理", "MonitorCog", "/aiops/admin", "系统管理", "org_admin", 90, "模型、运行参数和审计统一入口"),
    ("netops.system_audit", "系统审计与使用分析", "ChartNoAxesCombined", "/system-audit", "系统管理", "super_admin", 95, "仅超级管理员可查看登录、功能使用与平台审计日志"),
)


def seed_menus() -> None:
    app = create_app()
    with app.app_context():
        for key, name, icon, path, group, role, order, remark in MENU_ROWS:
            item = AppMenu.query.filter_by(menu_key=key).one_or_none() or AppMenu(menu_key=key)
            item.name = name
            item.icon = icon
            item.path = path
            item.group_name = group
            item.min_role = role
            item.user_type = "internal"
            item.enabled = True
            item.sort_order = order
            item.remark = remark
            db.session.add(item)
        db.session.commit()
        print("menus=" + ",".join(row[0] for row in MENU_ROWS))


def enable_task_mutations() -> None:
    config_path = Path(os.getenv("NETOPS2026_CONFIG", "/home/yvesyuan/.netops2026.json"))
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    payload.setdefault("aiops", {})["task_mutations_enabled"] = True
    temporary = config_path.with_suffix(config_path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(config_path)
    print("task_mutations_enabled=true")


if __name__ == "__main__":
    seed_menus()
    enable_task_mutations()

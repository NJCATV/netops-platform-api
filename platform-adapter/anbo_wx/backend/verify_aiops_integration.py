"""Production-safe, read-only acceptance check for the embedded AIOps BFF."""

from __future__ import annotations

from app import create_app
from app.extensions import db
from app.models import User
from app.utils.jwt import create_access_token


def choose_users():
    users = User.query.filter_by(status="active").order_by(User.id).all()
    anbo = [
        {"id": user.id, "role": user.role_code, "user_type": user.user_type, "org": user.to_public_dict().get("org_name")}
        for user in users
        if "安播中心" in str(user.to_public_dict().get("org_name") or "")
    ]
    print(f"anbo_candidates={anbo}")
    chosen = []
    predicates = (
        ("management", lambda user: user.role_code in ("org_admin", "super_admin")),
        ("anbo_staff", lambda user: "安播中心" in str(user.to_public_dict().get("org_name") or "")),
        ("other_staff", lambda user: user.role_code == "normal_user" and "安播中心" not in str(user.to_public_dict().get("org_name") or "")),
    )
    for label, predicate in predicates:
        match = next((user for user in users if predicate(user)), None)
        if match is not None:
            chosen.append((label, match))
    return chosen


def main() -> None:
    app = create_app()
    with app.app_context():
        client = app.test_client()
        for label, user in choose_users():
            token = create_access_token(user.id)
            headers = {"Authorization": f"Bearer {token}"}
            navigation = client.get("/api/netops2026/navigation", headers=headers)
            navigation_data = navigation.get_json(silent=True) or {}
            items = (navigation_data.get("data") or {}).get("items") or []
            ai_keys = sorted(item["menu_key"] for item in items if str(item.get("menu_key", "")).startswith(("netops.aiops", "netops.ai_assistant")))
            overview = client.get("/api/netops2026/aiops/runtime/overview?hours=24", headers=headers)
            body = overview.get_json(silent=True) or {}
            windows = body.get("windows") or (body.get("data") or {}).get("windows") or []
            window = next((item for item in windows if item.get("hours") == 24), {})
            print(
                f"{label}: role={user.role_code} org={user.to_public_dict().get('org_name')} "
                f"menus={ai_keys} overview={overview.status_code} "
                f"syslog={window.get('syslog_parsed')} trap={window.get('trap_raw')} events={window.get('alarm_events')}"
            )
            if label != "other_staff":
                assert navigation.status_code == 200 and overview.status_code == 200
                assert window.get("syslog_parsed", 0) > 0
                runs = client.get("/api/netops2026/aiops/ai-runs?limit=5", headers=headers)
                tasks = client.get("/api/netops2026/aiops/report-tasks", headers=headers)
                knowledge = client.get("/api/netops2026/aiops/fault-kb/summary", headers=headers)
                qq_status = client.get("/api/netops2026/aiops/system/qq-bot-status", headers=headers)
                qq_body = qq_status.get_json(silent=True) or {}
                qq_data = qq_body.get("data") or qq_body
                task_body = tasks.get_json(silent=True) or {}
                task_items = task_body.get("items") or (task_body.get("data") or {}).get("items") or []
                knowledge_body = knowledge.get_json(silent=True) or {}
                knowledge_data = knowledge_body.get("data") or knowledge_body
                print(
                    f"  runs={runs.status_code} tasks={tasks.status_code}/{len(task_items)} "
                    f"knowledge={knowledge.status_code}/{knowledge_data.get('formal_report_count')},"
                    f"{knowledge_data.get('repair_count')},{knowledge_data.get('document_count')},"
                    f"{knowledge_data.get('topic_count')} qq={qq_status.status_code}/{qq_data.get('status') or qq_data.get('online')}"
                )
                assert runs.status_code == tasks.status_code == knowledge.status_code == 200
                assert task_items
                assert all(knowledge_data.get(key, 0) > 0 for key in ("formal_report_count", "repair_count", "document_count", "topic_count"))
                assert qq_status.status_code == 200
                if user.role_code in ("org_admin", "super_admin"):
                    audit_statuses = {
                        path: client.get(f"/api/netops2026/aiops/{path}?limit=2", headers=headers).status_code
                        for path in ("fault-kb/chat/logs", "system/qq-audit-logs", "system/operation-logs", "system/login-logs")
                    }
                    print(f"  audit={audit_statuses}")
                    assert all(status == 200 for status in audit_statuses.values())
                    bindings = client.get("/api/netops2026/aiops/llm/usage-bindings", headers=headers)
                    binding_body = bindings.get_json(silent=True) or {}
                    binding_items = binding_body.get("items") or (binding_body.get("data") or {}).get("items") or []
                    print(f"  bindings={bindings.status_code} top_keys={sorted(binding_body)} data_keys={sorted((binding_body.get('data') or {}))}")
                    assert bindings.status_code == 200 and binding_items
                    print(f"  manual_model={binding_items[0]['model_pk']} configured")
            else:
                assert not ai_keys and overview.status_code == 403


if __name__ == "__main__":
    main()

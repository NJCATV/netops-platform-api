"""Inspect the exact production admin account navigation and permissions."""

from app import create_app
from app.models import AppMenu, User
from app.utils.jwt import create_access_token


def main() -> None:
    app = create_app()
    with app.app_context():
        users = User.query.order_by(User.id).all()
        matches = []
        for user in users:
            public = user.to_public_dict()
            if any(str(value or "").lower() == "admin" for value in public.values()):
                matches.append((user, public))
        if not matches:
            raise RuntimeError("active internal admin account not found")
        print({"configured_menus": [(item.menu_key, item.user_type, item.min_role, item.enabled) for item in AppMenu.query.filter(AppMenu.menu_key.like("netops.%")).order_by(AppMenu.id).all()]})
        client = app.test_client()
        for user, public in matches:
            headers = {"Authorization": f"Bearer {create_access_token(user.id)}"}
            response = client.get("/api/netops2026/navigation", headers=headers)
            body = response.get_json(silent=True) or {}
            items = (body.get("data") or {}).get("items") or []
            overview = client.get("/api/netops2026/aiops/runtime/overview?hours=24", headers=headers)
            import_probe = client.post(
                "/api/netops2026/aiops/fault-kb/import/upload",
                headers=headers,
                data={},
                content_type="multipart/form-data",
            )
            print(
                {
                    "id": user.id,
                    "account": public.get("oss_account") or public.get("account") or public.get("mobile") or public.get("real_name"),
                    "role": user.role_code,
                    "user_type": user.user_type,
                    "user_status": user.status,
                    "org": public.get("org_name"),
                    "status": response.status_code,
                    "aiops_overview": overview.status_code,
                    "import_probe": import_probe.status_code,
                    "menus": [(item.get("group_name"), item.get("menu_key"), item.get("path")) for item in items],
                }
            )
            keys = {item.get("menu_key") for item in items}
            required = {
                "netops.dashboard", "netops.onu_search", "netops.quality", "netops.performance",
                "netops.collector", "netops.devices", "netops.hfc", "netops.aiops",
                "netops.ai_assistant", "netops.aiops_knowledge", "netops.aiops_admin",
            }
            assert response.status_code == 200 and required <= keys
            assert overview.status_code == 200
            assert import_probe.status_code == 400


if __name__ == "__main__":
    main()

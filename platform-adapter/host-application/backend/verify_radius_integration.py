"""Production acceptance checks for Radius navigation, auth and ClickHouse APIs."""

from app import create_app
from app.models import User
from app.utils.jwt import create_access_token


PATHS = (
    "/api/netops2026/radius/overview?hours=1",
    "/api/netops2026/radius/records?event_type=auth&hours=1&page_size=2",
    "/api/netops2026/radius/records?event_type=control&hours=1&page_size=2",
    "/api/netops2026/radius/analytics?hours=1",
    "/api/netops2026/radius/risk/reject?hours=1&limit=2",
    "/api/netops2026/radius/risk/multi-mac?hours=1&limit=2",
    "/api/netops2026/radius/accounting?hours=1",
    "/api/netops2026/radius/ingest/status",
    "/api/netops2026/radius/profile?keyword=GDF2795313",
    "/api/netops2026/onu/search?type=terminal_mac&keyword=68:dd:b7:c7:51:11",
)


def main():
    app = create_app()
    with app.app_context():
        admin = User.query.filter_by(role_code="super_admin", status="active").first()
        if not admin:
            raise RuntimeError("active super_admin not found")
        client = app.test_client()
        unauth = client.get(PATHS[0])
        assert unauth.status_code in (401, 403), unauth.get_data(as_text=True)
        headers = {"Authorization": f"Bearer {create_access_token(admin.id)}"}
        navigation = client.get("/api/netops2026/navigation", headers=headers)
        assert navigation.status_code == 200
        items = ((navigation.get_json() or {}).get("data") or {}).get("items") or []
        assert "netops.radius" in {item.get("menu_key") for item in items}
        statuses = {}
        for path in PATHS:
            response = client.get(path, headers=headers)
            statuses[path] = response.status_code
            assert response.status_code == 200, response.get_data(as_text=True)[:1000]
        overview = client.get(PATHS[0], headers=headers).get_json()["data"]["overview"]
        assert int(overview.get("auth_total") or 0) > 0
        profile = client.get(
            "/api/netops2026/radius/profile?keyword=GDF2795313", headers=headers
        ).get_json()["data"]
        assert profile.get("matched") is True
        assert profile.get("identity", {}).get("accounts")
        terminal = client.get(PATHS[-1], headers=headers).get_json()["data"]
        resolution = terminal.get("terminal_resolution") or {}
        assert resolution.get("terminal_mac_norm") == "68ddb7c75111"
        assert "GDF2795313" in (resolution.get("verified_accounts") or [])
        assert resolution.get("status") == "olt_mapping_unavailable"
        assert resolution.get("expected_onus")
        export = client.get(
            "/api/netops2026/radius/export.csv?event_type=auth&hours=1",
            headers=headers,
        )
        assert export.status_code == 200
        assert export.mimetype == "text/csv"
        normal = User.query.filter_by(role_code="normal_user", user_type="internal", status="active").first()
        normal_status = None
        if normal:
            normal_headers = {"Authorization": f"Bearer {create_access_token(normal.id)}"}
            normal_status = client.get(PATHS[0], headers=normal_headers).status_code
            assert normal_status == 200
        print({
            "unauthenticated": unauth.status_code,
            "menu": "netops.radius",
            "statuses": statuses,
            "auth_total_1h": overview.get("auth_total"),
            "accounting_total_1h": overview.get("accounting_total"),
            "latest_event_time": overview.get("latest_event_time"),
            "profile_health": profile.get("health"),
            "terminal_path_status": resolution.get("status"),
            "csv_export": export.status_code,
            "normal_internal_user": normal_status,
        })


if __name__ == "__main__":
    main()

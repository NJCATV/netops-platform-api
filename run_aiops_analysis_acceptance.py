"""Start one real AIOps analysis through the production BFF and await persistence."""

from __future__ import annotations

import time
import os

from app import create_app
from app.models import User
from app.utils.jwt import create_access_token


def unwrap(response):
    body = response.get_json(silent=True) or {}
    return body.get("data") or body


def main() -> None:
    app = create_app()
    with app.app_context():
        user = User.query.filter(User.status == "active", User.role_code.in_(("org_admin", "super_admin"))).order_by(User.id).first()
        if user is None:
            raise RuntimeError("no active management user")
        headers = {"Authorization": f"Bearer {create_access_token(user.id)}", "Content-Type": "application/json"}
        client = app.test_client()
        run_uid = os.getenv("AIOPS_RUN_UID")
        if not run_uid:
            created = client.post(
                "/api/netops2026/aiops/ai-runs",
                headers=headers,
                json={"hours": 4, "max_tool_rounds": 2, "save_to_db": True},
            )
            payload = unwrap(created)
            run_uid = payload.get("run_uid") or (payload.get("item") or {}).get("run_uid")
            if created.status_code not in (200, 201, 202) or not run_uid:
                raise RuntimeError(f"analysis start failed: status={created.status_code} keys={sorted(payload)}")
            print(f"started run_uid={run_uid}", flush=True)
        else:
            print(f"resuming run_uid={run_uid}", flush=True)
        for attempt in range(90):
            time.sleep(10)
            response = client.get(f"/api/netops2026/aiops/ai-runs/{run_uid}", headers=headers)
            item = unwrap(response).get("item") or unwrap(response)
            status = item.get("status")
            if attempt % 3 == 0 or status in ("success", "failed"):
                print(f"poll={attempt + 1} status={status}", flush=True)
            if status in ("success", "failed"):
                finding_total = sum(len(item.get(key) or []) for key in ("must_handle", "watch", "correlations", "recovered", "next_actions", "noise", "insufficient"))
                print(
                    f"finished status={status} title={item.get('overall_title')} "
                    f"findings={item.get('finding_count') or finding_total} error={item.get('error_message')}",
                    flush=True,
                )
                if status != "success":
                    raise RuntimeError("analysis did not persist successfully")
                return
        raise TimeoutError("analysis did not finish within 15 minutes")


if __name__ == "__main__":
    main()

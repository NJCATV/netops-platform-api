"""Idempotently add the Radius management entry to the unified platform."""

from app import create_app
from app.extensions import db
from app.models import AppMenu


def main():
    app = create_app()
    with app.app_context():
        item = AppMenu.query.filter_by(menu_key="netops.radius").one_or_none() or AppMenu(menu_key="netops.radius")
        item.name = "Radius 管理"
        item.icon = "ShieldCheck"
        item.path = "/radius"
        item.group_name = "Radius 管理"
        item.min_role = "normal_user"
        item.user_type = "internal"
        item.enabled = True
        item.sort_order = 60
        item.remark = "Radius 认证、风险、Accounting 流量和采集链路统一入口"
        db.session.add(item)
        db.session.commit()
        print("menu=netops.radius enabled=true")


if __name__ == "__main__":
    main()

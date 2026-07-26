"""Seed the super-admin infrastructure monitor navigation item."""
from app import create_app
from app.extensions import db
from app.models import AppMenu


def main():
    app = create_app()
    with app.app_context():
        item = AppMenu.query.filter_by(menu_key="netops.infrastructure").one_or_none() or AppMenu(menu_key="netops.infrastructure")
        item.name = "基础设施监控"
        item.icon = "ServerCog"
        item.path = "/infrastructure"
        item.group_name = "系统管理"
        item.min_role = "super_admin"
        item.user_type = "internal"
        item.enabled = True
        item.sort_order = 96
        item.remark = "超级管理员查看服务器资源、服务健康和运维管理入口"
        db.session.add(item)
        db.session.commit()
        print("menu=netops.infrastructure")


if __name__ == "__main__":
    main()

from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from decimal import Decimal
import base64
import csv
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import socket
import threading
import time
import zipfile
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape as xml_escape
from urllib import error as urlerror, parse, request as urlrequest

import pymysql
from flask import Blueprint, Response, current_app, g, request
from sqlalchemy import false, func, or_, text
from werkzeug.security import check_password_hash

from app.services.auth_service import change_password as base_change_password, login as base_login
from app.services.permission_service import next_action_for_user
from app.extensions import db
from app.models import AppMenu, OperationLog, OrgUnit, User
from app.utils.decorators import login_required
from app.utils.responses import BAD_REQUEST, SERVER_ERROR, UNAUTHORIZED, fail, success


netops2026_bp = Blueprint("netops2026", __name__, url_prefix="/api/netops2026")


_USAGE_AUDIT_SCHEMA_READY = False


def ensure_usage_audit_schema():
    """Create the platform-local audit store without recording request payloads."""
    global _USAGE_AUDIT_SCHEMA_READY
    if _USAGE_AUDIT_SCHEMA_READY:
        return
    execute_write(
        """
        CREATE TABLE IF NOT EXISTS netops2026_usage_audit_log (
          id BIGINT PRIMARY KEY AUTO_INCREMENT,
          occurred_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
          user_id BIGINT NULL,
          username VARCHAR(128) NULL,
          display_name VARCHAR(128) NULL,
          role_code VARCHAR(32) NULL,
          org_name VARCHAR(128) NULL,
          module VARCHAR(48) NOT NULL,
          action VARCHAR(96) NOT NULL,
          method VARCHAR(12) NOT NULL,
          request_path VARCHAR(255) NOT NULL,
          result VARCHAR(16) NOT NULL,
          status_code SMALLINT NOT NULL,
          duration_ms INT NULL,
          client_ip VARCHAR(64) NULL,
          user_agent VARCHAR(255) NULL,
          KEY idx_usage_audit_time (occurred_at),
          KEY idx_usage_audit_user_time (user_id, occurred_at),
          KEY idx_usage_audit_module_time (module, occurred_at),
          KEY idx_usage_audit_action_time (action, occurred_at),
          KEY idx_usage_audit_result_time (result, occurred_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """
    )
    _USAGE_AUDIT_SCHEMA_READY = True


def backfill_platform_audit_history():
    """Bring existing platform login/operation records into the unified view once."""
    marker_path = "/__system_audit_backfill__"
    marker = query_one("SELECT id FROM netops2026_usage_audit_log WHERE request_path=%s LIMIT 1", (marker_path,))
    if marker:
        return {"login_count": 0, "operation_count": 0, "already_backfilled": True}
    login_rows = db.session.execute(text("""
        SELECT l.id, l.user_id, l.login_account, l.login_ip, l.result, l.fail_reason, l.created_at,
               u.real_name, u.oa_username, u.mobile, u.role_code
        FROM login_logs l LEFT JOIN users u ON u.id=l.user_id
        ORDER BY l.created_at DESC, l.id DESC LIMIT 2000
    """)).mappings().all()
    operation_rows = db.session.execute(text("""
        SELECT o.id, o.user_id, o.module, o.action, o.ip, o.created_at,
               u.real_name, u.oa_username, u.mobile, u.role_code
        FROM operation_logs o LEFT JOIN users u ON u.id=o.user_id
        ORDER BY o.created_at DESC, o.id DESC LIMIT 2000
    """)).mappings().all()
    inserted_logins = 0
    inserted_operations = 0
    with mysql_conn() as conn:
        with conn.cursor() as cur:
            for row in login_rows:
                result_text = str(row.get("result") or "").lower()
                result = "success" if result_text in ("success", "ok", "passed", "1", "true") else "failed"
                cur.execute(
                    """
                    INSERT INTO netops2026_usage_audit_log
                    (occurred_at,user_id,username,display_name,role_code,module,action,method,request_path,result,status_code,duration_ms,client_ip,user_agent)
                    VALUES (%s,%s,%s,%s,%s,'auth','login','POST',%s,%s,%s,NULL,%s,NULL)
                    """,
                    (
                        row.get("created_at"), row.get("user_id"), row.get("oa_username") or row.get("mobile") or row.get("login_account"),
                        row.get("real_name"), row.get("role_code"), "/historical/login/%s" % row["id"], result,
                        200 if result == "success" else 401, row.get("login_ip"),
                    ),
                )
                inserted_logins += 1
            for row in operation_rows:
                module = str(row.get("module") or "platform")[:48]
                action = str(row.get("action") or "operation")[:96]
                cur.execute(
                    """
                    INSERT INTO netops2026_usage_audit_log
                    (occurred_at,user_id,username,display_name,role_code,module,action,method,request_path,result,status_code,duration_ms,client_ip,user_agent)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,'POST',%s,'success',200,NULL,%s,NULL)
                    """,
                    (
                        row.get("created_at"), row.get("user_id"), row.get("oa_username") or row.get("mobile"), row.get("real_name"),
                        row.get("role_code"), module, action, "/historical/operation/%s" % row["id"], row.get("ip"),
                    ),
                )
                inserted_operations += 1
            cur.execute(
                """
                INSERT INTO netops2026_usage_audit_log
                (occurred_at,module,action,method,request_path,result,status_code)
                VALUES (NOW(),'system_audit','historical_backfill','SYSTEM',%s,'success',200)
                """,
                (marker_path,),
            )
        conn.commit()
    return {"login_count": inserted_logins, "operation_count": inserted_operations, "already_backfilled": False}


def normalized_audit_path(path):
    clean = "/" + str(path or "").strip("/")
    return re.sub(r"/\d+(?=/|$)", "/:id", clean)


def audit_module_for_path(path):
    if path.startswith("/auth/"):
        return "auth"
    if path.startswith("/aiops/"):
        return "aiops"
    if path.startswith("/radius/"):
        return "radius"
    if path.startswith("/collector/"):
        return "collector"
    if path.startswith(("/onu/", "/quality")):
        return "onu"
    if path.startswith(("/olt/", "/performance")):
        return "olt"
    if path.startswith(("/cm/", "/cmts/")):
        return "hfc"
    if path.startswith("/boss/"):
        return "boss"
    if path.startswith(("/access/", "/user-orgs/", "/device-orgs/", "/organization-mappings")):
        return "access"
    if path.startswith("/settings"):
        return "settings"
    if path.startswith("/system/audit"):
        return "system_audit"
    if path.startswith("/dashboard"):
        return "dashboard"
    return "platform"


def audit_action_for_request(path, method):
    method = str(method or "GET").upper()
    if path == "/auth/login":
        return "login"
    if path == "/auth/change-password":
        return "change_password"
    if path == "/aiops/ai-runs" and method == "POST":
        return "run_ai_analysis"
    if path == "/aiops/fault-kb/chat" and method == "POST":
        return "ai_chat"
    if path == "/onu/quality-daily/export":
        return "export_quality_excel"
    if path == "/boss/users/import" and method == "POST":
        return "import_boss_users"
    if path == "/dashboard/presence":
        return "dashboard_visit"
    return method.lower() + ":" + normalized_audit_path(path).strip("/").replace("/", ".")


def audit_actor():
    user = getattr(g, "current_user", None)
    if user is not None:
        public = user.to_public_dict()
        return {
            "user_id": getattr(user, "id", None),
            "username": public.get("oa_username") or public.get("mobile") or public.get("oss_account"),
            "display_name": public.get("real_name") or public.get("name"),
            "role_code": getattr(user, "role_code", None),
            "org_name": public.get("org_name"),
        }
    if request.path.endswith("/auth/login"):
        payload = request.get_json(silent=True) or {}
        return {"user_id": None, "username": str(payload.get("account") or "").strip() or None, "display_name": None, "role_code": None, "org_name": None}
    return {"user_id": None, "username": None, "display_name": None, "role_code": None, "org_name": None}


@netops2026_bp.before_request
def start_usage_audit_timer():
    g.netops2026_audit_started_at = time.monotonic()


@netops2026_bp.after_request
def record_platform_usage(response):
    """Audit the outcome and route only; never persist passwords, tokens, query values, or bodies."""
    try:
        relative_path = request.path.replace(netops2026_bp.url_prefix, "", 1) or "/"
        # Bootstrap probes happen on every page load and would distort feature usage.
        if relative_path in ("/auth/me", "/navigation"):
            return response
        if relative_path == "/dashboard/presence":
            payload = request.get_json(silent=True) or {}
            if not payload.get("visit"):
                return response
        started_at = getattr(g, "netops2026_audit_started_at", None)
        duration_ms = int((time.monotonic() - started_at) * 1000) if started_at else None
        status_code = int(response.status_code)
        result = "success" if status_code < 400 else ("denied" if status_code in (401, 403) else "failed")
        actor = audit_actor()
        ensure_usage_audit_schema()
        execute_write(
            """
            INSERT INTO netops2026_usage_audit_log
            (user_id,username,display_name,role_code,org_name,module,action,method,request_path,result,status_code,duration_ms,client_ip,user_agent)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """,
            (
                actor["user_id"], actor["username"], actor["display_name"], actor["role_code"], actor["org_name"],
                audit_module_for_path(relative_path), audit_action_for_request(relative_path, request.method), request.method.upper(),
                normalized_audit_path(relative_path), result, status_code, duration_ms, request.remote_addr,
                (request.user_agent.string or "")[:255],
            ),
        )
    except Exception as exc:
        current_app.logger.warning("Platform usage audit write failed: %s", exc)
    return response


def _secret_config():
    path = os.getenv("NETOPS2026_CONFIG", "/home/yvesyuan/.netops2026.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return {}


def _mysql_conf():
    cfg = _secret_config().get("mysql", {})
    return {
        "host": cfg.get("host", os.getenv("GO_COLLECTOR_MYSQL_HOST", "172.31.1.236")),
        "port": int(cfg.get("port", os.getenv("GO_COLLECTOR_MYSQL_PORT", "3339"))),
        "user": cfg.get("user", os.getenv("GO_COLLECTOR_MYSQL_USER", "go_collector")),
        "password": cfg.get("password", os.getenv("GO_COLLECTOR_MYSQL_PASSWORD", "")),
        "database": cfg.get("database", os.getenv("GO_COLLECTOR_MYSQL_DB", "go_collector")),
        "charset": "utf8mb4",
        "cursorclass": pymysql.cursors.DictCursor,
        "connect_timeout": 5,
        "read_timeout": 30,
        "write_timeout": 10,
    }


def mysql_conn():
    return pymysql.connect(**_mysql_conf())


def query_all(sql, args=None):
    with mysql_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, args or ())
            return cur.fetchall()


def query_one(sql, args=None):
    rows = query_all(sql, args)
    return rows[0] if rows else None


def execute_write(sql, args=None):
    with mysql_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, args or ())
            last_id = cur.lastrowid
            affected = cur.rowcount
        conn.commit()
    return last_id, affected


DEVICE_REGION_LABELS = {
    "chengbei": "城北", "chengdong": "城东", "chengnan": "城南", "chengxi": "城西",
    "gaochun": "高淳", "jiangning": "江宁", "lishui": "溧水", "liuhe": "六合",
    "pukou": "浦口", "qixia": "栖霞", "yuhua": "雨花",
}
USER_ORG_REGION_RULES = (
    ("建邺", "chengxi"), ("秦淮", "chengnan"), ("玄武", "chengbei"), ("鼓楼", "chengdong"),
    ("高淳", "gaochun"), ("江宁", "jiangning"), ("溧水", "lishui"), ("六合", "liuhe"),
    ("浦口", "pukou"), ("栖霞", "qixia"), ("雨花", "yuhua"),
)


def ensure_device_org_schema():
    execute_write(
        """
        CREATE TABLE IF NOT EXISTS netops2026_device_org (
          id BIGINT PRIMARY KEY AUTO_INCREMENT,
          parent_id BIGINT NULL,
          node_type VARCHAR(16) NOT NULL,
          region_code VARCHAR(32) NOT NULL,
          name VARCHAR(128) NOT NULL,
          sort_order INT NOT NULL DEFAULT 0,
          status VARCHAR(16) NOT NULL DEFAULT 'active',
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          UNIQUE KEY uk_device_org_parent_name (parent_id, name),
          KEY idx_device_org_region (region_code),
          KEY idx_device_org_parent (parent_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """
    )
    execute_write(
        """
        CREATE TABLE IF NOT EXISTS netops2026_user_device_region_map (
          user_org_id BIGINT NOT NULL,
          user_org_name VARCHAR(128) NOT NULL,
          device_region VARCHAR(32) NOT NULL,
          enabled TINYINT(1) NOT NULL DEFAULT 1,
          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          PRIMARY KEY (user_org_id, device_region)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """
    )
    execute_write(
        """
        DELETE duplicate_root FROM netops2026_device_org duplicate_root
        JOIN netops2026_device_org keep_root
          ON keep_root.node_type='region' AND duplicate_root.node_type='region'
         AND keep_root.region_code=duplicate_root.region_code
         AND keep_root.parent_id IS NULL AND duplicate_root.parent_id IS NULL
         AND keep_root.id < duplicate_root.id
        """
    )
    execute_write(
        """
        DELETE orphan_room FROM netops2026_device_org orphan_room
        JOIN netops2026_device_org root ON root.node_type='region' AND root.region_code=orphan_room.region_code AND root.parent_id IS NULL
        JOIN netops2026_device_org existing_room ON existing_room.node_type='room' AND existing_room.parent_id=root.id AND existing_room.name=orphan_room.name
        WHERE orphan_room.node_type='room' AND orphan_room.parent_id<>root.id
        """
    )
    execute_write(
        """
        UPDATE netops2026_device_org room_node
        JOIN netops2026_device_org root ON root.node_type='region' AND root.region_code=room_node.region_code AND root.parent_id IS NULL
        SET room_node.parent_id=root.id
        WHERE room_node.node_type='room' AND room_node.parent_id<>root.id
        """
    )
    regions = query_all("SELECT DISTINCT region FROM olt_devices WHERE COALESCE(region, '')<>'' ORDER BY region")
    for index, row in enumerate(regions):
        code = str(row["region"])
        existing_root = query_one("SELECT id FROM netops2026_device_org WHERE node_type='region' AND parent_id IS NULL AND region_code=%s LIMIT 1", (code,))
        if not existing_root:
            execute_write(
                "INSERT INTO netops2026_device_org(parent_id,node_type,region_code,name,sort_order) VALUES(NULL,'region',%s,%s,%s)",
                (code, DEVICE_REGION_LABELS.get(code, code), (index + 1) * 10),
            )
    rooms = query_all("SELECT DISTINCT region, room FROM olt_devices WHERE COALESCE(region,'')<>'' AND COALESCE(room,'')<>'' ORDER BY region, room")
    for index, row in enumerate(rooms):
        parent = query_one("SELECT id FROM netops2026_device_org WHERE node_type='region' AND region_code=%s LIMIT 1", (row["region"],))
        if parent:
            execute_write(
                "INSERT IGNORE INTO netops2026_device_org(parent_id,node_type,region_code,name,sort_order) VALUES(%s,'room',%s,%s,%s)",
                (parent["id"], row["region"], row["room"], (index + 1) * 10),
            )


def level_two_org(user):
    org_id = getattr(user, "org_id", None)
    if not org_id:
        return None
    org = db.session.get(OrgUnit, org_id)
    if org is None:
        return None
    if org.level == 2:
        return org
    ids = [int(value) for value in (org.path or "").strip("/").split("/") if value.isdigit()]
    return OrgUnit.query.filter(OrgUnit.id.in_(ids), OrgUnit.level == 2).first() if ids else None


def ensure_default_region_mappings():
    ensure_device_org_schema()
    for org in OrgUnit.query.filter_by(level=2, status="active").all():
        existing = query_one("SELECT COUNT(*) AS total FROM netops2026_user_device_region_map WHERE user_org_id=%s", (org.id,))
        if existing and int(existing["total"] or 0) > 0:
            continue
        if "安播" in org.name:
            for region in DEVICE_REGION_LABELS:
                execute_write(
                    "INSERT IGNORE INTO netops2026_user_device_region_map(user_org_id,user_org_name,device_region,enabled) VALUES(%s,%s,%s,1)",
                    (org.id, org.name, region),
                )
            continue
        for token, region in USER_ORG_REGION_RULES:
            if token in org.name:
                execute_write(
                    "INSERT IGNORE INTO netops2026_user_device_region_map(user_org_id,user_org_name,device_region,enabled) VALUES(%s,%s,%s,1)",
                    (org.id, org.name, region),
                )
                break


def allowed_device_regions():
    cached = getattr(g, "_netops_allowed_device_regions", "__missing__")
    if cached != "__missing__":
        return cached
    if getattr(g.current_user, "role_code", "") == "super_admin":
        g._netops_allowed_device_regions = None
        return None
    org = level_two_org(g.current_user)
    if org is None:
        g._netops_allowed_device_regions = []
        return []
    rows = query_all(
        "SELECT device_region FROM netops2026_user_device_region_map WHERE user_org_id=%s AND enabled=1 ORDER BY device_region",
        (org.id,),
    )
    regions = [row["device_region"] for row in rows]
    g._netops_allowed_device_regions = regions
    return regions


def authorized_device_ids():
    cached = getattr(g, "_netops_authorized_device_ids", "__missing__")
    if cached != "__missing__":
        return cached
    regions = allowed_device_regions()
    if regions is None:
        g._netops_authorized_device_ids = None
        return None
    if not regions:
        g._netops_authorized_device_ids = []
        return []
    rows = query_all(
        f"SELECT olt_device_id FROM olt_devices WHERE is_active=1 AND region IN ({mysql_placeholders(regions)})",
        tuple(regions),
    )
    ids = [int(row["olt_device_id"]) for row in rows]
    g._netops_authorized_device_ids = ids
    return ids


def can_access_device(device_id):
    ids = authorized_device_ids()
    return ids is None or int(device_id) in set(ids)


def append_region_scope(clauses, args, column="d.region"):
    regions = allowed_device_regions()
    if regions is None:
        return
    if not regions:
        clauses.append("1=0")
        return
    clauses.append(f"{column} IN ({mysql_placeholders(regions)})")
    args.extend(regions)


def user_org_business_token():
    """Return the district token used by BOSS data, or None for unrestricted admins."""
    if getattr(g.current_user, "role_code", "") == "super_admin":
        return None
    org = level_two_org(g.current_user)
    if org is None:
        return "__none__"
    if "安播" in org.name:
        return None
    for token, _region in USER_ORG_REGION_RULES:
        if token in org.name:
            return token
    return "__none__"


def visible_user_org_ids():
    """Organization scope for user and organization administration."""
    if getattr(g.current_user, "role_code", "") == "super_admin":
        return None
    own_org_id = getattr(g.current_user, "org_id", None)
    manage_org_id = getattr(g.current_user, "manage_org_id", None)
    own_org = db.session.get(OrgUnit, own_org_id) if own_org_id else None
    anchor = db.session.get(OrgUnit, manage_org_id) if manage_org_id else own_org
    regional_root = level_two_org(g.current_user)
    if regional_root is not None and anchor is not None:
        anchor_in_region = anchor.id == regional_root.id or (anchor.path or "").startswith(regional_root.path or "/invalid/")
        if anchor.level < 2 or not anchor_in_region:
            anchor = regional_root
    if anchor is None:
        return []
    rows = OrgUnit.query.filter(
        OrgUnit.status == "active",
        or_(OrgUnit.id == anchor.id, OrgUnit.path.like(f"{anchor.path}%")),
    ).all()
    return [row.id for row in rows]


def org_subtree_ids(org_id, visible_ids=None):
    root = db.session.get(OrgUnit, org_id)
    if root is None:
        return []
    ids = [row.id for row in OrgUnit.query.filter(or_(OrgUnit.id == root.id, OrgUnit.path.like(f"{root.path}%"))).all()]
    return ids if visible_ids is None else [value for value in ids if value in set(visible_ids)]


def ensure_platform_admin():
    if getattr(g.current_user, "role_code", "") not in ("super_admin", "org_admin"):
        return fail(UNAUTHORIZED, "当前账号没有管理权限", http_status=403)
    return None


def ensure_super_admin():
    if getattr(g.current_user, "role_code", "") != "super_admin":
        return fail(UNAUTHORIZED, "基础设施监控仅限超级管理员访问", http_status=403)
    return None


_BOSS_RATE_FALLBACK = {}


def ensure_boss_super_admin(require_sensitive_access=True):
    if getattr(g.current_user, "role_code", "") != "super_admin":
        return fail(UNAUTHORIZED, "BOSS 用户资料仅限超级管理员访问", http_status=403)
    if require_sensitive_access and not verify_boss_access_token(request.headers.get("X-Boss-Access") or ""):
        return fail(UNAUTHORIZED, "敏感访问授权已失效，请重新验证登录密码", http_status=403)
    return None


def boss_access_secret():
    return str(current_app.config.get("JWT_SECRET_KEY") or current_app.config.get("SECRET_KEY") or "")


def issue_boss_access_token(ttl_seconds=300):
    payload = {
        "uid": int(g.current_user.id),
        "role": "super_admin",
        "exp": int(time.time()) + int(ttl_seconds),
        "nonce": secrets.token_hex(12),
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    body = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    signature = hmac.new(boss_access_secret().encode("utf-8"), body.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{body}.{signature}", payload["exp"]


def verify_boss_access_token(token):
    try:
        body, signature = token.split(".", 1)
        expected = hmac.new(boss_access_secret().encode("utf-8"), body.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return False
        padded = body + "=" * (-len(body) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
        return (
            int(payload.get("uid") or 0) == int(g.current_user.id)
            and payload.get("role") == "super_admin"
            and int(payload.get("exp") or 0) >= int(time.time())
        )
    except (ValueError, TypeError, json.JSONDecodeError):
        return False


def sensitive_rate_limited(action, limit, window_seconds):
    user_id = int(getattr(g.current_user, "id", 0) or 0)
    remote_ip = request.remote_addr or "unknown"
    bucket = int(time.time()) // int(window_seconds)
    key = f"netops2026:sensitive-rate:{action}:{user_id}:{remote_ip}:{bucket}"
    count = redis_command("INCR", key)
    if count == 1:
        redis_command("EXPIRE", key, int(window_seconds) + 2)
    if count is None:
        now = time.time()
        fallback_key = (action, user_id, remote_ip)
        start, current = _BOSS_RATE_FALLBACK.get(fallback_key, (now, 0))
        if now - start >= window_seconds:
            start, current = now, 0
        current += 1
        _BOSS_RATE_FALLBACK[fallback_key] = (start, current)
        count = current
    return int(count) > int(limit)


def write_sensitive_audit(action, detail=None):
    try:
        db.session.add(OperationLog(
            user_id=g.current_user.id,
            module="netops_boss",
            action=action,
            target_type="boss_user_info",
            detail=json.dumps(detail or {}, ensure_ascii=False, separators=(",", ":")),
            ip=request.remote_addr,
        ))
        db.session.commit()
    except Exception:
        db.session.rollback()


def no_store(result):
    response, status = result
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response, status


def mask_name(value):
    text = str(value or "")
    return text[:1] + "*" * max(1, len(text) - 1) if text else ""


def mask_phone(value):
    text = re.sub(r"\s+", "", str(value or ""))
    return text[:3] + "****" + text[-4:] if len(text) >= 7 else ("***" if text else "")


def mask_account(value):
    text = str(value or "")
    return "****" + text[-4:] if len(text) > 4 else ("****" if text else "")


def mask_address(value):
    text = str(value or "")
    return text[:8] + "***" if len(text) > 8 else (text[:2] + "***" if text else "")


def ch_query(sql):
    cfg = _secret_config().get("clickhouse", {})
    host = cfg.get("host", os.getenv("CLICKHOUSE_HOST", "172.25.194.212"))
    port = int(cfg.get("http_port", cfg.get("port", os.getenv("CLICKHOUSE_PORT", "8123"))))
    db = cfg.get("database", os.getenv("CLICKHOUSE_DB", "go_collector_ch"))
    user = cfg.get("user", os.getenv("CLICKHOUSE_USER", "go_collector"))
    password = cfg.get("password", os.getenv("CLICKHOUSE_PASSWORD", ""))
    url = f"http://{host}:{port}/?database={parse.quote(db)}&default_format=JSON"
    req = urlrequest.Request(url, data=sql.encode("utf-8"), method="POST")
    if user:
        req.add_header("X-ClickHouse-User", user)
    if password:
        req.add_header("X-ClickHouse-Key", password)
    with urlrequest.urlopen(req, timeout=25) as resp:
        return json.loads(resp.read().decode("utf-8")).get("data", [])


def radius_ch_query(sql, cache_seconds=45):
    """Query the dedicated Radius ClickHouse database with a read-only account.

    Radius landing pages fan out into several aggregate queries.  A short
    read-through cache coalesces repeated views and the cockpit's periodic
    refreshes without hiding a meaningful operational change.
    """
    cache_id = None
    if cache_seconds:
        cache_id = cache_key("radius_ch_query", {"sql": " ".join(sql.split())})
        cached = cache_get_json(cache_id, touch_ttl=cache_seconds)
        if cached is not None:
            return cached
    cfg = _secret_config().get("radius_clickhouse", {})
    host = cfg.get("host", os.getenv("RADIUS_CLICKHOUSE_HOST", "172.25.194.212"))
    port = int(cfg.get("http_port", cfg.get("port", os.getenv("RADIUS_CLICKHOUSE_PORT", "8123"))))
    database = cfg.get("database", os.getenv("RADIUS_CLICKHOUSE_DB", "radius_monitor_ch"))
    user = cfg.get("user", os.getenv("RADIUS_CLICKHOUSE_USER", "radius_reader"))
    password = cfg.get("password", os.getenv("RADIUS_CLICKHOUSE_PASSWORD", ""))
    url = (
        f"http://{host}:{port}/?database={parse.quote(database)}"
        "&default_format=JSON&prefer_column_name_to_alias=1"
    )
    req = urlrequest.Request(url, data=sql.encode("utf-8"), method="POST")
    if user:
        req.add_header("X-ClickHouse-User", user)
    if password:
        req.add_header("X-ClickHouse-Key", password)
    try:
        with urlrequest.urlopen(req, timeout=25) as resp:
            result = json.loads(resp.read().decode("utf-8")).get("data", [])
        if cache_id:
            cache_set_json(cache_id, result, cache_seconds)
        return result
    except urlerror.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        raise RuntimeError(f"Radius ClickHouse HTTP {exc.code}: {detail}") from exc


def redis_conf():
    cfg = _secret_config().get("redis", {})
    return {
        "host": cfg.get("host", os.getenv("NETOPS2026_REDIS_HOST", "127.0.0.1")),
        "port": int(cfg.get("port", os.getenv("NETOPS2026_REDIS_PORT", "6379"))),
        "db": int(cfg.get("db", os.getenv("NETOPS2026_REDIS_DB", "0"))),
        "password": cfg.get("password", os.getenv("NETOPS2026_REDIS_PASSWORD", "")),
        "enabled": str(cfg.get("enabled", os.getenv("NETOPS2026_REDIS_ENABLED", "1"))).lower() not in ("0", "false", "no"),
    }


def redis_command(*parts):
    cfg = redis_conf()
    if not cfg["enabled"]:
        return None
    payload = f"*{len(parts)}\r\n".encode("utf-8")
    for part in parts:
        raw = str(part).encode("utf-8")
        payload += f"${len(raw)}\r\n".encode("utf-8") + raw + b"\r\n"
    try:
        with socket.create_connection((cfg["host"], cfg["port"]), timeout=0.25) as sock:
            sock.settimeout(0.8)
            if cfg["password"]:
                sock.sendall(f"*2\r\n$4\r\nAUTH\r\n${len(cfg['password'])}\r\n{cfg['password']}\r\n".encode("utf-8"))
                _redis_read(sock)
            if cfg["db"]:
                sock.sendall(f"*2\r\n$6\r\nSELECT\r\n${len(str(cfg['db']))}\r\n{cfg['db']}\r\n".encode("utf-8"))
                _redis_read(sock)
            sock.sendall(payload)
            return _redis_read(sock)
    except OSError:
        return None


def _redis_read(sock):
    prefix = sock.recv(1)
    if not prefix:
        return None
    if prefix == b"+":
        return _redis_line(sock)
    if prefix == b":":
        value = _redis_line(sock)
        return int(value) if value and value.lstrip("-").isdigit() else value
    if prefix == b"$":
        length_text = _redis_line(sock)
        try:
            length = int(length_text)
        except (TypeError, ValueError):
            return None
        if length < 0:
            return None
        data = b""
        while len(data) < length:
            data += sock.recv(length - len(data))
        sock.recv(2)
        return data.decode("utf-8")
    if prefix == b"-":
        _redis_line(sock)
        return None
    return None


def _redis_line(sock):
    data = b""
    while not data.endswith(b"\r\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data[:-2].decode("utf-8")


def cache_key(name, params):
    normalized = json.dumps(params, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha1(normalized.encode("utf-8")).hexdigest()
    return f"netops2026:{name}:{digest}"


def cache_get_json(key, touch_ttl=None):
    raw = redis_command("GET", key)
    if not raw:
        return None
    if touch_ttl:
        # Keep frequently viewed operational summaries hot.  This is deliberately
        # a small sliding window; refreshes do not extend data beyond the current
        # operator activity period.
        redis_command("EXPIRE", key, int(touch_ttl))
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def cache_set_json(key, value, ttl):
    redis_command("SETEX", key, int(ttl), json.dumps(value, ensure_ascii=False, separators=(",", ":")))


_DASHBOARD_REFRESH_LOCK = threading.Lock()
_DASHBOARD_REFRESHING = set()


def schedule_dashboard_refresh(cache_key_value, hours, user_id):
    """Refresh one permission-scoped cockpit snapshot off the request path."""
    with _DASHBOARD_REFRESH_LOCK:
        if cache_key_value in _DASHBOARD_REFRESHING:
            return
        _DASHBOARD_REFRESHING.add(cache_key_value)
    # Gunicorn has multiple workers.  Use Redis as a short distributed lease so
    # concurrent page opens still result in a single expensive aggregation.
    refresh_lease_key = "netops2026:dashboard_refresh:" + hashlib.sha1(cache_key_value.encode("utf-8")).hexdigest()
    if redis_command("SET", refresh_lease_key, "1", "NX", "EX", 90) != "OK":
        with _DASHBOARD_REFRESH_LOCK:
            _DASHBOARD_REFRESHING.discard(cache_key_value)
        return
    app = current_app._get_current_object()

    def refresh():
        try:
            with app.app_context():
                user = db.session.get(User, int(user_id))
                if user is None or user.status != "active":
                    return
                with app.test_request_context(f"/api/netops2026/dashboard?hours={int(hours)}&refresh=1"):
                    g.current_user = user
                    # Invoke the protected view body with the same user scope.
                    dashboard.__wrapped__()
        except Exception:
            app.logger.exception("background cockpit refresh failed")
        finally:
            with _DASHBOARD_REFRESH_LOCK:
                _DASHBOARD_REFRESHING.discard(cache_key_value)

    threading.Thread(target=refresh, name=f"netops-dashboard-{hours}h", daemon=True).start()


_dashboard_activity_schema_ready = False


def ensure_dashboard_activity_schema():
    """Persist cockpit visit and presence signals without coupling them to page refreshes."""
    global _dashboard_activity_schema_ready
    if _dashboard_activity_schema_ready:
        return
    execute_write(
        """
        CREATE TABLE IF NOT EXISTS netops2026_dashboard_presence (
          user_id BIGINT NOT NULL PRIMARY KEY,
          last_seen_at DATETIME NOT NULL,
          last_visit_at DATETIME NOT NULL,
          visit_count BIGINT UNSIGNED NOT NULL DEFAULT 0,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          KEY idx_dashboard_presence_seen (last_seen_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """
    )
    _dashboard_activity_schema_ready = True


def dashboard_platform_stats():
    """Return account-facing metrics restricted to the caller's user-org scope."""
    user_scope = visible_user_org_ids()
    users_query = User.query.filter(User.status == "active")
    if user_scope is not None:
        users_query = users_query.filter(User.org_id.in_(user_scope)) if user_scope else users_query.filter(false())
    active_users = users_query.with_entities(User.id).all()
    user_ids = [int(row[0]) for row in active_users]
    result = {
        "active_accounts": len(user_ids),
        "online_users": 0,
        "today_active_users": 0,
        "total_visits": 0,
        "today_visits": 0,
        "online_window_minutes": 5,
    }
    if not user_ids:
        return result
    ensure_dashboard_activity_schema()
    placeholders = mysql_placeholders(user_ids)
    row = query_one(
        f"""
        SELECT
          COALESCE(SUM(last_seen_at >= NOW() - INTERVAL 5 MINUTE), 0) AS online_users,
          COALESCE(SUM(DATE(last_seen_at)=CURDATE()), 0) AS today_active_users,
          COALESCE(SUM(visit_count), 0) AS total_visits,
          COALESCE(SUM(CASE WHEN DATE(last_visit_at)=CURDATE() THEN visit_count ELSE 0 END), 0) AS today_visits
        FROM netops2026_dashboard_presence
        WHERE user_id IN ({placeholders})
        """,
        tuple(user_ids),
    ) or {}
    result.update({key: int(row.get(key) or 0) for key in ("online_users", "today_active_users", "total_visits", "today_visits")})
    return result


@netops2026_bp.post("/dashboard/presence")
@login_required
def dashboard_presence():
    """Heartbeat for the cockpit. A visit is recorded only on a page entry, never on auto refresh."""
    ensure_dashboard_activity_schema()
    payload = request.get_json(silent=True) or {}
    visit = bool(payload.get("visit", False))
    visit_delta = 1 if visit else 0
    execute_write(
        """
        INSERT INTO netops2026_dashboard_presence (user_id, last_seen_at, last_visit_at, visit_count)
        VALUES (%s, NOW(), NOW(), %s)
        ON DUPLICATE KEY UPDATE
          last_seen_at=NOW(),
          last_visit_at=IF(%s=1, NOW(), last_visit_at),
          visit_count=visit_count + %s
        """,
        (int(g.current_user.id), visit_delta, visit_delta, visit_delta),
    )
    # Do not evict the expensive dashboard aggregate for a heartbeat.  The
    # cockpit is served from a pre-warmed snapshot; evicting it here turned
    # every page entry into a cold MySQL/ClickHouse calculation.
    return success({"visit_recorded": visit, "online_window_minutes": 5})


def agent_conf():
    cfg = _secret_config().get("agent", {})
    return {
        "base_url": cfg.get("base_url", os.getenv("COLLECTOR_AGENT_BASE_URL", "http://172.31.1.236:18086")).rstrip("/"),
        "token": cfg.get("token", os.getenv("COLLECTOR_AGENT_TOKEN", "")),
    }


_INFRASTRUCTURE_CACHE = {"expires_at": 0.0, "payload": None}


def infrastructure_conf():
    """Configuration for the three lightweight in-network host probes."""
    cfg = _secret_config().get("infrastructure", {})
    return {
        "token": str(cfg.get("token") or os.getenv("NETOPS_INFRASTRUCTURE_TOKEN", "")),
        "nodes": {
            "platform": {
                "id": "233", "name": "统一网管平台", "host": "172.31.1.233", "role": "前端、BFF、缓存与业务库",
                "url": str(cfg.get("platform_url") or "http://127.0.0.1:18190/v1/overview"),
                "management": [],
            },
            "collector": {
                "id": "236", "name": "采集与查询节点", "host": "172.31.1.236", "role": "采集引擎、采集库与设备查询",
                "url": str(cfg.get("collector_url") or "http://172.31.1.236:18190/v1/overview"),
                "management": [],
            },
            "aiops": {
                "id": "20", "name": "AIOps 与 ELK 节点", "host": "172.25.60.20", "role": "AIOps、分析库与日志检索",
                "url": str(cfg.get("aiops_url") or "http://172.25.60.20:18190/v1/overview"),
                "management": [
                    {"label": "Kibana", "url": str(cfg.get("kibana_url") or "http://172.25.60.20:5601")},
                ],
            },
            "radius": {
                "id": "213", "name": "Radius 采集节点", "host": "172.25.194.213", "role": "RADIUS 抓包、解析、缓存与本地落库",
                "url": str(cfg.get("radius_url") or "http://172.25.194.213:18190/v1/overview"),
                "management": [],
            },
        },
    }


def infrastructure_http_probe(node, token):
    headers = {"Authorization": "Bearer " + token} if token else {}
    started_at = time.monotonic()
    req = urlrequest.Request(node["url"], headers=headers)
    try:
        with urlrequest.urlopen(req, timeout=4) as response:
            payload = json.loads(response.read().decode("utf-8"))
        if not isinstance(payload, dict):
            raise RuntimeError("探针返回格式无效")
        payload["response_ms"] = round((time.monotonic() - started_at) * 1000)
        return payload, None
    except (urlerror.URLError, urlerror.HTTPError, OSError, ValueError, json.JSONDecodeError) as exc:
        return None, f"探针不可达：{exc.__class__.__name__}"


def infrastructure_http_logs(node, token, service, limit):
    """Fetch only a curated service key from the node log endpoint."""
    headers = {"Authorization": "Bearer " + token} if token else {}
    base = str(node["url"]).rsplit("/", 1)[0]
    query = parse.urlencode({"service": service, "limit": limit})
    req = urlrequest.Request(f"{base}/logs?{query}", headers=headers)
    try:
        with urlrequest.urlopen(req, timeout=8) as response:
            payload = json.loads(response.read().decode("utf-8"))
        if not isinstance(payload, dict):
            raise RuntimeError("invalid log probe payload")
        return payload, None
    except (urlerror.URLError, urlerror.HTTPError, OSError, ValueError, json.JSONDecodeError) as exc:
        return None, f"log probe unavailable: {exc.__class__.__name__}"


def infrastructure_node_status(resources, services):
    if any(item.get("status") == "failed" for item in services):
        return "failed"
    thresholds = [
        float((resources or {}).get("cpu_percent") or 0),
        float(((resources or {}).get("memory") or {}).get("used_percent") or 0),
        float(((resources or {}).get("disk") or {}).get("used_percent") or 0),
    ]
    return "warning" if max(thresholds or [0]) >= 85 else "ok"


def clickhouse_infrastructure_node():
    node = {
        "id": "212", "name": "ClickHouse 分析节点", "host": str(_secret_config().get("clickhouse", {}).get("host") or "172.25.194.212"),
        "role": "ONU、Radius 分析数据仓库", "management": [],
    }
    started_at = time.monotonic()
    services = []
    try:
        ch_query("SELECT 1")
        services.append({"key": "clickhouse", "label": "ClickHouse 服务", "status": "ok", "detail": "分析库查询正常"})
    except Exception as exc:
        services.append({"key": "clickhouse", "label": "ClickHouse 服务", "status": "failed", "detail": f"查询失败：{type(exc).__name__}"})
    try:
        radius_ch_query("SELECT 1")
        services.append({"key": "radius_warehouse", "label": "Radius 分析库", "status": "ok", "detail": "Radius 数据库可查询"})
    except Exception as exc:
        services.append({"key": "radius_warehouse", "label": "Radius 分析库", "status": "failed", "detail": f"查询失败：{type(exc).__name__}"})
    try:
        rows = radius_ch_query("""
            SELECT dateDiff('second', metric_time, now()) AS lag_seconds, spool_pending, sink_retries
            FROM radius_collector_metrics ORDER BY metric_time DESC LIMIT 1
        """)
        latest = rows[0] if rows else {}
        lag_seconds = int(latest.get("lag_seconds") or 999999)
        spool_pending = int(latest.get("spool_pending") or 0)
        status = "ok" if lag_seconds <= 180 and spool_pending < 10000 else "warning"
        services.append({"key": "radius_collector", "label": "Radius 采集链路", "status": status, "detail": f"延迟 {lag_seconds} 秒 · 待重放 {spool_pending} 条"})
    except Exception as exc:
        services.append({"key": "radius_collector", "label": "Radius 采集链路", "status": "failed", "detail": f"状态读取失败：{type(exc).__name__}"})
    metrics = {}
    try:
        rows = ch_query("""
            SELECT metric, value FROM system.asynchronous_metrics
            WHERE metric IN ('OSMemoryTotal','OSMemoryAvailable','FilesystemMainPathTotalBytes',
                             'FilesystemMainPathAvailableBytes','LoadAverage1','NumberOfCPUCores')
               OR metric LIKE 'OSIdleTimeCPU%'
        """)
        metrics = {str(row.get("metric")): float(row.get("value") or 0) for row in rows}
    except Exception:
        # Service checks remain authoritative even where the server disallows the system table.
        metrics = {}
    memory_total = int(metrics.get("OSMemoryTotal") or 0)
    memory_available = int(metrics.get("OSMemoryAvailable") or 0)
    disk_total = int(metrics.get("FilesystemMainPathTotalBytes") or 0)
    disk_available = int(metrics.get("FilesystemMainPathAvailableBytes") or 0)
    idle_samples = [value for key, value in metrics.items() if key.startswith("OSIdleTimeCPU")]
    cores = max(1, int(metrics.get("NumberOfCPUCores") or len(idle_samples) or 1))
    load_1 = float(metrics.get("LoadAverage1") or 0)
    # ClickHouse exposes a rolling idle ratio for each CPU.  It is the closest
    # real host-utilisation signal available without an SSH agent on 212.  Do
    # not confuse a load average with a CPU percentage.
    cpu_percent = round(max(0, min(100, (1 - sum(idle_samples) / len(idle_samples)) * 100)), 1) if idle_samples else round(min(100, load_1 * 100 / cores), 1)
    resources = {
        "cpu_percent": cpu_percent, "cpu_cores": cores, "load_1": round(load_1, 2),
        "memory": {"total_bytes": memory_total, "available_bytes": memory_available, "used_bytes": max(0, memory_total - memory_available), "used_percent": round(max(0, memory_total - memory_available) * 100 / memory_total, 1) if memory_total else None},
        "disk": {"path": "/", "total_bytes": disk_total, "free_bytes": disk_available, "used_bytes": max(0, disk_total - disk_available), "used_percent": round(max(0, disk_total - disk_available) * 100 / disk_total, 1) if disk_total else None},
    }
    node.update({"resources": resources, "services": services, "response_ms": round((time.monotonic() - started_at) * 1000), "observed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
    node["status"] = infrastructure_node_status(resources, services)
    return node


def infrastructure_snapshot(force=False):
    now = time.monotonic()
    if not force and _INFRASTRUCTURE_CACHE["payload"] is not None and now < _INFRASTRUCTURE_CACHE["expires_at"]:
        return _INFRASTRUCTURE_CACHE["payload"]
    config = infrastructure_conf()
    nodes = []
    for key in ("platform", "collector", "aiops", "radius"):
        definition = config["nodes"][key]
        payload, error = infrastructure_http_probe(definition, config["token"])
        if error:
            nodes.append({**definition, "status": "failed", "error": error, "services": [], "resources": {}, "observed_at": None})
            continue
        resources = payload.get("resources") or {}
        services = payload.get("services") or []
        nodes.append({**definition, "hostname": payload.get("hostname"), "observed_at": payload.get("observed_at"), "response_ms": payload.get("response_ms"), "resources": resources, "services": services, "status": infrastructure_node_status(resources, services)})
    nodes.append(clickhouse_infrastructure_node())
    components = []
    for node in nodes:
        for service in node.get("services") or []:
            components.append({"node_id": node["id"], "node_name": node["name"], **service})
    failed = sum(1 for item in components if item.get("status") == "failed")
    warning = sum(1 for node in nodes if node.get("status") == "warning")
    node_status = {str(node["id"]): node.get("status") for node in nodes}
    def link_status(*node_ids):
        values = [node_status.get(str(node_id), "failed") for node_id in node_ids]
        return "failed" if "failed" in values else "warning" if "warning" in values else "ok"
    # Links come from the live production configuration and actual BFF calls.
    # Firewall captions are the last verified host-policy baseline.  They make
    # source allowlists visible so a reachable service is never mistaken for a
    # public service.
    topology = [
        {"id": "web-entry", "from": "clients", "to": "233", "protocol": "HTTPS", "ports": "5772", "direction": "用户 → 平台", "description": "浏览器经 233:5772 访问统一网管入口（Nginx → Vue / BFF）", "status": node_status.get("233", "failed"), "firewall": "233 UFW：5772 对外；BFF 7001 仅回环；SSH 由 Fail2ban 防护"},
        {"id": "collector-api", "from": "233", "to": "236", "protocol": "HTTP", "ports": "18086", "direction": "233 → 236", "description": "采集探测、设备查询与采集状态", "status": link_status("233", "236"), "firewall": "236 当前未启用主机入站白名单；仅 SSH Fail2ban，需收紧 18086 来源"},
        {"id": "collector-mysql", "from": "233", "to": "236", "protocol": "MySQL", "ports": "3339", "direction": "233 → 236", "description": "OLT、CMTS、ONU 与采集结果查询", "status": link_status("233", "236"), "firewall": "236 当前未启用主机入站白名单；需按 172.31 网段与管理来源收紧 3339"},
        {"id": "aiops-api", "from": "233", "to": "20", "protocol": "HTTP + 签名", "ports": "18080", "direction": "233 → 20", "description": "AIOps 分析、事件、日志与知识库代理", "status": link_status("233", "20"), "firewall": "20 端口守卫：18080 仅 233 与回环；SSH Fail2ban 已启用"},
        {"id": "clickhouse", "from": "233", "to": "212", "protocol": "ClickHouse HTTP", "ports": "8123", "direction": "233 → 212", "description": "ONU 质差、性能与 Radius 分析查询", "status": link_status("233", "212"), "firewall": "212 端口守卫：8123 仅 233、236、213 与回环；SSH 5334 仅 172.31.0.0/16；Fail2ban 已启用"},
        {"id": "radius-udp", "from": "radius_nas", "to": "213", "protocol": "RADIUS / UDP", "ports": "1812 / 1813 / 3799", "direction": "NAS / BRAS → 213", "description": "认证、Accounting 与 CoA/Disconnect 报文镜像抓包", "status": node_status.get("213", "failed"), "firewall": "213 端口守卫已限制 3306/18190；SSH Fail2ban 已启用；UDP 来源需按 NAS/BRAS 清单复核"},
        {"id": "radius-sink", "from": "213", "to": "212", "protocol": "ClickHouse HTTP", "ports": "8123", "direction": "213 → 212", "description": "解析结果与采集指标写入 Radius 分析库", "status": link_status("213", "212"), "firewall": "212 端口守卫：8123 仅 233、236、213 与回环；9000/9004/9005/9009 仅本机；Fail2ban 已启用"},
    ]
    result = {"observed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "nodes": nodes, "components": components, "topology": topology, "summary": {"total_nodes": len(nodes), "healthy_nodes": sum(1 for node in nodes if node.get("status") == "ok"), "warning_nodes": warning, "failed_nodes": sum(1 for node in nodes if node.get("status") == "failed"), "total_components": len(components), "failed_components": failed}}
    _INFRASTRUCTURE_CACHE.update({"expires_at": now + 20, "payload": result})
    return result


def aiops_conf():
    """Return the internal AIOps service settings used by the platform BFF."""
    cfg = _secret_config().get("aiops", {})
    return {
        "base_url": cfg.get("base_url", os.getenv("AIOPS_INTERNAL_BASE_URL", "http://172.25.60.20:18080")).rstrip("/"),
        "shared_secret": cfg.get("shared_secret", os.getenv("AIOPS_INTERNAL_SHARED_SECRET", "")),
        "timeout": int(cfg.get("timeout", os.getenv("AIOPS_INTERNAL_TIMEOUT_SECONDS", "150"))),
        "rtc_epoch_path": cfg.get("rtc_epoch_path", os.getenv("AIOPS_RTC_EPOCH_PATH", "/sys/class/rtc/rtc0/since_epoch")),
        "task_mutations_enabled": str(
            cfg.get("task_mutations_enabled", os.getenv("AIOPS_TASK_MUTATIONS_ENABLED", "false"))
        ).lower() in ("1", "true", "yes"),
    }


AIOPS_ALL_PERMISSIONS = {
    "netops.aiops.view",
    "netops.aiops.events.view",
    "netops.aiops.logs.view",
    "netops.aiops.analysis.view",
    "netops.aiops.analysis.run",
    "netops.aiops.tasks.manage",
    "netops.aiops.rules.manage",
    "netops.aiops.kb.manage",
    "netops.aiops.models.manage",
    "netops.aiops.audit.view",
    "netops.ai_chat.use",
}
AIOPS_ENTRY_KEYS = {"netops.aiops", "netops.ai_assistant", "netops.aiops_knowledge", "netops.aiops_admin"}


def aiops_page_audience_allowed():
    """Use menu role/type permission only; AIOps never applies org/region scope."""
    return True


def aiops_permissions_for_user():
    role = getattr(g.current_user, "role_code", "normal_user") or "normal_user"
    permissions = {
        "netops.aiops.view",
        "netops.aiops.events.view",
        "netops.aiops.logs.view",
        "netops.aiops.analysis.view",
        "netops.ai_chat.use",
    }
    if role in ("org_admin", "super_admin"):
        permissions.update({
            "netops.aiops.analysis.run",
            "netops.aiops.tasks.manage",
            "netops.aiops.rules.manage",
            "netops.aiops.kb.manage",
            "netops.aiops.models.manage",
            "netops.aiops.audit.view",
        })
    if role == "super_admin":
        permissions = set(AIOPS_ALL_PERMISSIONS)
    return sorted(permissions)


def aiops_entry_allowed(menu_key):
    """Honor the same enabled/min-role/user-type gate used by platform navigation."""
    menu = AppMenu.query.filter_by(menu_key=menu_key, enabled=True).first()
    if menu is None:
        return False
    if menu_key in AIOPS_ENTRY_KEYS and not aiops_page_audience_allowed():
        return False
    role_rank = {"normal_user": 1, "org_admin": 2, "super_admin": 3}
    role = getattr(g.current_user, "role_code", "normal_user") or "normal_user"
    user_type = getattr(g.current_user, "user_type", "internal") or "internal"
    if role_rank.get(role, 1) < role_rank.get(menu.min_role or "normal_user", 1):
        return False
    # The built-in system administrator is a super-admin with user_type=system.
    # It must not lose internal operational menus because of the audience tag.
    return role == "super_admin" or menu.user_type in (None, "", "all", user_type)


def aiops_required_permission(path, method):
    normalized = "/" + str(path or "").strip("/")
    if normalized.startswith((
        "/fault-kb/chat/logs",
        "/system/operation-logs",
        "/system/qq-audit-logs",
        "/system/login-logs",
    )):
        return "netops.aiops.audit.view"
    if normalized.startswith("/fault-kb/chat"):
        return "netops.ai_chat.use"
    if normalized.startswith(("/llm/providers", "/llm/models", "/llm/usage-bindings", "/llm/usage-keys")):
        return "netops.aiops.models.manage"
    if normalized.startswith("/system/settings") and method != "GET":
        return "netops.aiops.models.manage"
    if normalized.startswith("/report-tasks"):
        return "netops.aiops.tasks.manage" if method != "GET" else "netops.aiops.analysis.view"
    if normalized.startswith("/ai-analysis-rules"):
        return "netops.aiops.rules.manage" if method != "GET" else "netops.aiops.analysis.view"
    if normalized.startswith("/fault-kb") and method != "GET":
        return "netops.aiops.kb.manage"
    if normalized == "/ai-runs" and method == "POST":
        return "netops.aiops.analysis.run"
    if normalized.startswith("/findings/") and normalized.endswith("/feedback") and method == "POST":
        return "netops.aiops.analysis.run"
    if normalized.startswith("/syslog") or normalized.startswith("/trap"):
        return "netops.aiops.logs.view"
    if normalized.startswith("/alarm-events"):
        return "netops.aiops.events.view"
    return "netops.aiops.models.manage" if method != "GET" else "netops.aiops.view"


def aiops_identity_payload(permissions):
    public = g.current_user.to_public_dict()
    return {
        "subject": str(g.current_user.id),
        "username": public.get("oa_username") or public.get("mobile") or public.get("oss_account") or public.get("account") or str(g.current_user.id),
        "display_name": public.get("real_name") or public.get("name") or public.get("mobile"),
        "role_code": getattr(g.current_user, "role_code", "normal_user") or "normal_user",
        "user_type": getattr(g.current_user, "user_type", "internal") or "internal",
        "org_id": getattr(g.current_user, "org_id", None),
        "org_name": public.get("org_name"),
        # AIOps is a global operational dataset. The page/capability permission,
        # rather than the OLT/CMTS regional inventory, is the access boundary.
        "regions": None,
        "permissions": permissions,
    }


def aiops_unix_timestamp(cfg):
    """Use the hardware RTC only when the host clock is clearly unsynchronized."""
    system_now = int(time.time())
    rtc_path = str(cfg.get("rtc_epoch_path") or "").strip()
    if not rtc_path:
        return system_now
    try:
        with open(rtc_path, "r", encoding="ascii") as handle:
            rtc_now = int(handle.read().strip())
    except (OSError, ValueError):
        return system_now
    return rtc_now if abs(rtc_now - system_now) > 300 else system_now


def aiops_proxy(path):
    """Forward an authenticated platform request with a tamper-evident identity envelope."""
    clean_path = "/" + str(path or "").strip("/")
    platform_identity_probe = clean_path == "/auth/me" and request.method == "GET"
    if ".." in clean_path or (clean_path.startswith("/auth") and not platform_identity_probe) or clean_path.startswith("/system/users"):
        return fail(UNAUTHORIZED, "该 AIOps 接口不允许通过统一平台访问", http_status=403)
    permissions = aiops_permissions_for_user()
    required = aiops_required_permission(clean_path, request.method)
    if required == "netops.ai_chat.use":
        entry_key = "netops.ai_assistant"
    elif clean_path.startswith("/fault-kb"):
        entry_key = "netops.aiops_knowledge"
    elif clean_path.startswith(("/llm/", "/system/")):
        entry_key = "netops.aiops_admin"
    else:
        entry_key = "netops.aiops"
    if not aiops_entry_allowed(entry_key):
        return fail(UNAUTHORIZED, "当前账号未启用该智能运维入口", http_status=403)
    if required not in permissions:
        return fail(UNAUTHORIZED, "当前账号没有该 AIOps 功能权限", http_status=403)

    cfg = aiops_conf()
    if clean_path.startswith("/report-tasks") and request.method != "GET" and not cfg["task_mutations_enabled"]:
        return fail(
            SERVER_ERROR,
            "AI 调度任务当前为只读；待 20 服务器调度器完成安全切换后开放编辑",
            http_status=503,
        )
    if not cfg["shared_secret"]:
        return fail(SERVER_ERROR, "AIOps 内部共享密钥尚未配置", http_status=503)

    body = request.get_data(cache=True) or b""
    identity_json = json.dumps(aiops_identity_payload(permissions), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    timestamp = str(aiops_unix_timestamp(cfg))
    nonce = secrets.token_hex(12)
    canonical = "\n".join(
        [
            timestamp,
            nonce,
            request.method.upper(),
            clean_path,
            hashlib.sha256(body).hexdigest(),
            hashlib.sha256(identity_json.encode("utf-8")).hexdigest(),
        ]
    )
    signature = hmac.new(cfg["shared_secret"].encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    query = request.query_string.decode("utf-8", errors="ignore")
    upstream_url = f'{cfg["base_url"]}/api{clean_path}' + (f"?{query}" if query else "")
    headers = {
        "Accept": "application/json",
        "Content-Type": request.content_type or "application/json",
        "X-AIOps-Identity": base64.urlsafe_b64encode(identity_json.encode("utf-8")).decode("ascii"),
        "X-AIOps-Timestamp": timestamp,
        "X-AIOps-Nonce": nonce,
        "X-AIOps-Signature": signature,
        "X-Request-ID": request.headers.get("X-Request-ID") or secrets.token_hex(16),
    }
    upstream_request = urlrequest.Request(upstream_url, data=body if request.method != "GET" else None, method=request.method, headers=headers)
    try:
        with urlrequest.urlopen(upstream_request, timeout=cfg["timeout"]) as response:
            raw = response.read()
            payload = json.loads(raw.decode("utf-8")) if raw else {}
            return success(payload)
    except urlerror.HTTPError as exc:
        raw = exc.read()
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            payload = {}
        error_value = payload.get("error") if isinstance(payload, dict) else None
        message = error_value.get("message") if isinstance(error_value, dict) else error_value
        return fail(UNAUTHORIZED if exc.code in (401, 403) else SERVER_ERROR, message or f"AIOps 请求失败 HTTP {exc.code}", http_status=exc.code)
    except (urlerror.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        current_app.logger.warning("AIOps proxy failed: %s", exc)
        return fail(SERVER_ERROR, "AIOps 服务暂时不可用", http_status=503)


def agent_post(path, payload, timeout=25):
    cfg = agent_conf()
    if not cfg["token"]:
        raise RuntimeError("collector-agent token not configured")
    req = urlrequest.Request(
        cfg["base_url"] + path,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + cfg["token"]},
    )
    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urlerror.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        try:
            body = json.loads(raw)
            raise RuntimeError(body.get("message") or f"collector-agent http {exc.code}")
        except json.JSONDecodeError:
            raise RuntimeError(f"collector-agent http {exc.code}")
    if body.get("code") != 0:
        raise RuntimeError(body.get("message") or "collector-agent request failed")
    return body.get("data")


def int_arg(name, default=1, min_value=1, max_value=500):
    try:
        value = int(request.args.get(name, default))
    except (TypeError, ValueError):
        value = default
    return max(min_value, min(max_value, value))


def bool_arg(name, default=False):
    value = request.args.get(name)
    if value is None:
        return default
    return str(value).strip().lower() not in ("0", "false", "no", "off", "")


def normalize_mac(value):
    return re.sub(r"[^0-9a-fA-F]", "", value or "").lower()


def ch_escape(value):
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


def dt_value(value):
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(value, Decimal):
        return float(value)
    return value


def json_ready(row):
    return {k: dt_value(v) for k, v in dict(row).items()}


def fmt_mac(value):
    mac = normalize_mac(value)
    if len(mac) != 12:
        return value or ""
    return ":".join(mac[i:i + 2].upper() for i in range(0, 12, 2))


def parse_visit_datetime(value):
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    text = str(value or "").strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d", "%Y/%m/%d"):
        try:
            return datetime.strptime(text, fmt).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
    return None


def read_xlsx_rows(file_obj):
    data = file_obj.read()
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        shared = []
        if "xl/sharedStrings.xml" in zf.namelist():
            root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
            ns = {"x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
            for si in root.findall("x:si", ns):
                texts = [t.text or "" for t in si.findall(".//x:t", ns)]
                shared.append("".join(texts))
        sheet_name = "xl/worksheets/sheet1.xml"
        root = ET.fromstring(zf.read(sheet_name))
        ns = {"x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
        rows = []
        for row in root.findall(".//x:sheetData/x:row", ns):
            values = []
            for cell in row.findall("x:c", ns):
                ref = cell.attrib.get("r", "")
                col = 0
                for ch in re.sub(r"\d", "", ref):
                    col = col * 26 + ord(ch.upper()) - ord("A") + 1
                while len(values) < max(col - 1, 0):
                    values.append("")
                ctype = cell.attrib.get("t")
                value = ""
                if ctype == "inlineStr":
                    value = "".join(t.text or "" for t in cell.findall(".//x:t", ns))
                else:
                    v = cell.find("x:v", ns)
                    if v is not None and v.text is not None:
                        value = v.text
                        if ctype == "s":
                            value = shared[int(value)] if value.isdigit() and int(value) < len(shared) else ""
                values.append(str(value).strip())
            rows.append(values)
        return rows


def excel_col(index):
    result = ""
    index += 1
    while index:
        index, remainder = divmod(index - 1, 26)
        result = chr(65 + remainder) + result
    return result


def make_xlsx(headers, rows):
    def cell_xml(row_index, col_index, value):
        ref = f"{excel_col(col_index)}{row_index}"
        text = "" if value is None else str(value)
        return f'<c r="{ref}" t="inlineStr"><is><t>{xml_escape(text)}</t></is></c>'

    sheet_rows = []
    for row_index, row in enumerate([headers] + rows, 1):
        cells = "".join(cell_xml(row_index, col_index, value) for col_index, value in enumerate(row))
        sheet_rows.append(f'<row r="{row_index}">{cells}</row>')
    sheet_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<sheetData>{"".join(sheet_rows)}</sheetData>'
        '</worksheet>'
    )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>""")
        zf.writestr("_rels/.rels", """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>""")
        zf.writestr("xl/workbook.xml", """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="ONU质差明细" sheetId="1" r:id="rId1"/></sheets>
</workbook>""")
        zf.writestr("xl/_rels/workbook.xml.rels", """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>""")
        zf.writestr("xl/worksheets/sheet1.xml", sheet_xml)
    return output.getvalue()


def boss_header_map(headers):
    aliases = {
        "company": {"公司", "分公司", "company"},
        "id_number": {"证号", "gdf账号", "gdf帐号", "账号", "账户", "id_number"},
        "region": {"区域", "region"},
        "grid": {"网格", "grid"},
        "visit_datetime": {"入户时间日期", "入户时间", "安装时间", "visit_datetime"},
        "onu_serial_number": {"onu序列号", "onu serial", "onu_serial_number", "onu", "mac", "onu mac"},
    }
    result = {}
    normalized = [str(h or "").strip().lower().replace(" ", "") for h in headers]
    for key, names in aliases.items():
        for idx, name in enumerate(normalized):
            if name in {n.lower().replace(" ", "") for n in names}:
                result[key] = idx
                break
    return result


def quality_label(code):
    return {
        "rx_low": "接收光过低",
        "rx_high": "接收光过高",
        "rx_missing": "接收光缺失",
        "rx_invalid": "接收光异常",
    }.get(code or "", code or "-")


DEFAULT_QUALITY_RULE = {
    "onu_rx_low_dbm": -25.0,
    "onu_rx_high_dbm": -8.0,
    "onu_rx_invalid_min_dbm": -40.0,
    "onu_rx_invalid_max_dbm": 0.0,
    "onu_valid_rx_min_dbm": -40.0,
    "onu_valid_rx_max_dbm": 5.0,
    "onu_rule_version": "onu_rx_web_-25_-8",
}

DEFAULT_PERFORMANCE_RULE = {
    "olt_cpu_warning": 80.0,
    "olt_cpu_critical": 90.0,
    "olt_mem_warning": 80.0,
    "olt_mem_critical": 90.0,
    "board_cpu_warning": 80.0,
    "board_cpu_critical": 90.0,
    "board_mem_warning": 80.0,
    "board_mem_critical": 90.0,
    "stale_minutes": 30.0,
    "include_collect_failures": False,
    "rule_version": "olt_perf_web_80_90",
}

QUALITY_CURRENT_CACHE_TTL = 300
QUALITY_HISTORY_CACHE_TTL = 3600
QUALITY_TOP_OLT_LIMIT = 100
QUALITY_TOP_PORT_LIMIT = 200


def system_setting_get(key, default_value=None):
    try:
        row = query_one("SELECT setting_value FROM netops2026_settings WHERE setting_key=%s", (key,))
    except Exception:
        return default_value
    if not row:
        return default_value
    try:
        return json.loads(row["setting_value"])
    except (TypeError, json.JSONDecodeError):
        return default_value


def system_setting_set(key, value):
    with mysql_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS netops2026_settings (
                  setting_key varchar(128) NOT NULL PRIMARY KEY,
                  setting_value json NOT NULL,
                  updated_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """
            )
            cur.execute(
                """
                INSERT INTO netops2026_settings (setting_key, setting_value)
                VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)
                """,
                (key, json.dumps(value, ensure_ascii=False)),
            )
        conn.commit()


def quality_rule():
    rule = DEFAULT_QUALITY_RULE.copy()
    saved = system_setting_get("quality.onu_rx_rule", {})
    if isinstance(saved, dict):
        rule.update(saved)
    for key in ("onu_rx_low_dbm", "onu_rx_high_dbm", "onu_rx_invalid_min_dbm", "onu_rx_invalid_max_dbm", "onu_valid_rx_min_dbm", "onu_valid_rx_max_dbm"):
        try:
            rule[key] = float(rule[key])
        except (TypeError, ValueError):
            rule[key] = DEFAULT_QUALITY_RULE[key]
    if not str(rule.get("onu_rule_version") or "").strip():
        rule["onu_rule_version"] = f"onu_rx_web_{rule['onu_rx_low_dbm']}_{rule['onu_rx_high_dbm']}"
    return rule


def performance_rule():
    rule = DEFAULT_PERFORMANCE_RULE.copy()
    saved = system_setting_get("performance.olt_rule", {})
    if isinstance(saved, dict):
        rule.update(saved)
    for key in (
        "olt_cpu_warning", "olt_cpu_critical", "olt_mem_warning", "olt_mem_critical",
        "board_cpu_warning", "board_cpu_critical", "board_mem_warning", "board_mem_critical",
        "stale_minutes",
    ):
        try:
            rule[key] = float(rule[key])
        except (TypeError, ValueError):
            rule[key] = DEFAULT_PERFORMANCE_RULE[key]
    value = rule.get("include_collect_failures", False)
    if isinstance(value, str):
        value = value.strip().lower() in ("1", "true", "yes", "on")
    rule["include_collect_failures"] = bool(value)
    if not str(rule.get("rule_version") or "").strip():
        rule["rule_version"] = "olt_perf_web_80_90"
    return rule


def quality_rx_valid_expr(rule):
    return (
        f"isNotNull(rx_power) AND rx_power != 0 "
        f"AND rx_power <= {rule['onu_rx_invalid_max_dbm']} "
        f"AND rx_power > {rule['onu_rx_invalid_min_dbm']}"
    )


def quality_rx_bad_expr(rule):
    return f"({quality_rx_valid_expr(rule)} AND (rx_power < {rule['onu_rx_low_dbm']} OR rx_power > {rule['onu_rx_high_dbm']}))"


def score_onu(row):
    score = 0
    rx = row.get("rx_power")
    if rx is not None and -35 < float(rx) < -5:
        score += 100
    if row.get("tx_power") is not None:
        score += 20
    if str(row.get("status")) in ("1", "online", "up"):
        score += 20
    if row.get("source_type") == "local":
        score += 15
    model = (row.get("device_model") or "").lower()
    if "h3c" in model:
        score += 8
    if row.get("query_time"):
        score += 5
    return score


@netops2026_bp.post("/auth/login")
def login_route():
    payload = request.get_json(silent=True) or {}
    account = (payload.get("account") or "").strip()
    password = (payload.get("password") or "").strip()
    if not account or not password:
        return fail(BAD_REQUEST, "账号和密码不能为空")
    data, error = base_login(request, account, password)
    if error:
        return fail(UNAUTHORIZED, error, http_status=401)
    return success(data)


@netops2026_bp.get("/auth/me")
@login_required
def me_route():
    return success({"user": g.current_user.to_public_dict(), "next_action": next_action_for_user(g.current_user)})


@netops2026_bp.post("/auth/change-password")
@login_required
def change_password_route():
    payload = request.get_json(silent=True) or {}
    data, error = base_change_password(
        request,
        g.current_user,
        payload.get("old_password") or "",
        payload.get("new_password") or "",
    )
    if error:
        return fail(BAD_REQUEST, error)
    return success(data)


@netops2026_bp.route("/aiops/<path:path>", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
@login_required
def aiops_proxy_route(path):
    """Authenticated BFF entry point for all embedded AIOps pages."""
    return aiops_proxy(path)


@netops2026_bp.get("/navigation")
@login_required
def navigation_route():
    """Return enabled menus that the current role and user type may access."""
    role_rank = {"normal_user": 1, "org_admin": 2, "super_admin": 3}
    user_role = getattr(g.current_user, "role_code", "normal_user") or "normal_user"
    user_type = getattr(g.current_user, "user_type", "internal") or "internal"
    visible = []
    menus = AppMenu.query.filter(AppMenu.enabled.is_(True), AppMenu.menu_key.like("netops.%")).order_by(AppMenu.group_name.asc(), AppMenu.sort_order.asc(), AppMenu.id.asc()).all()
    for menu in menus:
        if menu.menu_key in AIOPS_ENTRY_KEYS and not aiops_page_audience_allowed():
            continue
        if role_rank.get(user_role, 1) < role_rank.get(menu.min_role or "normal_user", 1):
            continue
        if user_role != "super_admin" and menu.user_type not in (None, "", "all", user_type):
            continue
        visible.append(menu.to_dict())
    return success({"items": visible})


@netops2026_bp.get("/system/audit")
@login_required
def system_audit_route():
    """Super-admin-only audit dashboard backed by platform request audit records."""
    if getattr(g.current_user, "role_code", "") != "super_admin":
        return fail(UNAUTHORIZED, "系统审计仅限超级管理员访问", http_status=403)
    ensure_usage_audit_schema()
    backfill_platform_audit_history()
    try:
        hours = min(max(int(request.args.get("hours", 168)), 1), 2160)
        page = max(int(request.args.get("page", 1)), 1)
        page_size = min(max(int(request.args.get("page_size", 30)), 1), 100)
        user_id = int(request.args["user_id"]) if request.args.get("user_id") else None
    except ValueError:
        return fail(BAD_REQUEST, "筛选参数格式不正确")
    module = (request.args.get("module") or "").strip()
    result = (request.args.get("result") or "").strip()
    keyword = (request.args.get("keyword") or "").strip()[:64]
    # The backfill marker is bookkeeping, not a user-facing platform action.
    # Keep it out of all dashboard metrics and audit rows.
    clauses = ["occurred_at >= DATE_SUB(NOW(), INTERVAL %s HOUR)", "request_path<>%s"]
    args = [hours, "/__system_audit_backfill__"]
    if module:
        clauses.append("module=%s")
        args.append(module)
    if result:
        clauses.append("result=%s")
        args.append(result)
    if user_id is not None:
        clauses.append("user_id=%s")
        args.append(user_id)
    if keyword:
        clauses.append("(username LIKE %s OR display_name LIKE %s OR action LIKE %s OR request_path LIKE %s)")
        args.extend([f"%{keyword}%"] * 4)
    where = " WHERE " + " AND ".join(clauses)
    overview = query_one(
        """
        SELECT COUNT(*) AS request_count,
               COUNT(DISTINCT CASE WHEN user_id IS NOT NULL THEN user_id END) AS active_users,
               COALESCE(SUM(action='login' AND result='success'), 0) AS login_success,
               COALESCE(SUM(action='login' AND result<>'success'), 0) AS login_failed,
               COALESCE(SUM(module='aiops'), 0) AS aiops_requests,
               COALESCE(SUM(method IN ('POST','PUT','PATCH','DELETE')), 0) AS write_requests
        FROM netops2026_usage_audit_log
        """ + where,
        tuple(args),
    ) or {}
    trends = query_all(
        """
        SELECT DATE_FORMAT(occurred_at, '%%Y-%%m-%%d') AS day,
               COUNT(*) AS request_count,
               COUNT(DISTINCT CASE WHEN user_id IS NOT NULL THEN user_id END) AS active_users,
               COALESCE(SUM(action='login' AND result='success'), 0) AS login_success,
               COALESCE(SUM(module='aiops'), 0) AS aiops_requests
        FROM netops2026_usage_audit_log
        """ + where + " GROUP BY DATE_FORMAT(occurred_at, '%%Y-%%m-%%d') ORDER BY day ASC",
        tuple(args),
    )
    modules = query_all(
        """
        SELECT module, COUNT(*) AS request_count,
               COUNT(DISTINCT CASE WHEN user_id IS NOT NULL THEN user_id END) AS active_users,
               COALESCE(SUM(result='success'), 0) AS success_count,
               COALESCE(SUM(result<>'success'), 0) AS failure_count
        FROM netops2026_usage_audit_log
        """ + where + " GROUP BY module ORDER BY request_count DESC, module ASC LIMIT 12",
        tuple(args),
    )
    features = query_all(
        """
        SELECT module, action, COUNT(*) AS request_count,
               COUNT(DISTINCT CASE WHEN user_id IS NOT NULL THEN user_id END) AS active_users,
               MAX(occurred_at) AS last_used_at
        FROM netops2026_usage_audit_log
        """ + where + " GROUP BY module, action ORDER BY request_count DESC, last_used_at DESC LIMIT 12",
        tuple(args),
    )
    users = query_all(
        """
        SELECT user_id, MAX(COALESCE(display_name, username, CONCAT('用户 ', user_id))) AS display_name,
               MAX(username) AS username, MAX(role_code) AS role_code, MAX(org_name) AS org_name,
               COUNT(*) AS request_count, MAX(occurred_at) AS last_used_at
        FROM netops2026_usage_audit_log
        """ + where + " AND user_id IS NOT NULL GROUP BY user_id ORDER BY request_count DESC, last_used_at DESC LIMIT 12",
        tuple(args),
    )
    total_row = query_one("SELECT COUNT(*) AS total FROM netops2026_usage_audit_log" + where, tuple(args)) or {"total": 0}
    rows = query_all(
        """
        SELECT id, occurred_at, user_id,
               COALESCE(NULLIF(username, ''), '未绑定平台账号') AS username,
               CASE
                   WHEN COALESCE(display_name, '') <> '' THEN display_name
                   WHEN COALESCE(username, '') <> '' THEN username
                   WHEN client_ip IN ('127.0.0.1', '::1') THEN '系统探针'
                   ELSE '未认证访问'
               END AS display_name,
               role_code, org_name,
               module, action, method, request_path, result, status_code, duration_ms, client_ip
        FROM netops2026_usage_audit_log
        """ + where + " ORDER BY occurred_at DESC, id DESC LIMIT %s OFFSET %s",
        tuple(args + [page_size, (page - 1) * page_size]),
    )
    return success({
        "overview": json_ready(overview),
        "trends": [json_ready(row) for row in trends],
        "modules": [json_ready(row) for row in modules],
        "features": [json_ready(row) for row in features],
        "users": [json_ready(row) for row in users],
        "items": [json_ready(row) for row in rows],
        "total": int(total_row.get("total") or 0),
        "page": page,
        "page_size": page_size,
        "hours": hours,
        "filters": {"module": module or None, "result": result or None, "user_id": user_id, "keyword": keyword or None},
    })


@netops2026_bp.get("/access/users")
@login_required
def access_users_route():
    denied = ensure_platform_admin()
    if denied:
        return denied
    query = User.query
    ids = visible_user_org_ids()
    if ids is not None:
        query = query.filter(User.org_id.in_(ids), User.role_code != "super_admin")
    keyword = (request.args.get("keyword") or "").strip()
    if keyword:
        like = f"%{keyword}%"
        query = query.filter(or_(
            User.real_name.like(like),
            User.mobile.like(like),
            User.oa_username.like(like),
            User.oss_account.like(like),
        ))
    for field in ("role_code", "status", "oss_bind_status", "user_type"):
        value = (request.args.get(field) or "").strip()
        if value:
            query = query.filter(getattr(User, field) == value)
    org_id = (request.args.get("org_id") or "").strip()
    try:
        if org_id:
            if org_id == "unassigned":
                query = query.filter(User.org_id.is_(None))
            else:
                selected_ids = org_subtree_ids(int(org_id), ids)
                query = query.filter(User.org_id.in_(selected_ids)) if selected_ids else query.filter(false())
        page = max(int(request.args.get("page", 1)), 1)
        page_size = min(max(int(request.args.get("page_size", 20)), 1), 100)
    except ValueError:
        return fail(BAD_REQUEST, "筛选或分页参数无效")
    sort_column = {"name": User.real_name, "role": User.role_code}.get(request.args.get("sort_by"), User.real_name)
    sort_expr = sort_column.desc() if request.args.get("sort_order") == "desc" else sort_column.asc()
    total = query.count()
    users = query.order_by(sort_expr, User.id.asc()).offset((page - 1) * page_size).limit(page_size).all()
    return success({"items": [user.to_public_dict() for user in users], "total": total, "page": page, "page_size": page_size})


@netops2026_bp.get("/access/orgs/tree")
@login_required
def access_org_tree_route():
    denied = ensure_platform_admin()
    if denied:
        return denied
    ids = visible_user_org_ids()
    query = OrgUnit.query.filter_by(status="active")
    if ids is not None:
        query = query.filter(OrgUnit.id.in_(ids))
    orgs = query.order_by(OrgUnit.level, OrgUnit.sort_order, OrgUnit.id).all()
    visible = {org.id for org in orgs}
    user_query = User.query
    if ids is not None:
        user_query = user_query.filter(User.org_id.in_(ids), User.role_code != "super_admin")
    total_count = user_query.count()
    unassigned_count = user_query.filter(User.org_id.is_(None)).count()
    direct_counts = dict(
        user_query.with_entities(User.org_id, func.count(User.id))
        .filter(User.org_id.in_(visible) if visible else false())
        .group_by(User.org_id)
        .all()
    )
    subtree_counts = {org.id: int(direct_counts.get(org.id, 0)) for org in orgs}
    for org in sorted(orgs, key=lambda item: item.level or 0, reverse=True):
        if org.parent_id in subtree_counts:
            subtree_counts[org.parent_id] += subtree_counts[org.id]
    items = []
    for org in orgs:
        item = org.to_dict()
        if item.get("parent_id") not in visible:
            item["parent_id"] = None
        item["user_count"] = subtree_counts[org.id]
        items.append(item)
    return success({"items": items, "total": total_count, "unassigned_count": unassigned_count})


@netops2026_bp.delete("/access/users/<int:user_id>")
@login_required
def access_user_delete_route(user_id):
    denied = ensure_platform_admin()
    if denied:
        return denied
    target = db.session.get(User, user_id)
    if target is None:
        return fail(BAD_REQUEST, "用户不存在", http_status=404)
    if target.id == g.current_user.id:
        return fail(BAD_REQUEST, "不能删除当前登录账号")

    ids = visible_user_org_ids()
    if ids is not None and (
        target.org_id not in set(ids)
        or target.user_type != "internal"
        or target.role_code != "normal_user"
    ):
        return fail(UNAUTHORIZED, "当前账号无权删除该用户", http_status=403)
    if target.role_code == "super_admin" and target.status == "active":
        active_admins = User.query.filter_by(role_code="super_admin", status="active").count()
        if active_admins <= 1:
            return fail(BAD_REQUEST, "不能删除最后一个启用中的系统管理员")

    target_summary = {
        "id": target.id,
        "real_name": target.real_name,
        "mobile": target.mobile,
        "role_code": target.role_code,
    }
    try:
        # 历史日志和工单保留，仅解除用户外键；用户专属共享关系直接移除。
        db.session.execute(text("DELETE FROM server_asset_shares WHERE user_id=:user_id"), {"user_id": target.id})
        for table_name, column_name in (
            ("login_logs", "user_id"),
            ("operation_logs", "user_id"),
            ("server_assets", "owner_id"),
            ("work_order_comments", "user_id"),
            ("work_order_logs", "actor_id"),
            ("work_orders", "assignee_id"),
            ("work_orders", "creator_id"),
        ):
            db.session.execute(
                text(f"UPDATE {table_name} SET {column_name}=NULL WHERE {column_name}=:user_id"),
                {"user_id": target.id},
            )
        db.session.add(OperationLog(
            user_id=g.current_user.id,
            module="admin.users",
            action="delete",
            target_type="user",
            target_id=str(target.id),
            detail=json.dumps(target_summary, ensure_ascii=False, separators=(",", ":")),
            ip=request.remote_addr,
        ))
        db.session.delete(target)
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception("delete user failed: user_id=%s", user_id)
        return fail(SERVER_ERROR, "删除用户失败，请检查关联数据", http_status=500)
    return success({"deleted_id": user_id})


@netops2026_bp.get("/access/user-options")
@login_required
def access_user_options_route():
    denied = ensure_platform_admin()
    if denied:
        return denied
    ids = visible_user_org_ids()
    query = OrgUnit.query.filter_by(status="active")
    if ids is not None:
        query = query.filter(OrgUnit.id.in_(ids))
    orgs = query.order_by(OrgUnit.level, OrgUnit.sort_order, OrgUnit.id).all()
    role_codes = ["super_admin", "org_admin", "normal_user"] if ids is None else ["normal_user"]
    return success({
        "orgs": [{**org.to_dict(), "display_name": org.name} for org in orgs],
        "role_codes": role_codes,
        "user_types": ["internal", "external", "system"] if ids is None else ["internal", "external"],
        "statuses": ["active", "disabled", "pending"],
        "oss_bind_statuses": ["unbound", "pending", "bound", "failed"],
    })


@netops2026_bp.get("/device-orgs")
@login_required
def device_orgs_route():
    regions = allowed_device_regions()
    clauses = ["status='active'"]
    args = []
    if regions is not None:
        if not regions:
            return success({"items": []})
        clauses.append(f"region_code IN ({mysql_placeholders(regions)})")
        args.extend(regions)
    nodes = query_all(
        f"SELECT * FROM netops2026_device_org WHERE {' AND '.join(clauses)} ORDER BY parent_id IS NOT NULL,sort_order,name",
        tuple(args),
    )
    count_clauses = ["is_active=1"]
    count_args = []
    if regions is not None:
        count_clauses.append(f"region IN ({mysql_placeholders(regions)})")
        count_args.extend(regions)
    counts = query_all(
        f"SELECT region,room,COUNT(*) AS total FROM olt_devices WHERE {' AND '.join(count_clauses)} GROUP BY region,room",
        tuple(count_args),
    )
    room_counts = {(row["region"], row["room"]): int(row["total"]) for row in counts}
    region_counts = {}
    for row in counts:
        region_counts[row["region"]] = region_counts.get(row["region"], 0) + int(row["total"])
    for node in nodes:
        node["device_count"] = region_counts.get(node["region_code"], 0) if node["node_type"] == "region" else room_counts.get((node["region_code"], node["name"]), 0)
    return success({"items": [json_ready(row) for row in nodes]})


@netops2026_bp.post("/device-orgs")
@login_required
def device_org_create_route():
    denied = ensure_platform_admin()
    if denied:
        return denied
    ensure_device_org_schema()
    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()
    node_type = (payload.get("node_type") or "room").strip()
    parent_id = payload.get("parent_id")
    if not name or node_type not in ("region", "room"):
        return fail(BAD_REQUEST, "组织名称或类型无效")
    if node_type == "region":
        region_code = (payload.get("region_code") or "").strip().lower()
        if not re.fullmatch(r"[a-z0-9_]+", region_code):
            return fail(BAD_REQUEST, "区域编码只能包含小写字母、数字和下划线")
        parent_id = None
    else:
        parent = query_one("SELECT id,region_code FROM netops2026_device_org WHERE id=%s AND node_type='region'", (parent_id,))
        if not parent:
            return fail(BAD_REQUEST, "机房必须放在区域下")
        region_code = parent["region_code"]
    try:
        item_id, _ = execute_write(
            "INSERT INTO netops2026_device_org(parent_id,node_type,region_code,name,sort_order) VALUES(%s,%s,%s,%s,%s)",
            (parent_id, node_type, region_code, name, int(payload.get("sort_order") or 0)),
        )
    except pymysql.IntegrityError:
        return fail(BAD_REQUEST, "同级下已存在同名组织")
    return success({"id": item_id})


@netops2026_bp.put("/device-orgs/<int:org_id>")
@login_required
def device_org_update_route(org_id):
    denied = ensure_platform_admin()
    if denied:
        return denied
    ensure_device_org_schema()
    current = query_one("SELECT * FROM netops2026_device_org WHERE id=%s", (org_id,))
    if not current:
        return fail(BAD_REQUEST, "设备组织不存在")
    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or current["name"]).strip()
    sort_order = int(payload.get("sort_order", current["sort_order"]) or 0)
    if current["node_type"] == "room" and name != current["name"]:
        execute_write("UPDATE olt_devices SET room=%s WHERE region=%s AND room=%s", (name, current["region_code"], current["name"]))
    execute_write("UPDATE netops2026_device_org SET name=%s,sort_order=%s WHERE id=%s", (name, sort_order, org_id))
    return success({"id": org_id})


@netops2026_bp.post("/device-orgs/<int:org_id>/move")
@login_required
def device_org_move_route(org_id):
    denied = ensure_platform_admin()
    if denied:
        return denied
    ensure_device_org_schema()
    current = query_one("SELECT * FROM netops2026_device_org WHERE id=%s", (org_id,))
    payload = request.get_json(silent=True) or {}
    if not current:
        return fail(BAD_REQUEST, "设备组织不存在")
    if current["node_type"] == "region":
        execute_write("UPDATE netops2026_device_org SET sort_order=%s WHERE id=%s", (int(payload.get("sort_order") or 0), org_id))
        return success({"id": org_id})
    parent = query_one("SELECT id,region_code FROM netops2026_device_org WHERE id=%s AND node_type='region'", (payload.get("parent_id"),))
    if not parent:
        return fail(BAD_REQUEST, "目标必须是区域组织")
    execute_write("UPDATE olt_devices SET region=%s WHERE region=%s AND room=%s", (parent["region_code"], current["region_code"], current["name"]))
    execute_write("UPDATE netops2026_device_org SET parent_id=%s,region_code=%s,sort_order=%s WHERE id=%s", (parent["id"], parent["region_code"], int(payload.get("sort_order") or 0), org_id))
    return success({"id": org_id})


@netops2026_bp.delete("/device-orgs/<int:org_id>")
@login_required
def device_org_delete_route(org_id):
    denied = ensure_platform_admin()
    if denied:
        return denied
    ensure_device_org_schema()
    current = query_one("SELECT * FROM netops2026_device_org WHERE id=%s", (org_id,))
    if not current:
        return fail(BAD_REQUEST, "设备组织不存在")
    children = query_one("SELECT COUNT(*) AS total FROM netops2026_device_org WHERE parent_id=%s AND status='active'", (org_id,))["total"]
    devices = query_one(
        "SELECT COUNT(*) AS total FROM olt_devices WHERE is_active=1 AND region=%s" + ("" if current["node_type"] == "region" else " AND room=%s"),
        (current["region_code"],) if current["node_type"] == "region" else (current["region_code"], current["name"]),
    )["total"]
    if children or devices:
        return fail(BAD_REQUEST, "组织下仍有子组织或设备，不能删除")
    execute_write("DELETE FROM netops2026_device_org WHERE id=%s", (org_id,))
    return success({"deleted": True})


@netops2026_bp.get("/organization-mappings")
@login_required
def organization_mappings_route():
    if getattr(g.current_user, "role_code", "") != "super_admin":
        return fail(UNAUTHORIZED, "仅系统管理员可以维护跨域映射", http_status=403)
    mappings = query_all("SELECT * FROM netops2026_user_device_region_map WHERE enabled=1 ORDER BY user_org_id,device_region")
    by_org = {}
    for row in mappings:
        by_org.setdefault(int(row["user_org_id"]), []).append(row["device_region"])
    orgs = OrgUnit.query.filter_by(level=2, status="active").order_by(OrgUnit.sort_order, OrgUnit.id).all()
    return success({
        "items": [{"user_org_id": org.id, "user_org_name": org.name, "regions": by_org.get(org.id, [])} for org in orgs],
        "regions": [{"code": code, "name": name} for code, name in DEVICE_REGION_LABELS.items()],
    })


@netops2026_bp.put("/organization-mappings/<int:user_org_id>")
@login_required
def organization_mapping_update_route(user_org_id):
    denied = ensure_platform_admin()
    if denied:
        return denied
    ensure_device_org_schema()
    org = db.session.get(OrgUnit, user_org_id)
    if org is None or org.level != 2:
        return fail(BAD_REQUEST, "用户组织不存在或层级无效")
    payload = request.get_json(silent=True) or {}
    regions = sorted(set(payload.get("regions") or []))
    invalid = [region for region in regions if region not in DEVICE_REGION_LABELS]
    if invalid:
        return fail(BAD_REQUEST, "包含无效设备区域")
    execute_write("DELETE FROM netops2026_user_device_region_map WHERE user_org_id=%s", (user_org_id,))
    for region in regions:
        execute_write("INSERT INTO netops2026_user_device_region_map(user_org_id,user_org_name,device_region,enabled) VALUES(%s,%s,%s,1)", (org.id, org.name, region))
    if not regions:
        execute_write("INSERT INTO netops2026_user_device_region_map(user_org_id,user_org_name,device_region,enabled) VALUES(%s,%s,'__none__',0)", (org.id, org.name))
    return success({"user_org_id": user_org_id, "regions": regions})


@netops2026_bp.post("/user-orgs/<int:org_id>/move")
@login_required
def user_org_move_route(org_id):
    if getattr(g.current_user, "role_code", "") != "super_admin":
        return fail(UNAUTHORIZED, "当前账号没有管理权限", http_status=403)
    payload = request.get_json(silent=True) or {}
    source = db.session.get(OrgUnit, org_id)
    target = db.session.get(OrgUnit, payload.get("parent_id")) if payload.get("parent_id") else None
    if source is None or target is None or source.level == 1:
        return fail(BAD_REQUEST, "源组织或目标组织无效")
    if (target.path or "").startswith(source.path or "/invalid/"):
        return fail(BAD_REQUEST, "不能移动到自己的下级组织")
    descendants = OrgUnit.query.filter(OrgUnit.path.like(f"{source.path}%")).order_by(OrgUnit.level).all()
    delta = target.level + 1 - source.level
    if max((item.level + delta for item in descendants), default=source.level + delta) > 3:
        return fail(BAD_REQUEST, "移动后组织层级不能超过三级")
    old_path = source.path
    new_path = f"{target.path}{source.id}/"
    source.parent_id = target.id
    for item in descendants:
        item.path = new_path + item.path[len(old_path):]
        item.level += delta
    db.session.commit()
    return success({"id": source.id, "parent_id": target.id})


@netops2026_bp.get("/settings")
@login_required
def settings_get():
    return success({
        "quality": {"onu_rx_rule": quality_rule()},
        "performance": {"olt_rule": performance_rule()},
    })


@netops2026_bp.post("/settings/quality/onu-rx-rule")
@login_required
def settings_quality_onu_rx_rule():
    denied = ensure_platform_admin()
    if denied:
        return denied
    payload = request.get_json(silent=True) or {}
    rule = quality_rule()
    for key in ("onu_rx_low_dbm", "onu_rx_high_dbm", "onu_rx_invalid_min_dbm", "onu_rx_invalid_max_dbm", "onu_valid_rx_min_dbm", "onu_valid_rx_max_dbm"):
        if key in payload:
            try:
                rule[key] = float(payload[key])
            except (TypeError, ValueError):
                return fail(BAD_REQUEST, f"{key} 必须是数字")
    if rule["onu_rx_invalid_min_dbm"] >= rule["onu_rx_invalid_max_dbm"]:
        return fail(BAD_REQUEST, "无效值最小阈值必须小于最大阈值")
    if rule["onu_rx_low_dbm"] >= rule["onu_rx_high_dbm"]:
        return fail(BAD_REQUEST, "低光阈值必须小于高光阈值")
    if rule["onu_valid_rx_min_dbm"] >= rule["onu_valid_rx_max_dbm"]:
        return fail(BAD_REQUEST, "有效值范围最小值必须小于最大值")
    rule["onu_rule_version"] = str(payload.get("onu_rule_version") or f"onu_rx_web_{rule['onu_rx_low_dbm']}_{rule['onu_rx_high_dbm']}").strip()
    system_setting_set("quality.onu_rx_rule", rule)
    return success({"onu_rx_rule": rule})


@netops2026_bp.post("/settings/performance/olt-rule")
@login_required
def settings_performance_olt_rule():
    denied = ensure_platform_admin()
    if denied:
        return denied
    payload = request.get_json(silent=True) or {}
    rule = performance_rule()
    numeric_keys = (
        "olt_cpu_warning", "olt_cpu_critical", "olt_mem_warning", "olt_mem_critical",
        "board_cpu_warning", "board_cpu_critical", "board_mem_warning", "board_mem_critical",
        "stale_minutes",
    )
    for key in numeric_keys:
        if key in payload:
            try:
                rule[key] = float(payload[key])
            except (TypeError, ValueError):
                return fail(BAD_REQUEST, f"{key} 必须是数字")
    if "include_collect_failures" in payload:
        value = payload["include_collect_failures"]
        if isinstance(value, str):
            value = value.strip().lower() in ("1", "true", "yes", "on")
        rule["include_collect_failures"] = bool(value)
    if rule["olt_cpu_warning"] > rule["olt_cpu_critical"]:
        return fail(BAD_REQUEST, "OLT CPU 告警阈值不能大于严重阈值")
    if rule["olt_mem_warning"] > rule["olt_mem_critical"]:
        return fail(BAD_REQUEST, "OLT 内存告警阈值不能大于严重阈值")
    if rule["board_cpu_warning"] > rule["board_cpu_critical"]:
        return fail(BAD_REQUEST, "板卡 CPU 告警阈值不能大于严重阈值")
    if rule["board_mem_warning"] > rule["board_mem_critical"]:
        return fail(BAD_REQUEST, "板卡内存告警阈值不能大于严重阈值")
    if rule["stale_minutes"] <= 0:
        return fail(BAD_REQUEST, "采集超时分钟数必须大于 0")
    rule["rule_version"] = str(payload.get("rule_version") or rule.get("rule_version") or "olt_perf_web_80_90").strip()
    system_setting_set("performance.olt_rule", rule)
    return success({"olt_rule": rule})


@netops2026_bp.get("/infrastructure/overview")
@login_required
def infrastructure_overview():
    denied = ensure_super_admin()
    if denied:
        return denied
    return success(infrastructure_snapshot(force=request.args.get("refresh") == "1"))


@netops2026_bp.get("/infrastructure/logs")
@login_required
def infrastructure_logs():
    denied = ensure_super_admin()
    if denied:
        return denied
    node_id = str(request.args.get("node_id") or "").strip()
    service = str(request.args.get("service") or "").strip()
    limit = int_arg("limit", 80, 1, 200)
    config = infrastructure_conf()
    definition = next((item for item in config["nodes"].values() if item.get("id") == node_id), None)
    if not definition or not service:
        return fail(BAD_REQUEST, "节点或服务参数无效")
    payload, error = infrastructure_http_logs(definition, config["token"], service, limit)
    if error:
        return fail(SERVER_ERROR, error, http_status=502)
    return success({"node_id": node_id, "service": service, **payload})


@netops2026_bp.get("/dashboard")
@login_required
def dashboard():
    """Return the compact, permission-scoped data model used by the operations cockpit.

    This deliberately aggregates server-side: the home page must not fan out into a
    series of slow device, CMTS, quality and performance calls for regional users.
    """
    hours = int_arg("hours", 24, 1, 720)
    # The dashboard has three deliberate time ranges.  Keep an arbitrary URL from
    # accidentally creating a very expensive history query.
    hours = 24 if hours <= 24 else 168 if hours <= 168 else 720
    regions = allowed_device_regions()
    # User-facing metrics are scoped independently from device regions.  Include
    # that scope in the cache key so a regional administrator never receives a
    # previously cached global account count or visit total.
    user_scope = visible_user_org_ids()
    cache_params = {"hours": hours, "regions": regions, "user_scope": user_scope, "is_super_admin": getattr(g.current_user, "role_code", "") == "super_admin"}
    force_refresh = request.args.get("refresh") == "1"
    dashboard_cache_key = cache_key("operations_dashboard", cache_params)
    cached = cache_get_json(dashboard_cache_key)
    if cached is not None and not force_refresh:
        # Serve the most recent snapshot immediately.  Once it is one minute
        # old, one daemon thread recomputes it for the next view; concurrent
        # visitors keep receiving the usable snapshot instead of queueing on
        # identical MySQL/ClickHouse aggregates.
        if isinstance(cached, dict) and isinstance(cached.get("payload"), dict):
            payload = cached["payload"]
            age_seconds = max(0, time.time() - float(cached.get("generated_at") or 0))
        else:
            # Compatibility with cache entries written before SWR was added.
            payload, age_seconds = cached, float("inf")
        if age_seconds >= 60:
            schedule_dashboard_refresh(dashboard_cache_key, hours, int(g.current_user.id))
        return success(payload)
    region_where = ""
    region_args = []
    if regions is not None:
        region_where = " AND region IN (" + mysql_placeholders(regions) + ")" if regions else " AND 1=0"
        region_args = list(regions)
    olt_collect = query_one(
        f"""
        SELECT COUNT(*) AS total,
               SUM(last_result_status='success') AS success_count,
               SUM(last_result_status<>'success') AS fail_count,
               MAX(last_finished_at) AS latest_finished_at,
               ROUND(SUM(last_result_status='success') / NULLIF(COUNT(*), 0) * 100, 1) AS success_rate
        FROM olt_device_collect_overview
        WHERE is_active=1{region_where}
        """, tuple(region_args)
    )
    olt_device = query_one(f"SELECT COUNT(*) AS total FROM olt_devices WHERE is_active=1{region_where}", tuple(region_args))
    cmts_region_where = ""
    if regions is not None:
        cmts_region_where = " AND d.region IN (" + mysql_placeholders(regions) + ")" if regions else " AND 1=0"
    olt_region_where = ""
    if regions is not None:
        olt_region_where = " AND d.region IN (" + mysql_placeholders(regions) + ")" if regions else " AND 1=0"
    cmts_device = query_one(
        f"SELECT COUNT(*) AS total FROM cmts_devices d WHERE d.is_active=1{cmts_region_where}", tuple(region_args)
    )
    cmts_uses_overview = True
    try:
        cmts_collect = query_one(
            f"""
            SELECT COUNT(*) AS total,
                   SUM(o.last_result_status='success') AS success_count,
                   SUM(COALESCE(o.last_result_status, 'missing')<>'success') AS fail_count,
                   MAX(o.last_finished_at) AS latest_finished_at,
                   ROUND(SUM(o.last_result_status='success') / NULLIF(COUNT(*), 0) * 100, 1) AS success_rate
            FROM cmts_device_collect_overview o
            JOIN cmts_devices d ON d.cmts_device_id=o.cmts_device_id
            WHERE d.is_active=1{cmts_region_where}
            """, tuple(region_args)
        )
    except Exception:
        # Older production schemas have round history but not the current-state
        # overview table.  The newest round of every CMTS is an equivalent source
        # for the cockpit's current collection result.
        cmts_uses_overview = False
        cmts_collect = query_one(
            f"""
            SELECT COUNT(*) AS total,
                   SUM(h.is_snmp=1) AS success_count,
                   SUM(h.is_snmp<>1) AS fail_count,
                   MAX(h.finished_at) AS latest_finished_at,
                   ROUND(SUM(h.is_snmp=1) / NULLIF(COUNT(*), 0) * 100, 1) AS success_rate
            FROM cmts_collect_round_his h
            JOIN (
              SELECT cmts_device_id, MAX(finished_at) AS latest_finished_at
              FROM cmts_collect_round_his
              GROUP BY cmts_device_id
            ) latest ON latest.cmts_device_id=h.cmts_device_id AND latest.latest_finished_at=h.finished_at
            JOIN cmts_devices d ON d.cmts_device_id=h.cmts_device_id
            WHERE d.is_active=1{cmts_region_where}
            """, tuple(region_args)
        )
    quality = query_one(
        f"""
        SELECT COUNT(*) AS current_bad,
               SUM(quality_code='rx_low') AS rx_low,
               SUM(quality_code='rx_high') AS rx_high,
               SUM(quality_code='rx_missing') AS rx_missing,
               MAX(query_time) AS latest_time
        FROM olt_onu_last
        WHERE quality_bad=1{region_where}
        """, tuple(region_args)
    )
    perf_scope = ""
    perf_args = []
    if regions is not None:
        perf_scope = " AND d.region IN (" + mysql_placeholders(regions) + ")" if regions else " AND 1=0"
        perf_args = list(regions)
    rule = performance_rule()
    perf_rows = performance_current_rows([], "", rule)
    perf = performance_stats(perf_rows)
    ch_region = ""
    if regions is not None:
        ch_region = " AND region IN (" + ",".join(f"'{ch_escape(region)}'" for region in regions) + ")" if regions else " AND 1=0"
    try:
        quality_trend = ch_query(
            f"""
            SELECT toString(sample_date) AS stat_date,
                   countIf(quality_bad=1) AS bad_count,
                   count() AS total_count
            FROM onu_optical_sample
            -- Daily snapshots: exclude today's partial data to avoid a misleading last-point drop.
            WHERE sample_date >= today() - 7 AND sample_date < today(){ch_region}
            GROUP BY sample_date
            ORDER BY sample_date
            """
        )
        perf_trend = performance_trend(hours, [], bucket_hours=1 if hours <= 168 else 6)
    except Exception:
        # Historical charts are useful but must not turn a healthy cockpit into a
        # 500 page when ClickHouse is being maintained.
        quality_trend, perf_trend = [], []

    bucket_format = "%Y-%m-%d %H:00:00" if hours <= 168 else "%Y-%m-%d"
    collection_points = {}
    for kind, sql, args in (
        ("olt", f"""
            SELECT DATE_FORMAT(h.finished_at, %s) AS bucket, COUNT(*) AS total,
                   SUM(h.is_snmp=1) AS success_count, SUM(h.is_snmp<>1) AS fail_count
            FROM olt_collect_round_his h JOIN olt_devices d ON d.olt_device_id=h.olt_device_id
            WHERE h.finished_at >= NOW() - INTERVAL {hours} HOUR{perf_scope}
            GROUP BY bucket ORDER BY bucket
        """, [bucket_format] + perf_args),
        ("cmts", f"""
            SELECT DATE_FORMAT(h.finished_at, %s) AS bucket, COUNT(*) AS total,
                   SUM(h.is_snmp=1) AS success_count, SUM(h.is_snmp<>1) AS fail_count
            FROM cmts_collect_round_his h JOIN cmts_devices d ON d.cmts_device_id=h.cmts_device_id
            WHERE h.finished_at >= NOW() - INTERVAL {hours} HOUR{cmts_region_where}
            GROUP BY bucket ORDER BY bucket
        """, [bucket_format] + region_args),
    ):
        try:
            for row in query_all(sql, tuple(args)):
                point = collection_points.setdefault(str(row["bucket"]), {"sample_time": row["bucket"], "total": 0, "success_count": 0, "fail_count": 0})
                point["total"] += int(row.get("total") or 0)
                point["success_count"] += int(row.get("success_count") or 0)
                point["fail_count"] += int(row.get("fail_count") or 0)
        except Exception:
            # A partially upgraded collector database can lack CMTS history; the
            # current-round counters above remain available.
            continue
    collection_trend = []
    for point in collection_points.values():
        point["success_rate"] = round(point["success_count"] * 100 / point["total"], 1) if point["total"] else 0
        collection_trend.append(point)
    collection_trend.sort(key=lambda point: point["sample_time"])

    region_summary = {}
    def region_item(code):
        return region_summary.setdefault(code, {
            "region": code, "label": DEVICE_REGION_LABELS.get(code, "南京（未分区）" if code == "nanjing" else code),
            "olt_total": 0, "cmts_total": 0, "local_total": 0, "external_total": 0,
            "success_count": 0, "collect_total": 0, "risk_count": 0,
        })
    # Seed every region visible to the caller. A cockpit must show coverage gaps,
    # not silently hide regions that have no current collection record.
    visible_region_codes = regions if regions is not None else list(DEVICE_REGION_LABELS)
    for code in visible_region_codes:
        region_item(code)
    for row in query_all(
        f"""SELECT region, COUNT(*) AS total,
                   SUM(COALESCE(external_database, '')='') AS local_total,
                   SUM(COALESCE(external_database, '')<>'') AS external_total
            FROM olt_devices WHERE is_active=1{region_where} GROUP BY region""",
        tuple(region_args),
    ):
        item = region_item(row["region"])
        item["olt_total"] = int(row.get("total") or 0)
        item["local_total"] += int(row.get("local_total") or 0)
        item["external_total"] += int(row.get("external_total") or 0)
    for row in query_all(
        f"""SELECT d.region, COUNT(*) AS total,
                   SUM(COALESCE(d.external_database, '')='') AS local_total,
                   SUM(COALESCE(d.external_database, '')<>'') AS external_total
            FROM cmts_devices d WHERE d.is_active=1{cmts_region_where} GROUP BY d.region""",
        tuple(region_args),
    ):
        item = region_item(row["region"])
        item["cmts_total"] = int(row.get("total") or 0)
        item["local_total"] += int(row.get("local_total") or 0)
        item["external_total"] += int(row.get("external_total") or 0)
    cmts_region_collect_sql = (
        f"SELECT d.region, COUNT(*) AS total, SUM(o.last_result_status='success') AS success_count FROM cmts_device_collect_overview o JOIN cmts_devices d ON d.cmts_device_id=o.cmts_device_id WHERE d.is_active=1 AND COALESCE(d.external_database, '')=''{cmts_region_where} GROUP BY d.region"
        if cmts_uses_overview else
        f"""SELECT d.region, COUNT(*) AS total, SUM(h.is_snmp=1) AS success_count
            FROM cmts_collect_round_his h
            JOIN (SELECT cmts_device_id, MAX(finished_at) AS latest_finished_at FROM cmts_collect_round_his GROUP BY cmts_device_id) latest
              ON latest.cmts_device_id=h.cmts_device_id AND latest.latest_finished_at=h.finished_at
            JOIN cmts_devices d ON d.cmts_device_id=h.cmts_device_id
            WHERE d.is_active=1 AND COALESCE(d.external_database, '')=''{cmts_region_where} GROUP BY d.region"""
    )
    for sql, args in (
        (f"""SELECT d.region, COUNT(*) AS total, SUM(o.last_result_status='success') AS success_count
            FROM olt_device_collect_overview o JOIN olt_devices d ON d.olt_device_id=o.olt_device_id
            WHERE d.is_active=1 AND COALESCE(d.external_database, '')=''{olt_region_where} GROUP BY d.region""", region_args),
        (cmts_region_collect_sql, region_args),
    ):
        for row in query_all(sql, tuple(args)):
            item = region_item(row["region"])
            item["collect_total"] += int(row.get("total") or 0)
            item["success_count"] += int(row.get("success_count") or 0)
    for row in query_all(f"SELECT region, COUNT(*) AS total FROM olt_onu_last WHERE quality_bad=1{region_where} GROUP BY region", tuple(region_args)):
        region_item(row["region"])["risk_count"] += int(row.get("total") or 0)
    for row in perf_rows:
        if row.get("is_abnormal"):
            region_item(row.get("region") or "-")["risk_count"] += 1
    regions_overview = []
    for item in region_summary.values():
        item["device_total"] = item.pop("olt_total") + item.pop("cmts_total")
        # Only locally collected devices participate in this rate. Externally
        # synchronized devices are inventory coverage, not local collection failures.
        item["success_rate"] = round(item.pop("success_count") * 100 / item.pop("collect_total"), 1) if item.get("collect_total") else None
        regions_overview.append(item)
    region_order = {code: index for index, code in enumerate(DEVICE_REGION_LABELS)}
    regions_overview.sort(key=lambda item: (region_order.get(item["region"], 999), item["label"]))

    risk_groups = {}
    def add_risk_group(kind, severity, title, region, latest_time, path, count=1):
        key = (kind, severity, title, path)
        group = risk_groups.setdefault(key, {
            "kind": kind, "severity": severity, "title": title, "regions": set(),
            "latest_time": latest_time or "-", "path": path, "count": 0,
            "score": {"high": 3, "medium": 2, "low": 1}[severity],
        })
        group["count"] += int(count or 0)
        if region and region != "-":
            group["regions"].add(region)
        if str(latest_time or "") > str(group["latest_time"] or ""):
            group["latest_time"] = latest_time

    for row in perf_rows:
        if not row.get("is_abnormal"):
            continue
        severity = "high" if row.get("status") == "critical" else "medium" if row.get("status") == "warning" else "low"
        add_risk_group(
            "performance", severity, row.get("status_label") or "性能异常",
            DEVICE_REGION_LABELS.get(row.get("region"), row.get("region") or "-"), row.get("latest_time") or "-", "/performance",
        )
    quality_group_rows = query_all(
        f"""
        SELECT quality_code, COUNT(*) AS affected_count, MAX(query_time) AS latest_time,
               GROUP_CONCAT(DISTINCT region ORDER BY region SEPARATOR '、') AS region_names
        FROM olt_onu_last
        WHERE quality_bad=1{region_where}
        GROUP BY quality_code
        ORDER BY affected_count DESC
        """,
        tuple(region_args),
    )
    for row in quality_group_rows:
        region_names = "、".join(
            DEVICE_REGION_LABELS.get(code, code)
            for code in str(row.get("region_names") or "").split("、") if code
        )
        add_risk_group(
            "quality", "medium", quality_label(row.get("quality_code")), region_names,
            dt_value(row.get("latest_time")) or "-", "/quality", int(row.get("affected_count") or 0),
        )
    risks = []
    for group in risk_groups.values():
        region_names = sorted(group.pop("regions"))
        risks.append({
            **group,
            "region": "、".join(region_names[:3]) + ("等" if len(region_names) > 3 else ""),
            "device": f"影响 {int(group['count']):,} 个对象",
        })
    risks.sort(key=lambda item: (-item["score"], -item["count"], str(item["latest_time"])))

    olt_collect = json_ready(olt_collect or {})
    cmts_collect = json_ready(cmts_collect or {})
    olt_total = int((olt_device or {}).get("total") or 0)
    cmts_total = int((cmts_device or {}).get("total") or 0)
    olt_success, olt_fail = int((olt_collect or {}).get("success_count") or 0), int((olt_collect or {}).get("fail_count") or 0)
    cmts_success, cmts_fail = int((cmts_collect or {}).get("success_count") or 0), int((cmts_collect or {}).get("fail_count") or 0)
    collect = {
        "total": olt_success + olt_fail + cmts_success + cmts_fail,
        "success_count": olt_success + cmts_success,
        "fail_count": olt_fail + cmts_fail,
        "latest_finished_at": max([value for value in [dt_value((olt_collect or {}).get("latest_finished_at")), dt_value((cmts_collect or {}).get("latest_finished_at"))] if value] or [None]),
        "success_rate": round((olt_success + cmts_success) * 100 / max(olt_success + olt_fail + cmts_success + cmts_fail, 1), 1),
        "olt": {"total": olt_success + olt_fail, "success_count": olt_success, "fail_count": olt_fail, "success_rate": (olt_collect or {}).get("success_rate") or 0},
        "cmts": {"total": cmts_success + cmts_fail, "success_count": cmts_success, "fail_count": cmts_fail, "success_rate": (cmts_collect or {}).get("success_rate") or 0},
    }
    payload = {
        "hours": hours,
        "device": {"olt_total": olt_total, "cmts_total": cmts_total, "total": olt_total + cmts_total},
        "platform": dashboard_platform_stats(),
        "collect": collect,
        "quality": json_ready(quality),
        "perf": perf,
        "quality_trend": quality_trend,
        "performance_trend": perf_trend,
        "collection_trend": collection_trend,
        "risk_list": risks[:8],
        "risk_summary": {
            "total": int((quality or {}).get("current_bad") or 0) + sum(1 for row in perf_rows if row.get("is_abnormal")),
            "quality_count": int((quality or {}).get("current_bad") or 0),
            "performance_count": sum(1 for row in perf_rows if row.get("is_abnormal")),
        },
        "regions": regions_overview,
        "freshness": {
            "olt_collect": dt_value((olt_collect or {}).get("latest_finished_at")),
            "cmts_collect": dt_value((cmts_collect or {}).get("latest_finished_at")),
            "quality": dt_value((quality or {}).get("latest_time")),
            "performance": perf.get("latest_time"),
        },
    }
    # Infrastructure details are sensitive, so the unified cockpit only exposes
    # the concise component-light strip to super administrators.
    if getattr(g.current_user, "role_code", "") == "super_admin":
        infrastructure = infrastructure_snapshot()
        payload["infrastructure"] = {
            "observed_at": infrastructure.get("observed_at"),
            "summary": infrastructure.get("summary", {}),
            "components": infrastructure.get("components", [])[:12],
        }
    # Preserve the last successful cockpit model for instant page entry across
    # quiet periods and restarts.  The one-minute generated_at threshold still
    # controls background freshness.
    cache_set_json(dashboard_cache_key, {"generated_at": time.time(), "payload": payload}, 604800)
    return success(payload)


@netops2026_bp.get("/collector/overview")
@login_required
def collector_overview():
    clauses, args = ["is_active=1"], []
    append_region_scope(clauses, args, "region")
    rows = query_all(
        f"""
        SELECT olt_device_id, region, last_result_status, last_fail_reason,
               last_is_ping, last_is_snmp, last_mac_cnt, last_power_cnt,
               last_total_cost_ms, last_finished_at
        FROM olt_device_collect_overview
        WHERE {' AND '.join(clauses)}
        ORDER BY last_finished_at DESC
        LIMIT 80
        """, tuple(args)
    )
    return success([json_ready(r) for r in rows])


def collector_filter_clauses(prefix="d"):
    clauses = ["1=1"]
    args = []
    filters = {
        "region": f"{prefix}.region",
        "room_group": f"{prefix}.room_group",
        "room": f"{prefix}.room",
        "device_model": f"{prefix}.device_model",
    }
    for name, column in filters.items():
        value = (request.args.get(name) or "").strip()
        if value:
            clauses.append(f"{column}=%s")
            args.append(value)
    keyword = (request.args.get("keyword") or "").strip()
    if keyword:
        like = f"%{keyword}%"
        clauses.append(f"({prefix}.name LIKE %s OR {prefix}.primary_ip LIKE %s OR {prefix}.backup_ip LIKE %s)")
        args.extend([like, like, like])
    append_region_scope(clauses, args, f"{prefix}.region")
    return clauses, args


@netops2026_bp.get("/collector/tasks")
@login_required
def collector_tasks():
    page = int_arg("page", 1)
    size = int_arg("size", 20, 1, 100)
    offset = (page - 1) * size
    task_type = (request.args.get("task_type") or "").strip()
    status = (request.args.get("status") or "").strip()
    clauses = ["1=1"]
    args = []
    if task_type:
        clauses.append("task_type=%s")
        args.append(task_type)
    if status:
        clauses.append("status=%s")
        args.append(status)
    where = " AND ".join(clauses)
    rows = query_all(
        f"SELECT * FROM collector_task_overview WHERE {where} ORDER BY task_key LIMIT %s OFFSET %s",
        tuple(args + [size, offset]),
    )
    total = query_one(f"SELECT COUNT(*) AS total FROM collector_task_overview WHERE {where}", tuple(args))
    details = query_all("SELECT * FROM collector_task_detail ORDER BY task_key, detail_key")
    detail_map = {}
    for raw in details:
        detail_map.setdefault(raw["task_key"], []).append(json_ready(raw))
    items = []
    for raw in rows:
        item = json_ready(raw)
        item["details"] = detail_map.get(raw["task_key"], [])
        items.append(item)
    return success({"items": items, "total": int(total["total"]), "page": page, "size": size})


@netops2026_bp.get("/collector/batches")
@login_required
def collector_batches():
    """Aggregate per-device OLT collection rounds into their hourly batch key."""
    page = int_arg("page", 1)
    size = int_arg("size", 20, 1, 100)
    offset = (page - 1) * size
    hours = int_arg("hours", 48, 1, 720)
    long_cost_ms = int_arg("long_cost_ms", 60000, 1000, 3600000)
    clauses, args = collector_filter_clauses("d")
    clauses.extend([
        "COALESCE(h.collect_batches, '')<>''",
        f"h.finished_at >= NOW() - INTERVAL {hours} HOUR",
    ])
    where = " AND ".join(clauses)
    success_expr = "h.is_ping=1 AND h.is_snmp=1 AND COALESCE(h.fail_reason, '')=''"
    fields = f"""
        h.collect_batches,
        MIN(h.started_at) AS started_at,
        MAX(h.finished_at) AS finished_at,
        TIMESTAMPDIFF(MICROSECOND, MIN(h.started_at), MAX(h.finished_at)) DIV 1000 AS batch_cost_ms,
        COUNT(*) AS total_count,
        COUNT(DISTINCT h.olt_device_id) AS device_count,
        SUM({success_expr}) AS success_count,
        SUM(NOT ({success_expr})) AS fail_count,
        SUM(COALESCE(h.total_cost_ms, 0) >= %s) AS long_count,
        MAX(COALESCE(h.total_cost_ms, 0)) AS max_cost_ms,
        SUM(COALESCE(h.external_database, '')<>'') AS external_count
    """
    rows = query_all(
        f"""SELECT {fields}
            FROM olt_collect_round_his h JOIN olt_devices d ON d.olt_device_id=h.olt_device_id
            WHERE {where}
            GROUP BY h.collect_batches
            ORDER BY MAX(h.finished_at) DESC
            LIMIT %s OFFSET %s""",
        tuple([long_cost_ms] + args + [size, offset]),
    )
    total = query_one(
        f"""SELECT COUNT(*) AS total FROM (
                SELECT h.collect_batches
                FROM olt_collect_round_his h JOIN olt_devices d ON d.olt_device_id=h.olt_device_id
                WHERE {where}
                GROUP BY h.collect_batches
            ) batches""",
        tuple(args),
    )
    trend_rows = query_all(
        f"""SELECT h.collect_batches, MAX(h.finished_at) AS sample_time,
                   COUNT(*) AS total_count,
                   SUM({success_expr}) AS success_count,
                   SUM(NOT ({success_expr})) AS fail_count
            FROM olt_collect_round_his h JOIN olt_devices d ON d.olt_device_id=h.olt_device_id
            WHERE {where}
            GROUP BY h.collect_batches
            ORDER BY sample_time ASC""",
        tuple(args),
    )
    return success({
        "items": [json_ready(row) for row in rows],
        "trend": [json_ready(row) for row in trend_rows],
        "total": int(total["total"]),
        "page": page,
        "size": size,
        "hours": hours,
        "long_cost_ms": long_cost_ms,
    })


@netops2026_bp.get("/collector/devices")
@login_required
def collector_devices():
    page = int_arg("page", 1)
    size = int_arg("size", 30, 1, 100)
    offset = (page - 1) * size
    clauses, args = collector_filter_clauses("d")
    status = (request.args.get("status") or "").strip()
    source = (request.args.get("source") or "").strip()
    if status:
        clauses.append("COALESCE(o.last_result_status, 'missing')=%s")
        args.append(status)
    if source == "local":
        clauses.append("COALESCE(d.external_database, '')=''")
    elif source == "external":
        clauses.append("COALESCE(d.external_database, '')<>''")
    where = " AND ".join(clauses)
    fields = """
        d.olt_device_id, d.name, d.region, d.room_group, d.room, d.brand, d.device_model,
        d.primary_ip, d.backup_ip, d.external_database,
        COALESCE(o.last_result_status, 'missing') AS last_result_status, o.last_fail_reason,
        o.last_is_ping, o.last_is_snmp, o.last_snmp_version,
        o.last_if_cnt, o.last_mac_cnt, o.last_power_cnt,
        o.last_ping_cost_ms, o.last_snmp_cost_ms, o.last_total_cost_ms,
        o.last_started_at, o.last_finished_at, o.last_success_at
    """
    rows = query_all(
        f"SELECT {fields} FROM olt_devices d LEFT JOIN olt_device_collect_overview o ON o.olt_device_id=d.olt_device_id WHERE {where} ORDER BY o.last_finished_at DESC, d.olt_device_id LIMIT %s OFFSET %s",
        tuple(args + [size, offset]),
    )
    total = query_one(
        f"SELECT COUNT(*) AS total FROM olt_devices d LEFT JOIN olt_device_collect_overview o ON o.olt_device_id=d.olt_device_id WHERE {where}",
        tuple(args),
    )
    return success({"items": [json_ready(r) for r in rows], "total": int(total["total"]), "page": page, "size": size})


@netops2026_bp.get("/collector/history")
@login_required
def collector_history():
    page = int_arg("page", 1)
    size = int_arg("size", 30, 1, 100)
    offset = (page - 1) * size
    clauses, args = collector_filter_clauses("d")
    device_id = int_arg("olt_device_id", 0, 0, 100000000)
    if device_id:
        clauses.append("h.olt_device_id=%s")
        args.append(device_id)
    result = (request.args.get("result") or "").strip()
    if result == "success":
        clauses.append("h.is_ping=1 AND h.is_snmp=1 AND COALESCE(h.fail_reason, '')=''")
    elif result == "fail":
        clauses.append("(h.is_ping=0 OR h.is_snmp=0 OR COALESCE(h.fail_reason, '')<>'')")
    where = " AND ".join(clauses)
    rows = query_all(
        f"""SELECT h.round_id, h.olt_device_id, d.name, d.region, d.room_group, d.room, d.device_model,
                   d.primary_ip, h.external_database, h.collect_batches, h.is_ping, h.is_snmp,
                   h.snmp_version, h.fail_reason, h.if_cnt, h.mac_cnt, h.power_cnt,
                   h.ping_cost_ms, h.snmp_cost_ms, h.total_cost_ms, h.started_at, h.finished_at
            FROM olt_collect_round_his h JOIN olt_devices d ON d.olt_device_id=h.olt_device_id
            WHERE {where} ORDER BY h.finished_at DESC LIMIT %s OFFSET %s""",
        tuple(args + [size, offset]),
    )
    total = query_one(
        f"SELECT COUNT(*) AS total FROM olt_collect_round_his h JOIN olt_devices d ON d.olt_device_id=h.olt_device_id WHERE {where}",
        tuple(args),
    )
    return success({"items": [json_ready(r) for r in rows], "total": int(total["total"]), "page": page, "size": size})


@netops2026_bp.get("/olt/device-options")
@login_required
def olt_device_options():
    clauses, args = ["is_active=1"], []
    append_region_scope(clauses, args, "region")
    where = " AND ".join(clauses)
    rows = query_all(f"SELECT olt_device_id, name, region, room_group, room, brand, device_model FROM olt_devices WHERE {where} ORDER BY region, room_group, room, name", tuple(args))
    organizations = query_all(
        f"SELECT region, room_group, room, COUNT(*) AS device_count FROM olt_devices WHERE {where} GROUP BY region, room_group, room ORDER BY region, room_group, room",
        tuple(args),
    )
    def values(field):
        return sorted({str(row.get(field) or "").strip() for row in rows if str(row.get(field) or "").strip()})
    return success({
        "regions": values("region"), "room_groups": values("room_group"), "rooms": values("room"),
        "brands": values("brand"), "models": values("device_model"),
        "items": [json_ready(row) for row in rows],
        "organizations": [json_ready(row) for row in organizations],
    })


@netops2026_bp.get("/olt/devices")
@login_required
def olt_devices():
    page = int_arg("page", 1)
    size = int_arg("size", 30, 1, 100)
    offset = (page - 1) * size
    clauses, args = collector_filter_clauses("d")
    active = (request.args.get("active") or "").strip()
    if active in ("0", "1"):
        clauses.append("d.is_active=%s")
        args.append(int(active))
    where = " AND ".join(clauses)
    rows = query_all(
        f"""SELECT d.olt_device_id, d.name, d.region, d.room_group, d.room, d.brand, d.device_model,
                   d.primary_ip, d.backup_ip, IF(COALESCE(d.community, '')<>'', 1, 0) AS community_configured,
                   d.is_active, d.external_database, d.external_id, d.updated_at
            FROM olt_devices d WHERE {where}
            ORDER BY d.region, d.room_group, d.room, d.olt_device_id LIMIT %s OFFSET %s""",
        tuple(args + [size, offset]),
    )
    total = query_one(f"SELECT COUNT(*) AS total FROM olt_devices d WHERE {where}", tuple(args))
    return success({"items": [json_ready(r) for r in rows], "total": int(total["total"]), "page": page, "size": size})


def normalized_device_payload(payload, updating=False):
    fields = ("name", "region", "room_group", "room", "brand", "device_model", "primary_ip", "backup_ip", "community", "external_database")
    data = {field: (str(payload.get(field) or "").strip() or None) for field in fields}
    if not updating and (not data["name"] or not data["primary_ip"]):
        return None, "设备名称和主 IP 不能为空"
    data["is_active"] = 1 if str(payload.get("is_active", "1")).lower() not in ("0", "false", "off") else 0
    external_id = payload.get("external_id")
    try:
        data["external_id"] = int(external_id) if external_id not in (None, "") else None
    except (TypeError, ValueError):
        return None, "外部设备 ID 格式错误"
    return data, None


@netops2026_bp.post("/olt/devices")
@login_required
def olt_device_create():
    denied = ensure_platform_admin()
    if denied:
        return denied
    data, error = normalized_device_payload(request.get_json(silent=True) or {})
    if error:
        return fail(BAD_REQUEST, error)
    columns = list(data.keys())
    try:
        device_id, _ = execute_write(
            f"INSERT INTO olt_devices ({','.join(columns)}) VALUES ({mysql_placeholders(columns)})",
            tuple(data[column] for column in columns),
        )
    except pymysql.err.IntegrityError as exc:
        return fail(BAD_REQUEST, f"设备写入失败，IP 可能已存在：{exc}")
    redis_command("DEL", cache_key("olt_device_tree", {"active": 1}))
    return success({"olt_device_id": device_id})


@netops2026_bp.put("/olt/devices/<int:device_id>")
@login_required
def olt_device_update(device_id):
    denied = ensure_platform_admin()
    if denied:
        return denied
    existing = query_one("SELECT * FROM olt_devices WHERE olt_device_id=%s", (device_id,))
    if not existing:
        return fail(BAD_REQUEST, "设备不存在")
    payload = request.get_json(silent=True) or {}
    merged = {**existing, **payload}
    if "community" in payload and not str(payload.get("community") or "").strip():
        merged["community"] = existing.get("community")
    data, error = normalized_device_payload(merged, updating=True)
    if error:
        return fail(BAD_REQUEST, error)
    assignments = ",".join(f"{column}=%s" for column in data)
    execute_write(f"UPDATE olt_devices SET {assignments}, updated_at=NOW() WHERE olt_device_id=%s", tuple(data.values()) + (device_id,))
    redis_command("DEL", cache_key("olt_device_tree", {"active": 1}))
    return success({"olt_device_id": device_id})


@netops2026_bp.post("/olt/devices/organization")
@login_required
def olt_device_organization_update():
    denied = ensure_platform_admin()
    if denied:
        return denied
    payload = request.get_json(silent=True) or {}
    ids = sorted({int(value) for value in payload.get("olt_device_ids", []) if str(value).isdigit()})
    if not ids:
        return fail(BAD_REQUEST, "请选择设备")
    updates = []
    args = []
    for field in ("region", "room_group", "room"):
        if field in payload:
            updates.append(f"{field}=%s")
            args.append((str(payload.get(field) or "").strip() or None))
    if not updates:
        return fail(BAD_REQUEST, "没有可更新的设备组织字段")
    _, affected = execute_write(
        f"UPDATE olt_devices SET {','.join(updates)}, updated_at=NOW() WHERE olt_device_id IN ({mysql_placeholders(ids)})",
        tuple(args + ids),
    )
    redis_command("DEL", cache_key("olt_device_tree", {"active": 1}))
    return success({"updated_count": affected})


@netops2026_bp.post("/olt/probe")
@login_required
def olt_probe():
    payload = request.get_json(silent=True) or {}
    ip = (payload.get("primary_ip") or payload.get("ip") or "").strip()
    community = (payload.get("community") or "").strip()
    if not ip or not community:
        return fail(BAD_REQUEST, "IP 和团体号不能为空")
    try:
        return success(agent_post("/api/olt/probe", {"ip": ip, "community": community}, timeout=18))
    except Exception as exc:
        return fail(SERVER_ERROR, f"236 collector-agent 检测失败: {exc}", http_status=500)


def cmts_filter_clauses(prefix="d"):
    clauses, args = ["1=1"], []
    for name, column in {
        "region": f"{prefix}.region", "room_group": f"{prefix}.room_group",
        "room": f"{prefix}.room", "device_model": f"{prefix}.device_model",
    }.items():
        value = (request.args.get(name) or "").strip()
        if value:
            clauses.append(f"{column}=%s")
            args.append(value)
    keyword = (request.args.get("keyword") or "").strip()
    if keyword:
        like = f"%{keyword}%"
        clauses.append(f"({prefix}.name LIKE %s OR {prefix}.primary_ip LIKE %s OR {prefix}.backup_ip LIKE %s)")
        args.extend([like, like, like])
    append_region_scope(clauses, args, f"{prefix}.region")
    return clauses, args


def cmts_device_payload(payload, updating=False):
    fields = ("name", "region", "room_group", "room", "brand", "device_model", "primary_ip", "backup_ip", "community", "external_database")
    data = {field: (str(payload.get(field) or "").strip() or None) for field in fields}
    if not updating and (not data["name"] or not data["primary_ip"]):
        return None, "设备名称和主 IP 不能为空"
    data["is_active"] = 1 if str(payload.get("is_active", "1")).lower() not in ("0", "false", "off") else 0
    try:
        data["external_id"] = int(payload["external_id"]) if payload.get("external_id") not in (None, "") else None
    except (TypeError, ValueError):
        return None, "外部设备 ID 格式错误"
    return data, None


def can_manage_cmts_region(region):
    regions = allowed_device_regions()
    return regions is None or (region and region in regions)


@netops2026_bp.get("/cm/search")
@login_required
def cm_search():
    mac = normalize_mac(request.args.get("mac") or request.args.get("keyword") or "")
    if not mac:
        return success({"items": [], "primary": None})
    if len(mac) < 6 or not re.fullmatch(r"[0-9a-f]+", mac):
        return fail(BAD_REQUEST, "请输入至少 6 位有效的 CM MAC 地址")
    where, args = ["c.mac_address LIKE %s"], [f"{mac}%"]
    append_region_scope(where, args, "d.region")
    rows = query_all(
        f"""
        SELECT c.id, c.mac_address, c.cm_ip, c.cmts_device_id, c.if_index, c.uplink_port,
               c.down_if_index, c.downstream_port, c.snr, c.lvl, c.down_snr, c.down_lvl,
               c.query_time, c.collect_source, c.external_database, c.collect_batches,
               d.name AS cmts_name, d.region, d.room_group, d.room, d.brand, d.device_model,
               d.primary_ip, d.backup_ip, d.is_active AS cmts_active
        FROM cmts_cm_last c
        JOIN cmts_devices d ON d.cmts_device_id=c.cmts_device_id
        WHERE {' AND '.join(where)}
        ORDER BY c.query_time DESC, c.id DESC
        LIMIT 80
        """,
        tuple(args),
    )
    items = [json_ready(row) for row in rows]
    for index, item in enumerate(items):
        item["display_mac"] = fmt_mac(item.get("mac_address"))
        item["rank_label"] = "主记录" if index == 0 else "疑似重复记录"
    return success({"items": items, "primary": items[0] if items else None})


@netops2026_bp.get("/cmts/device-options")
@login_required
def cmts_device_options():
    clauses, args = ["1=1"], []
    append_region_scope(clauses, args, "region")
    rows = query_all(f"SELECT region,room_group,room,brand,device_model FROM cmts_devices WHERE {' AND '.join(clauses)}", tuple(args))
    def values(field):
        return sorted({str(row.get(field) or "").strip() for row in rows if str(row.get(field) or "").strip()})
    regions = values("region")
    for code in DEVICE_REGION_LABELS:
        if allowed_device_regions() is None or code in (allowed_device_regions() or []):
            if code not in regions:
                regions.append(code)
    return success({"regions": sorted(regions), "room_groups": values("room_group"), "rooms": values("room"), "brands": values("brand"), "models": values("device_model")})


@netops2026_bp.get("/cmts/devices")
@login_required
def cmts_devices():
    page = int_arg("page", 1)
    size = int_arg("size", 30, 1, 100)
    offset = (page - 1) * size
    clauses, args = cmts_filter_clauses("d")
    active = (request.args.get("active") or "").strip()
    if active in ("0", "1"):
        clauses.append("d.is_active=%s")
        args.append(int(active))
    where = " AND ".join(clauses)
    rows = query_all(
        f"""SELECT d.cmts_device_id,d.name,d.region,d.room_group,d.room,d.brand,d.device_model,
                   d.primary_ip,d.backup_ip,IF(COALESCE(d.community,'')<>'',1,0) AS community_configured,
                   d.is_active,d.external_database,d.external_id,d.created_at,
                   COUNT(c.id) AS cm_count,MAX(c.query_time) AS last_query_time
            FROM cmts_devices d LEFT JOIN cmts_cm_last c ON c.cmts_device_id=d.cmts_device_id
            WHERE {where}
            GROUP BY d.cmts_device_id
            ORDER BY d.region,d.room_group,d.room,d.cmts_device_id LIMIT %s OFFSET %s""",
        tuple(args + [size, offset]),
    )
    total = query_one(f"SELECT COUNT(*) AS total FROM cmts_devices d WHERE {where}", tuple(args))
    return success({"items": [json_ready(row) for row in rows], "total": int(total["total"]), "page": page, "size": size})


@netops2026_bp.post("/cmts/devices")
@login_required
def cmts_device_create():
    denied = ensure_platform_admin()
    if denied:
        return denied
    data, error = cmts_device_payload(request.get_json(silent=True) or {})
    if error:
        return fail(BAD_REQUEST, error)
    if not can_manage_cmts_region(data["region"]):
        return fail(UNAUTHORIZED, "无权在该区域维护 CMTS 设备", http_status=403)
    device_id, _ = execute_write(
        f"INSERT INTO cmts_devices ({','.join(data.keys())}) VALUES ({mysql_placeholders(data)})",
        tuple(data.values()),
    )
    return success({"cmts_device_id": device_id})


@netops2026_bp.put("/cmts/devices/<int:device_id>")
@login_required
def cmts_device_update(device_id):
    denied = ensure_platform_admin()
    if denied:
        return denied
    existing = query_one("SELECT * FROM cmts_devices WHERE cmts_device_id=%s", (device_id,))
    if not existing:
        return fail(BAD_REQUEST, "CMTS 设备不存在")
    payload = request.get_json(silent=True) or {}
    merged = {**existing, **payload}
    if "community" in payload and not str(payload.get("community") or "").strip():
        merged["community"] = existing.get("community")
    data, error = cmts_device_payload(merged, updating=True)
    if error:
        return fail(BAD_REQUEST, error)
    if not can_manage_cmts_region(existing.get("region")) or not can_manage_cmts_region(data["region"]):
        return fail(UNAUTHORIZED, "无权维护该区域的 CMTS 设备", http_status=403)
    assignments = ",".join(f"{column}=%s" for column in data)
    execute_write(f"UPDATE cmts_devices SET {assignments} WHERE cmts_device_id=%s", tuple(data.values()) + (device_id,))
    return success({"cmts_device_id": device_id})


@netops2026_bp.post("/boss/access")
@login_required
def boss_access():
    denied = ensure_boss_super_admin(require_sensitive_access=False)
    if denied:
        return denied
    if sensitive_rate_limited("access", 5, 300):
        write_sensitive_audit("access_rate_limited")
        return fail(UNAUTHORIZED, "密码验证次数过多，请 5 分钟后再试", http_status=429)
    password = str((request.get_json(silent=True) or {}).get("password") or "")
    if not password or not check_password_hash(g.current_user.password_hash, password):
        write_sensitive_audit("access_denied")
        return fail(UNAUTHORIZED, "登录密码验证失败", http_status=403)
    token, expires_at = issue_boss_access_token()
    write_sensitive_audit("access_granted", {"expires_at": expires_at})
    return no_store(success({"access_token": token, "expires_at": expires_at, "ttl_seconds": 300}))


@netops2026_bp.get("/boss/users")
@login_required
def boss_users():
    denied = ensure_boss_super_admin()
    if denied:
        return denied
    if sensitive_rate_limited("query", 20, 60):
        write_sensitive_audit("query_rate_limited")
        return fail(UNAUTHORIZED, "敏感查询过于频繁，请稍后再试", http_status=429)
    page = int_arg("page", 1)
    size = int_arg("size", 20, 1, 20)
    offset = (page - 1) * size
    keyword = (request.args.get("keyword") or "").strip()
    if not keyword:
        return no_store(success({"items": [], "total": 0, "page": page, "size": size, "query_required": True}))
    if len(keyword) < 4 or "%" in keyword or "_" in keyword:
        return fail(BAD_REQUEST, "请输入至少 4 个有效字符，且不能包含通配符")
    clauses = ["1=1"]
    args = []
    mac = normalize_mac(keyword)
    like = f"%{keyword}%"
    if len(mac) >= 6 and re.fullmatch(r"[0-9a-f]+", mac):
        clauses.append("(onu_mac_norm LIKE %s OR id_number LIKE %s OR name LIKE %s OR address LIKE %s OR region LIKE %s OR grid LIKE %s)")
        args.extend([f"{mac}%", like, like, like, like, like])
    else:
        clauses.append("(id_number LIKE %s OR name LIKE %s OR address LIKE %s OR region LIKE %s OR grid LIKE %s)")
        args.extend([like, like, like, like, like])
    where = " AND ".join(clauses)
    total = query_one(f"SELECT COUNT(*) AS total FROM boss_user_info WHERE {where}", tuple(args))
    rows = query_all(
        f"""
        SELECT id, company, id_number, name, address, phone1, phone2, region, grid,
               visit_datetime, onu_serial_number, onu_mac_norm
        FROM boss_user_info
        WHERE {where}
        ORDER BY visit_datetime DESC, id DESC
        LIMIT %s OFFSET %s
        """,
        tuple(args + [size, offset]),
    )
    items = [json_ready(r) for r in rows]
    for item in items:
        item["display_mac"] = fmt_mac(item.get("onu_mac_norm"))
        item["id_number"] = mask_account(item.get("id_number"))
        item["name"] = mask_name(item.get("name"))
        item["address"] = mask_address(item.get("address"))
        item["phone1"] = mask_phone(item.get("phone1"))
        item["phone2"] = mask_phone(item.get("phone2"))
    write_sensitive_audit("query", {"keyword_sha256": hashlib.sha256(keyword.encode("utf-8")).hexdigest(), "page": page, "result_count": len(items)})
    return no_store(success({"items": items, "total": int(total["total"]), "page": page, "size": size}))


@netops2026_bp.get("/boss/users/<int:row_id>")
@login_required
def boss_user_detail(row_id):
    denied = ensure_boss_super_admin()
    if denied:
        return denied
    if sensitive_rate_limited("detail", 30, 60):
        return fail(UNAUTHORIZED, "敏感详情访问过于频繁，请稍后再试", http_status=429)
    row = query_one(
        """SELECT id, company, id_number, name, address, phone1, phone2, region, grid,
                  visit_datetime, onu_serial_number, onu_mac_norm
           FROM boss_user_info WHERE id=%s LIMIT 1""",
        (row_id,),
    )
    if not row:
        return fail(BAD_REQUEST, "BOSS 用户记录不存在", http_status=404)
    item = json_ready(row)
    item["display_mac"] = fmt_mac(item.get("onu_mac_norm"))
    write_sensitive_audit("detail", {"row_id": row_id})
    return no_store(success(item))


@netops2026_bp.post("/boss/users/import")
@login_required
def boss_users_import():
    denied = ensure_boss_super_admin()
    if denied:
        return denied
    upload = request.files.get("file")
    if not upload:
        return fail(BAD_REQUEST, "请上传 Excel 文件")
    if not str(upload.filename or "").lower().endswith(".xlsx"):
        return fail(BAD_REQUEST, "仅允许上传 xlsx 文件")
    if request.content_length and request.content_length > 10 * 1024 * 1024:
        return fail(BAD_REQUEST, "Excel 文件不能超过 10MB", http_status=413)
    try:
        rows = read_xlsx_rows(upload)
    except Exception as exc:
        return fail(BAD_REQUEST, f"Excel 解析失败: {exc}")
    if not rows:
        return fail(BAD_REQUEST, "Excel 为空")
    headers = rows[0]
    mapping = boss_header_map(headers)
    required = {"company", "id_number", "region", "grid", "visit_datetime", "onu_serial_number"}
    missing = sorted(required - set(mapping))
    if missing:
        return fail(BAD_REQUEST, "缺少必要列: " + ", ".join(missing))

    total = valid = inserted = updated = skipped = 0
    with mysql_conn() as conn:
        with conn.cursor() as cur:
            for row in rows[1:]:
                total += 1
                def get(col):
                    idx = mapping[col]
                    return str(row[idx]).strip() if idx < len(row) and row[idx] is not None else ""
                onu_serial = get("onu_serial_number")
                mac_norm = normalize_mac(onu_serial)
                if len(mac_norm) != 12:
                    skipped += 1
                    continue
                valid += 1
                fields = {
                    "company": get("company"),
                    "id_number": get("id_number"),
                    "region": get("region"),
                    "grid": get("grid"),
                    "visit_datetime": parse_visit_datetime(get("visit_datetime")),
                    "onu_serial_number": onu_serial,
                }
                cur.execute("SELECT 1 FROM boss_user_info WHERE onu_mac_norm=%s LIMIT 1", (mac_norm,))
                exists = cur.fetchone() is not None
                if exists:
                    updates = []
                    args = []
                    for key, value in fields.items():
                        if value:
                            updates.append(f"{key}=%s")
                            args.append(value)
                    if updates:
                        args.append(mac_norm)
                        cur.execute(f"UPDATE boss_user_info SET {', '.join(updates)} WHERE onu_mac_norm=%s", tuple(args))
                        updated += cur.rowcount
                    else:
                        skipped += 1
                else:
                    cur.execute(
                        """
                        INSERT INTO boss_user_info
                          (company, id_number, region, grid, visit_datetime, onu_serial_number)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        """,
                        (
                            fields["company"] or None,
                            fields["id_number"] or None,
                            fields["region"] or None,
                            fields["grid"] or None,
                            fields["visit_datetime"],
                            fields["onu_serial_number"],
                        ),
                    )
                    inserted += 1
        conn.commit()
    result = {
        "total_rows": total,
        "valid_rows": valid,
        "inserted": inserted,
        "updated": updated,
        "skipped": skipped,
    }
    write_sensitive_audit("import", result)
    return no_store(success(result))


_mysql_table_presence_cache = {}


def mysql_table_exists(table_name, ttl_seconds=300):
    """Check optional integration tables without making their absence fatal."""
    if not re.fullmatch(r"[a-zA-Z0-9_]+", table_name or ""):
        return False
    cached = _mysql_table_presence_cache.get(table_name)
    now = time.monotonic()
    if cached and now - cached[0] < ttl_seconds:
        return cached[1]
    row = query_one(
        """
        SELECT 1 AS present
        FROM information_schema.TABLES
        WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=%s
        LIMIT 1
        """,
        (table_name,),
    )
    present = bool(row)
    _mysql_table_presence_cache[table_name] = (now, present)
    return present


def radius_terminal_evidence(terminal_mac, days=180):
    """Resolve a dialing-terminal MAC to accounts using Radius evidence only."""
    compact = normalize_mac(terminal_mac)
    if len(compact) != 12:
        return []
    return radius_ch_query(
        f"""
        SELECT username,
               argMax(mac_addr,event_time) AS mac_addr,
               countIf(event_type='auth' AND result_code=2) AS accept_count,
               countIf(event_type='auth' AND result_code=3) AS reject_count,
               countIf(event_type='accounting') AS accounting_count,
               uniqExactIf(acct_session_id,event_type='accounting' AND acct_session_id!='') AS session_count,
               argMaxIf(nas_ip,event_time,nas_ip!='') AS latest_nas_ip,
               argMaxIf(nas_port_id,event_time,nas_port_id!='') AS latest_nas_port_id,
               argMaxIf(framed_ip,event_time,framed_ip!='') AS latest_framed_ip,
               toString(max(event_time)) AS last_seen
        FROM radius_events
        WHERE event_time >= now() - INTERVAL {int(days)} DAY
          AND lower(replaceRegexpAll(mac_addr,'[^0-9a-fA-F]',''))='{ch_escape(compact)}'
          AND username!='' AND username!='(未匹配)'
        GROUP BY username
        ORDER BY accept_count DESC,accounting_count DESC,last_seen DESC
        LIMIT 20 FORMAT JSON
        """
    )


def gdf_account_keys(accounts):
    keys = []
    for value in accounts:
        account = str(value or "").strip().upper()
        if not account:
            continue
        keys.append(account)
        if re.fullmatch(r"GD[FC]\d{4,}", account):
            keys.append(account[3:])
    return list(dict.fromkeys(keys))


def boss_expected_onus_for_accounts(accounts):
    keys = gdf_account_keys(accounts)
    if not keys:
        return []
    placeholders = mysql_placeholders(keys)
    return query_all(
        f"""
        SELECT id_number AS gdf_account,onu_mac_norm AS onu_mac,
               region AS boss_region,grid AS boss_grid
        FROM boss_user_info
        WHERE UPPER(id_number) IN ({placeholders})
        ORDER BY id
        LIMIT 100
        """,
        tuple(keys),
    )


def optional_terminal_onu_mappings(terminal_mac):
    """Read the historical/live OLT FDB mapping when that optional table exists."""
    if (
        mysql_table_exists("olt_terminal_mac_snapshot_batch")
        and mysql_table_exists("olt_onu_terminal_mac_snapshot")
    ):
        batch = query_one(
            """
            SELECT batch_id,started_at,finished_at,status,device_count,success_device_count,
                   mapping_count,scope_description
            FROM olt_terminal_mac_snapshot_batch
            WHERE status IN ('completed','partial')
            ORDER BY finished_at DESC
            LIMIT 1
            """
        )
        if not batch:
            return [], {
                "available": False,
                "kind": "configured_no_snapshot",
                "label": "OLT 映射表已准备，尚无成功采集批次",
                "freshness": "当前 collector-agent 还没有安全的全厂商 OLT MAC 表采集接口",
            }
        rows = query_all(
            """
            SELECT olt_device_id,olt_name,vlan_id,if_index,port_name,onu_mac,terminal_mac,
                   NULL AS gdf_id,collected_at,batch_id
            FROM olt_onu_terminal_mac_snapshot
            WHERE batch_id=%s AND terminal_mac=%s
            ORDER BY olt_device_id,vlan_id,port_name
            LIMIT 50
            """,
            (batch["batch_id"], normalize_mac(terminal_mac)),
        )
        finished = dt_value(batch.get("finished_at"))
        return rows, {
            "available": True,
            "kind": "olt_fdb_snapshot",
            "label": f"OLT MAC 表映射快照（{batch.get('success_device_count') or 0}/{batch.get('device_count') or 0} 台）",
            "freshness": f"批次 {batch.get('batch_id')}，完成时间 {finished or '-'}；结论仅覆盖该批次声明范围",
            "batch": json_ready(batch),
        }
    if not mysql_table_exists("olt_onu_terminal_mac_once"):
        return [], {
            "available": False,
            "kind": "unavailable",
            "label": "OLT 终端映射尚未接入当前生产库",
            "freshness": "",
        }
    rows = query_all(
        """
        SELECT olt_device_id,olt_name,vlan_id,if_index,port_name,onu_mac,terminal_mac,gdf_id
        FROM olt_onu_terminal_mac_once
        WHERE terminal_mac=%s
        ORDER BY olt_device_id,vlan_id,port_name
        LIMIT 50
        """,
        (normalize_mac(terminal_mac),),
    )
    return rows, {
        "available": True,
        "kind": "olt_fdb_snapshot",
        "label": "OLT MAC 表映射快照",
        "freshness": "该历史表没有采集时间字段，仅作定位证据，不冒充实时结果",
    }


def onu_rows_for_macs(macs):
    compact_macs = [normalize_mac(item) for item in macs if len(normalize_mac(item)) == 12]
    compact_macs = list(dict.fromkeys(compact_macs))
    if not compact_macs:
        return []
    clauses = [f"l.mac_address IN ({mysql_placeholders(compact_macs)})"]
    args = list(compact_macs)
    append_region_scope(clauses, args, "d.region")
    return query_all(
        f"""
        SELECT
            l.mac_address AS onu_mac,l.mac_address AS onu_mac_norm,l.olt_device_id,
            d.name AS olt_name,d.room_group,d.room,d.device_model,d.primary_ip,d.backup_ip,
            l.region,l.if_index,l.port_if_index,l.uplink_port_norm,l.pon_port_norm AS pon_port,
            l.onu_port_norm,l.rx_power,l.tx_power,l.status,l.query_time,l.quality_bad,l.quality_code,
            b.name AS boss_customer_name,b.address AS boss_address,b.id_number AS gdf_account,
            b.region AS boss_region,b.grid AS boss_grid,
            '' AS product,'' AS access_type,'' AS service_status,'local' AS source_type
        FROM olt_onu_last l
        LEFT JOIN olt_devices d ON d.olt_device_id=l.olt_device_id
        LEFT JOIN boss_user_info b ON b.onu_mac_norm=l.mac_address
        WHERE {' AND '.join(clauses)}
        ORDER BY l.query_time DESC
        LIMIT 100
        """,
        tuple(args),
    )


def decorate_onu_items(rows):
    items = [json_ready(row) for row in rows]
    for item in items:
        item["display_mac"] = fmt_mac(item.get("onu_mac"))
        item["quality_label"] = quality_label(item.get("quality_code"))
        item["score"] = score_onu(item)
    items.sort(key=lambda row: (row["score"], row.get("query_time") or ""), reverse=True)
    for idx, item in enumerate(items):
        item["rank_label"] = "主记录" if idx == 0 else "疑似重复记录"
    return items


def terminal_mac_onu_result(terminal_mac):
    compact = normalize_mac(terminal_mac)
    evidence = radius_terminal_evidence(compact)
    verified_accounts = [
        str(row.get("username") or "")
        for row in evidence
        if int(row.get("accept_count") or 0) > 0
    ]
    accounting_accounts = [
        str(row.get("username") or "")
        for row in evidence
        if int(row.get("accounting_count") or 0) > 0
    ]
    observed_accounts = list(dict.fromkeys(verified_accounts + accounting_accounts))
    expected = boss_expected_onus_for_accounts(observed_accounts)
    mappings, mapping_source = optional_terminal_onu_mappings(compact)
    authorized_ids = authorized_device_ids()
    if authorized_ids is not None:
        allowed = set(authorized_ids)
        mappings = [row for row in mappings if int(row.get("olt_device_id") or 0) in allowed]
    expected_macs = [row.get("onu_mac") for row in expected if row.get("onu_mac")]
    actual_macs = [row.get("onu_mac") for row in mappings if row.get("onu_mac")]
    all_onu_macs = list(dict.fromkeys(actual_macs + expected_macs))
    items = decorate_onu_items(onu_rows_for_macs(all_onu_macs))

    expected_set = {normalize_mac(value) for value in expected_macs if len(normalize_mac(value)) == 12}
    actual_set = {normalize_mac(value) for value in actual_macs if len(normalize_mac(value)) == 12}
    if not evidence:
        status, label = "radius_not_seen", "近 180 天未发现该终端的 Radius 记录"
    elif not observed_accounts:
        status, label = "radius_reject_only", "仅发现认证拒绝，不能认定为实际使用"
    elif not expected_set:
        status, label = "boss_not_found", "已找到拨号账号，但 BOSS 未登记 ONU"
    elif not mapping_source["available"]:
        status, label = "olt_mapping_unavailable", "已找到 BOSS 预期 ONU，实际 OLT 映射待接入"
    elif not actual_set:
        status, label = "terminal_not_mapped", "终端 MAC 未在 OLT 映射快照中出现"
    elif len(actual_set) > 1:
        status, label = "multi_actual_onu", "终端 MAC 映射到多个 ONU，需人工复核"
    elif expected_set & actual_set:
        status, label = "correct_onu", "实际 ONU 与 BOSS 登记一致"
    else:
        status, label = "wrong_onu", "实际 ONU 与 BOSS 登记不一致"

    for item in items:
        mac = normalize_mac(item.get("onu_mac"))
        roles = []
        if mac in actual_set:
            roles.append("actual")
        if mac in expected_set:
            roles.append("expected")
        item["relation_role"] = "+".join(roles) or "related"
    items.sort(
        key=lambda row: (
            1 if "actual" in str(row.get("relation_role")) else 0,
            1 if "expected" in str(row.get("relation_role")) else 0,
            row.get("score") or 0,
            row.get("query_time") or "",
        ),
        reverse=True,
    )
    primary = items[0] if items else None
    resolution = {
        "terminal_mac": fmt_mac(compact),
        "terminal_mac_norm": compact,
        "accounts": observed_accounts,
        "verified_accounts": list(dict.fromkeys(verified_accounts)),
        "evidence": evidence,
        "expected_onus": [json_ready(row) for row in expected],
        "actual_mappings": [json_ready(row) for row in mappings],
        "mapping_source": mapping_source,
        "status": status,
        "status_label": label,
        "is_conclusive": status in ("correct_onu", "wrong_onu", "multi_actual_onu"),
    }
    return {"items": items, "primary": primary, "terminal_resolution": resolution}


@netops2026_bp.get("/onu/search")
@login_required
def onu_search():
    keyword = (request.args.get("keyword") or "").strip()
    search_type = (request.args.get("type") or "auto").strip()
    if not keyword:
        return success({"items": [], "primary": None})
    minimum = {"mac": 6, "terminal_mac": 12, "account": 4, "name": 2, "address": 4, "auto": 4}.get(search_type, 4)
    query_length = len(normalize_mac(keyword)) if search_type in ("mac", "terminal_mac") else len(keyword)
    if query_length < minimum:
        return fail(BAD_REQUEST, f"查询条件至少需要 {minimum} 个字符")
    if sensitive_rate_limited("onu_search", 60, 60):
        return fail(UNAUTHORIZED, "ONU 查询过于频繁，请稍后再试", http_status=429)
    if search_type == "terminal_mac":
        if query_length != 12:
            return fail(BAD_REQUEST, "请输入完整的 12 位用户拨号终端 MAC")
        denied = radius_guard()
        if denied:
            return denied
        return success(terminal_mac_onu_result(keyword))

    mac = normalize_mac(keyword)
    params = []
    account_join = "LEFT JOIN boss_user_info b ON b.onu_mac_norm=l.mac_address"
    select_cols = """
        l.mac_address AS onu_mac, l.mac_address AS onu_mac_norm, l.olt_device_id,
        d.name AS olt_name, d.room_group, d.room, d.device_model, d.primary_ip, d.backup_ip,
        l.region, l.if_index, l.port_if_index, l.uplink_port_norm, l.pon_port_norm AS pon_port,
        l.onu_port_norm, l.rx_power, l.tx_power, l.status, l.query_time, l.quality_bad, l.quality_code,
        b.name AS boss_customer_name,
        b.address AS boss_address,
        b.id_number AS gdf_account,
        b.region AS boss_region,
        b.grid AS boss_grid,
        '' AS product,
        '' AS access_type,
        '' AS service_status,
        'local' AS source_type
    """
    if search_type in ("mac", "auto") and len(mac) >= 6 and re.fullmatch(r"[0-9a-f]+", mac):
        where = "l.mac_address LIKE %s"
        params.append(f"{mac}%")
    elif search_type == "account":
        account = keyword.strip().upper()
        bare_account = account[3:] if re.fullmatch(r"GD[FC]\d{4,}", account) else account
        where = "(UPPER(b.id_number) LIKE %s OR UPPER(b.id_number) LIKE %s)"
        params.extend([f"%{account}%", f"%{bare_account}%"])
    elif search_type == "name":
        where = "b.name LIKE %s"
        params.append(f"%{keyword}%")
    elif search_type == "address":
        where = "b.address LIKE %s"
        params.append(f"%{keyword}%")
    else:
        where = "(d.name LIKE %s OR d.room LIKE %s OR d.room_group LIKE %s OR b.id_number LIKE %s OR b.name LIKE %s OR b.address LIKE %s)"
        params.extend([f"%{keyword}%"] * 6)

    scope_clauses, scope_args = [], []
    append_region_scope(scope_clauses, scope_args, "d.region")
    if scope_clauses:
        where = f"({where}) AND " + " AND ".join(scope_clauses)
        params.extend(scope_args)
    rows = query_all(
        f"""
        SELECT {select_cols}
        FROM olt_onu_last l
        LEFT JOIN olt_devices d ON d.olt_device_id=l.olt_device_id
        {account_join}
        WHERE {where}
        ORDER BY l.query_time DESC
        LIMIT 30
        """,
        tuple(params),
    )
    items = decorate_onu_items(rows)
    primary = items[0] if items else None
    return success({"items": items, "primary": primary, "terminal_resolution": None})


@netops2026_bp.get("/onu/history")
@login_required
def onu_history():
    mac = normalize_mac(request.args.get("onu_mac") or "")
    olt_device_id = request.args.get("olt_device_id")
    hours = int_arg("hours", 168, 1, 24 * 30)
    if not mac:
        return fail(BAD_REQUEST, "ONU MAC 不能为空")
    authorized_ids = authorized_device_ids()
    if olt_device_id and authorized_ids is not None and int(olt_device_id) not in authorized_ids:
        return fail(UNAUTHORIZED, "无权访问该设备数据", http_status=403)
    filters = [f"onu_mac = '{ch_escape(mac)}'", f"sample_time >= now() - INTERVAL {hours} HOUR"]
    if olt_device_id:
        filters.append(f"olt_device_id = {int(olt_device_id)}")
    sql = f"""
    SELECT toString(sample_time) AS sample_time, rx_power, tx_power, status, quality_bad, quality_code
    FROM (
        SELECT sample_time, rx_power, tx_power, status, quality_bad, quality_code
        FROM onu_optical_sample
        WHERE {' AND '.join(filters)}
        ORDER BY sample_time ASC
        LIMIT 1000
    )
    """
    return success({"items": ch_query(sql)})


@netops2026_bp.get("/olt/device-tree")
@login_required
def olt_device_tree():
    regions = allowed_device_regions()
    key = cache_key("olt_device_tree", {"active": 1, "regions": regions})
    cached = cache_get_json(key)
    if cached is not None and (request.args.get("no_cache") or "0") != "1":
        return success(cached)
    clauses, args = ["is_active=1"], []
    append_region_scope(clauses, args, "region")
    rows = query_all(
        f"""
        SELECT olt_device_id, name, region, room_group, room, device_model, primary_ip, backup_ip
        FROM olt_devices
        WHERE {' AND '.join(clauses)}
        ORDER BY room_group, room, name, olt_device_id
        """, tuple(args)
    )
    payload = {"items": [json_ready(r) for r in rows]}
    cache_set_json(key, payload, 600)
    return success(payload)


def quality_date_arg():
    date = (request.args.get("date") or datetime.now().strftime("%Y-%m-%d")).strip()
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        date = datetime.now().strftime("%Y-%m-%d")
    return date


def parse_olt_ids_arg():
    raw = (request.args.get("olt_device_ids") or "").strip()
    ids = []
    for part in raw.split(","):
        part = part.strip()
        if part.isdigit():
            ids.append(int(part))
    selected = sorted(set(ids))
    authorized = authorized_device_ids()
    if authorized is None:
        return selected
    allowed = set(authorized)
    return [item for item in selected if item in allowed] if selected else sorted(allowed)


def mysql_placeholders(values):
    return ",".join(["%s"] * len(values))


def quality_scope_ids():
    selected = parse_olt_ids_arg()
    if selected:
        return selected
    room_group = (request.args.get("room_group") or "").strip()
    room = (request.args.get("room") or "").strip()
    clauses = ["is_active=1"]
    args = []
    append_region_scope(clauses, args, "region")
    if room_group:
        clauses.append("room_group=%s")
        args.append(room_group)
    if room:
        clauses.append("room=%s")
        args.append(room)
    rows = query_all(
        f"SELECT olt_device_id FROM olt_devices WHERE {' AND '.join(clauses)} ORDER BY room_group, room, name",
        tuple(args),
    )
    return [int(r["olt_device_id"]) for r in rows]


def fetch_device_map(olt_ids):
    if not olt_ids:
        return {}
    rows = query_all(
        f"""
        SELECT olt_device_id, name AS olt_name, room_group, room, region, device_model, primary_ip, backup_ip
        FROM olt_devices
        WHERE olt_device_id IN ({mysql_placeholders(olt_ids)})
        """,
        tuple(olt_ids),
    )
    return {int(r["olt_device_id"]): json_ready(r) for r in rows}


def query_boss_map(macs):
    macs = sorted({normalize_mac(m) for m in macs if normalize_mac(m)})
    result = {}
    for i in range(0, len(macs), 800):
        chunk = macs[i:i + 800]
        rows = query_all(
            f"""
            SELECT onu_mac_norm, id_number AS gdf_account, name AS customer_name,
                   company, phone1, phone2, grid
            FROM boss_user_info
            WHERE onu_mac_norm IN ({mysql_placeholders(chunk)})
            """,
            tuple(chunk),
        )
        result.update({r["onu_mac_norm"]: json_ready(r) for r in rows})
    return result


def query_business_map(items):
    ips = set()
    ports = set()
    for item in items:
        for key in ("primary_ip", "backup_ip"):
            if item.get(key):
                ips.add(item[key])
        if item.get("pon_port"):
            ports.add(item["pon_port"])
    if not ips or not ports:
        return {}
    rows = query_all(
        f"""
        SELECT olt_ip, normalized_olt_port, business_type, optical_node_code, optical_node_location
        FROM olt_pon_business_info
        WHERE olt_ip IN ({mysql_placeholders(sorted(ips))})
          AND normalized_olt_port IN ({mysql_placeholders(sorted(ports))})
        """,
        tuple(sorted(ips) + sorted(ports)),
    )
    result = {}
    for row in rows:
        result.setdefault((row["olt_ip"], row["normalized_olt_port"]), json_ready(row))
    return result


def query_current_port_map(items):
    pairs = sorted({(int(i.get("olt_device_id") or 0), normalize_mac(i.get("onu_mac"))) for i in items if i.get("olt_device_id") and normalize_mac(i.get("onu_mac"))})
    result = {}
    if not pairs:
        return result
    olt_ids = sorted({olt_id for olt_id, _ in pairs})
    macs = sorted({mac for _, mac in pairs})
    for i in range(0, len(macs), 800):
        chunk = macs[i:i + 800]
        rows = query_all(
            f"""
            SELECT olt_device_id, mac_address, pon_port_norm, uplink_port_norm
            FROM olt_onu_last
            WHERE olt_device_id IN ({mysql_placeholders(olt_ids)})
              AND mac_address IN ({mysql_placeholders(chunk)})
            """,
            tuple(olt_ids + chunk),
        )
        for row in rows:
            result[(int(row["olt_device_id"]), row["mac_address"])] = json_ready(row)
    return result


def query_port_total_map(olt_ids):
    olt_ids = sorted({int(i) for i in olt_ids if i})
    if not olt_ids:
        return {}
    result = {}
    for i in range(0, len(olt_ids), 800):
        chunk = olt_ids[i:i + 800]
        rows = query_all(
            f"""
            SELECT olt_device_id,
                   COALESCE(NULLIF(pon_port_norm, ''), NULLIF(uplink_port_norm, ''), '未识别端口') AS pon_port,
                   COUNT(*) AS total_onu
            FROM olt_onu_last
            WHERE olt_device_id IN ({mysql_placeholders(chunk)})
            GROUP BY olt_device_id, pon_port
            """,
            tuple(chunk),
        )
        for row in rows:
            result[(int(row["olt_device_id"]), row["pon_port"] or "未识别端口")] = int(row["total_onu"] or 0)
    return result


def build_port_groups_from_bad_rows(rows, include_unknown_ports=False, pre_enriched=False):
    items = rows if pre_enriched else enrich_quality_items(
        rows, include_boss=False, include_business=True, include_current_port=False
    )
    total_map = query_port_total_map([item.get("olt_device_id") for item in items])
    groups = {}
    for item in items:
        olt_id = int(item.get("olt_device_id") or 0)
        port = item.get("pon_port") or "未识别端口"
        if str(port) == "0":
            port = "未识别端口"
        if port == "未识别端口" and not include_unknown_ports:
            continue
        key = (olt_id, port)
        group = groups.setdefault(key, {
            "region": item.get("region") or "",
            "olt_device_id": olt_id,
            "olt_name": item.get("olt_name") or "",
            "room_group": item.get("room_group") or "",
            "room": item.get("room") or "",
            "device_model": item.get("device_model") or "",
            "primary_ip": item.get("primary_ip") or "",
            "backup_ip": item.get("backup_ip") or "",
            "pon_port": port,
            "bad_count": 0,
            "total_onu": 0,
            "rx_low": 0,
            "rx_high": 0,
            "worst_rx": None,
            "latest_time": "",
            "business_type": item.get("business_type") or "",
            "optical_node_code": item.get("optical_node_code") or "",
            "optical_node_location": item.get("optical_node_location") or "",
        })
        group["bad_count"] += 1
        if item.get("quality_code") == "rx_high":
            group["rx_high"] += 1
        else:
            group["rx_low"] += 1
        try:
            rx = float(item.get("rx_power"))
            if group["worst_rx"] is None or rx < group["worst_rx"]:
                group["worst_rx"] = rx
        except (TypeError, ValueError):
            pass
        if str(item.get("query_time") or "") > str(group.get("latest_time") or ""):
            group["latest_time"] = item.get("query_time") or ""
        for key_name in ("business_type", "optical_node_code", "optical_node_location"):
            if not group.get(key_name) and item.get(key_name):
                group[key_name] = item.get(key_name) or ""
    result = []
    for key, group in groups.items():
        group["total_onu"] = total_map.get(key) or group["bad_count"]
        group["worst_rx"] = "" if group["worst_rx"] is None else round(group["worst_rx"], 2)
        result.append(group)
    result.sort(key=lambda row: (int(row["bad_count"] or 0), int(row["total_onu"] or 0)), reverse=True)
    return result


def enrich_quality_items(rows, include_boss=True, include_business=True, include_current_port=True):
    items = [json_ready(r) for r in rows]
    device_map = fetch_device_map(sorted({int(r.get("olt_device_id") or 0) for r in items if r.get("olt_device_id")}))
    for item in items:
        dev = device_map.get(int(item.get("olt_device_id") or 0), {})
        for key in ("olt_name", "room_group", "room", "region", "device_model", "primary_ip", "backup_ip"):
            item[key] = dev.get(key) or item.get(key) or ""
        item["display_mac"] = fmt_mac(item.get("onu_mac"))
        item["quality_label"] = quality_label(item.get("quality_code"))
    if include_current_port:
        port_map = query_current_port_map(items)
        for item in items:
            current = port_map.get((int(item.get("olt_device_id") or 0), normalize_mac(item.get("onu_mac"))), {})
            current_port = current.get("pon_port_norm") or current.get("uplink_port_norm")
            if current_port and (not item.get("pon_port") or str(item.get("pon_port")) == "0"):
                item["pon_port"] = current_port
    if include_boss:
        boss_map = query_boss_map([i.get("onu_mac") for i in items])
        for item in items:
            boss = boss_map.get(normalize_mac(item.get("onu_mac")), {})
            item["gdf_account"] = boss.get("gdf_account") or ""
            item["customer_name"] = boss.get("customer_name") or ""
            item["company"] = boss.get("company") or ""
            item["phone1"] = boss.get("phone1") or ""
            item["phone2"] = boss.get("phone2") or ""
            item["grid"] = boss.get("grid") or ""
    if include_business:
        biz_map = query_business_map(items)
        for item in items:
            biz = biz_map.get((item.get("primary_ip"), item.get("pon_port"))) or biz_map.get((item.get("backup_ip"), item.get("pon_port"))) or {}
            item["business_type"] = biz.get("business_type") or ""
            item["optical_node_code"] = biz.get("optical_node_code") or ""
            item["optical_node_location"] = biz.get("optical_node_location") or ""
    return items


def compact_quality_rankings(items, fields):
    """Ranking cards only need a small projection; do not send full device records."""
    return [{field: item.get(field) for field in fields} for item in items]


def quality_latest_subquery(date, olt_ids, include_order=False, rule=None):
    rule = rule or quality_rule()
    id_list = ",".join(str(int(i)) for i in olt_ids) or "0"
    order_expr = f"indexOf([{id_list}], toUInt32(olt_device_id)) AS device_order," if include_order else ""
    return f"""
        SELECT {order_expr}
               region, olt_device_id, olt_name, pon_port, if_index, onu_mac,
               rx_power, tx_power, status, query_time,
               multiIf(NOT ({quality_rx_valid_expr(rule)}), 'rx_invalid',
                       rx_power < {rule['onu_rx_low_dbm']}, 'rx_low',
                       rx_power > {rule['onu_rx_high_dbm']}, 'rx_high',
                       'normal') AS quality_code
        FROM (
            SELECT
                argMax(region, sample_time) AS region,
                olt_device_id,
                argMax(olt_name, sample_time) AS olt_name,
                argMax(pon_port, sample_time) AS pon_port,
                if_index,
                onu_mac,
                argMax(rx_power, sample_time) AS rx_power,
                argMax(tx_power, sample_time) AS tx_power,
                argMax(status, sample_time) AS status,
                max(sample_time) AS query_time
            FROM onu_optical_sample
            WHERE sample_date = toDate('{ch_escape(date)}')
              AND length(onu_mac) = 12
              AND olt_device_id IN ({id_list})
            GROUP BY olt_device_id, onu_mac, if_index
        )
    """


def quality_bad_where(rule=None):
    rule = rule or quality_rule()
    code = (request.args.get("quality_code") or "").strip()
    clauses = [quality_rx_bad_expr(rule)]
    if code == "rx_low":
        clauses.append(f"rx_power < {rule['onu_rx_low_dbm']}")
    elif code == "rx_high":
        clauses.append(f"rx_power > {rule['onu_rx_high_dbm']}")
    return " AND ".join(clauses)


@netops2026_bp.get("/onu/quality-daily")
@login_required
def onu_quality_daily():
    page = int_arg("page", 1)
    size = int_arg("size", 50, 1, 200)
    offset = (page - 1) * size
    date = quality_date_arg()
    include_summary = (request.args.get("summary") or "1") != "0"
    summary_only = include_summary and (request.args.get("summary_only") or "0") == "1"
    trend_days = int_arg("trend_days", 30, 7, 366)
    include_unknown_ports = (request.args.get("include_unknown_ports") or "0") == "1"
    olt_ids = quality_scope_ids()
    rule = quality_rule()
    if not olt_ids:
        return success({"items": [], "total": 0, "page": page, "size": size, "stats": {}, "trend": [], "top_olts": [], "port_groups": []})
    cache_params = {
        "date": date,
        "page": 0 if summary_only else page,
        "size": 0 if summary_only else size,
        "keyword": (request.args.get("keyword") or "").strip(),
        "quality_code": (request.args.get("quality_code") or "").strip(),
        "rule": rule,
        "trend_days": trend_days,
        "include_unknown_ports": include_unknown_ports,
        "summary": include_summary,
        "summary_only": summary_only,
        "olt_ids": olt_ids,
    }
    key = cache_key("onu_quality_daily", cache_params)
    if (request.args.get("no_cache") or "0") != "1":
        cached = cache_get_json(key)
        if cached is not None:
            return success(cached)
    latest = quality_latest_subquery(date, olt_ids, include_order=True, rule=rule)
    bad_where = quality_bad_where(rule)
    id_list = ",".join(str(int(i)) for i in olt_ids) or "0"
    stats = {}
    payload = {"items": [], "total": 0, "page": page, "size": size, "stats": stats, "rule": rule}
    if not summary_only:
        stats_rows = ch_query(
            f"""
            SELECT count() AS total,
                   countIf({quality_rx_valid_expr(rule)} AND rx_power < {rule['onu_rx_low_dbm']}) AS rx_low,
                   countIf({quality_rx_valid_expr(rule)} AND rx_power > {rule['onu_rx_high_dbm']}) AS rx_high,
                   uniqExact(olt_device_id) AS involved_olt,
                   toString(max(query_time)) AS latest_time
            FROM ({latest})
            WHERE {bad_where}
            FORMAT JSON
            """
        )
        stats = stats_rows[0] if stats_rows else {}
        rows = ch_query(
            f"""
            SELECT region, olt_device_id, olt_name, pon_port, if_index, onu_mac,
                   rx_power, tx_power, status, toString(query_time) AS query_time, quality_code
            FROM ({latest})
            WHERE {bad_where}
            ORDER BY device_order ASC, pon_port ASC, rx_power ASC, query_time DESC
            LIMIT {size} OFFSET {offset}
            FORMAT JSON
            """
        )
        payload.update({
            "items": enrich_quality_items(rows, include_boss=True, include_business=True),
            "total": int(stats.get("total") or 0),
            "stats": stats,
        })
    if not include_summary:
        cache_set_json(key, payload, QUALITY_CURRENT_CACHE_TTL if date == datetime.now().strftime("%Y-%m-%d") else QUALITY_HISTORY_CACHE_TTL)
        return success(payload)

    trend = ch_query(
        f"""
        SELECT toString(sample_date) AS stat_date,
               countIf({bad_where}) AS bad_count,
               countIf({quality_rx_valid_expr(rule)} AND rx_power < {rule['onu_rx_low_dbm']}) AS rx_low,
               countIf({quality_rx_valid_expr(rule)} AND rx_power > {rule['onu_rx_high_dbm']}) AS rx_high,
               count() AS total_count
        FROM (
            SELECT sample_date, olt_device_id, onu_mac, if_index,
                   argMax(rx_power, sample_time) AS rx_power
            FROM onu_optical_sample
            WHERE sample_date BETWEEN toDate('{ch_escape(date)}') - {trend_days - 1} AND toDate('{ch_escape(date)}')
              AND length(onu_mac)=12
              AND olt_device_id IN ({id_list})
            GROUP BY sample_date, olt_device_id, onu_mac, if_index
        )
        GROUP BY sample_date
        ORDER BY sample_date
        FORMAT JSON
        """
    )
    top_rows = ch_query(
        f"""
        SELECT olt_device_id,
               countIf({bad_where}) AS bad_count,
               count() AS total_onu,
               countIf({quality_rx_valid_expr(rule)} AND rx_power < {rule['onu_rx_low_dbm']}) AS rx_low,
               countIf({quality_rx_valid_expr(rule)} AND rx_power > {rule['onu_rx_high_dbm']}) AS rx_high,
               minIf(rx_power, {bad_where}) AS worst_rx
        FROM ({latest})
        GROUP BY olt_device_id
        HAVING bad_count > 0
        ORDER BY bad_count DESC
        LIMIT {QUALITY_TOP_OLT_LIMIT}
        FORMAT JSON
        """
    )
    # Do the port aggregation in ClickHouse.  The old path copied up to 50k
    # abnormal ONU rows into Python and then issued MySQL lookups, which made a
    # cold first request noticeably slow on busy collection days.
    port_rows = ch_query(
        f"""
        SELECT any(region) AS region,
               olt_device_id,
               any(olt_name) AS olt_name,
               pon_port,
               countIf({bad_where}) AS bad_count,
               count() AS total_onu,
               countIf({quality_rx_valid_expr(rule)} AND rx_power < {rule['onu_rx_low_dbm']}) AS rx_low,
               countIf({quality_rx_valid_expr(rule)} AND rx_power > {rule['onu_rx_high_dbm']}) AS rx_high,
               minIf(rx_power, {bad_where}) AS worst_rx,
               toString(maxIf(query_time, {bad_where})) AS latest_time
        FROM ({latest})
        GROUP BY olt_device_id, pon_port
        HAVING bad_count > 0
        ORDER BY bad_count DESC, total_onu DESC
        LIMIT {QUALITY_TOP_PORT_LIMIT}
        FORMAT JSON
        """
    )
    current_point = next((point for point in trend if point.get("stat_date") == date), None)
    current_total = int(stats.get("total") or (current_point or {}).get("bad_count") or 0)
    previous_total = None
    for idx, point in enumerate(trend):
        if point.get("stat_date") == date and idx > 0:
            previous_total = int(trend[idx - 1].get("bad_count") or 0)
            break
    if previous_total is None and len(trend) >= 2:
        previous_total = int(trend[-2].get("bad_count") or 0)
    stats["previous_total"] = previous_total if previous_total is not None else 0
    stats["total_delta"] = current_total - previous_total if previous_total is not None else 0
    visible_port_rows = port_rows
    if not include_unknown_ports:
        visible_port_rows = [item for item in visible_port_rows if str(item.get("pon_port") or "") not in ("", "0", "未识别端口")]
    port_groups = enrich_quality_items(
        visible_port_rows, include_boss=False, include_business=True, include_current_port=False
    )
    top_olts = compact_quality_rankings(
        enrich_quality_items(top_rows, include_boss=False, include_business=False, include_current_port=False),
        ("region", "olt_device_id", "olt_name", "bad_count", "total_onu", "rx_low", "rx_high", "worst_rx"),
    )
    port_groups = compact_quality_rankings(
        port_groups,
        ("region", "olt_device_id", "olt_name", "pon_port", "bad_count", "total_onu", "rx_low", "rx_high",
         "worst_rx", "latest_time", "optical_node_code", "optical_node_location"),
    )
    payload.update({
        "total": current_total if summary_only else payload["total"],
        "stats": stats,
        "trend": trend,
        "top_olts": top_olts,
        "port_groups": port_groups,
    })
    cache_set_json(key, payload, QUALITY_CURRENT_CACHE_TTL if date == datetime.now().strftime("%Y-%m-%d") else QUALITY_HISTORY_CACHE_TTL)
    return success(payload)


@netops2026_bp.get("/onu/quality-daily/export")
@login_required
def onu_quality_export():
    date = quality_date_arg()
    olt_ids = quality_scope_ids()
    rule = quality_rule()
    latest = quality_latest_subquery(date, olt_ids, include_order=True, rule=rule)
    rows = ch_query(
        f"""
        SELECT region, olt_device_id, olt_name, pon_port, if_index, onu_mac,
               rx_power, tx_power, status, toString(query_time) AS query_time, quality_code
        FROM ({latest})
        WHERE {quality_bad_where(rule)}
        ORDER BY device_order ASC, pon_port ASC, rx_power ASC, query_time DESC
        LIMIT 50000
        FORMAT JSON
        """
    )
    items = enrich_quality_items(rows, include_boss=True, include_business=True)
    headers = ["日期", "机房组", "机房", "网格", "公司", "电话1", "电话2", "OLT", "OLT ID", "主IP", "备IP", "PON", "业务类型", "光节点", "ONU MAC", "RX", "TX", "质差原因", "采集时间", "GDF账号", "用户"]
    export_rows = []
    for row in items:
        export_rows.append([
            date, row.get("room_group"), row.get("room"), row.get("grid"), row.get("company"), row.get("phone1"), row.get("phone2"), row.get("olt_name"), row.get("olt_device_id"),
            row.get("primary_ip"), row.get("backup_ip"), row.get("pon_port"), row.get("business_type"),
            row.get("optical_node_code"), fmt_mac(row.get("onu_mac")), row.get("rx_power"), row.get("tx_power"),
            quality_label(row.get("quality_code")), dt_value(row.get("query_time")), row.get("gdf_account"), row.get("customer_name"),
        ])
    filename = f"ONU质量日报_{date.replace('-', '')}_{datetime.now().strftime('%H%M%S')}.xlsx"
    payload = make_xlsx(headers, export_rows)
    encoded_filename = parse.quote(filename, safe="")
    return Response(
        payload,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            # HTTP response headers are Latin-1. Keep an ASCII fallback and provide
            # the real Chinese filename through the RFC 5987 UTF-8 parameter.
            "Content-Disposition": f"attachment; filename=onu_quality_{date.replace('-', '')}.xlsx; filename*=UTF-8''{encoded_filename}",
            "Content-Length": str(len(payload)),
        },
    )


@netops2026_bp.get("/olt/performance")
@login_required
def olt_performance():
    page = int_arg("page", 1)
    size = int_arg("size", 20, 1, 100)
    keyword = (request.args.get("keyword") or "").strip().lower()
    trend_hours = int_arg("hours", 24, 1, 8760)
    condition_cpu = bool_arg("condition_cpu", True)
    condition_mem = bool_arg("condition_mem", True)
    condition_collect_failure = bool_arg("condition_collect_failure", False)
    sort_by = (request.args.get("sort_by") or "abnormal").strip().lower()
    sort_by = sort_by if sort_by in ("abnormal", "cpu", "mem") else "abnormal"
    sort_order = (request.args.get("sort_order") or "desc").strip().lower()
    sort_order = sort_order if sort_order in ("asc", "desc") else "desc"
    olt_ids = parse_olt_ids_arg()
    rule = performance_rule()
    cache_params = {
        "page": page,
        "size": size,
        "keyword": keyword,
        "hours": trend_hours,
        "condition_cpu": condition_cpu,
        "condition_mem": condition_mem,
        "condition_collect_failure": condition_collect_failure,
        "sort_by": sort_by,
        "sort_order": sort_order,
        "olt_ids": olt_ids,
        "rule": rule,
    }
    key = cache_key("olt_performance", cache_params)
    if (request.args.get("no_cache") or "0") != "1":
        cached = cache_get_json(key)
        if cached is not None:
            return success(cached)

    all_rows = performance_current_rows(olt_ids, keyword, rule)
    selected_conditions = condition_cpu or condition_mem or condition_collect_failure
    if selected_conditions:
        filtered = [
            row for row in all_rows
            if (condition_cpu and row.get("cpu_abnormal"))
            or (condition_mem and row.get("mem_abnormal"))
            or (condition_collect_failure and row.get("collect_failure"))
        ]
    else:
        # No condition selected means the operator explicitly wants healthy devices.
        filtered = [row for row in all_rows if not row.get("is_abnormal")]
    if sort_by == "cpu":
        direction = -1 if sort_order == "desc" else 1
        filtered.sort(key=lambda r: (r.get("cpu_sort_value") is None, direction * float(r.get("cpu_sort_value") or 0), r.get("name") or ""))
    elif sort_by == "mem":
        direction = -1 if sort_order == "desc" else 1
        filtered.sort(key=lambda r: (r.get("mem_sort_value") is None, direction * float(r.get("mem_sort_value") or 0), r.get("name") or ""))
    else:
        filtered.sort(key=lambda r: (
            0 if r.get("is_abnormal") else 1,
            0 if r.get("status") == "critical" else 1 if r.get("status") == "warning" else 2,
            -(float(r.get("max_usage") or 0)),
            r.get("room_group") or "",
            r.get("name") or "",
        ))
    total = len(filtered)
    offset = (page - 1) * size
    items = filtered[offset:offset + size]
    stats = performance_stats(all_rows)
    trend_bucket_hours = 1 if trend_hours <= 168 else 4
    trend = performance_trend(trend_hours, olt_ids, bucket_hours=trend_bucket_hours)
    payload = {
        "items": items,
        "total": total,
        "page": page,
        "size": size,
        "stats": stats,
        "trend": trend,
        "trend_bucket_hours": trend_bucket_hours,
        "rule": rule,
        "conditions": {
            "cpu": condition_cpu,
            "mem": condition_mem,
            "collect_failure": condition_collect_failure,
        },
        "sort_by": sort_by,
        "sort_order": sort_order,
    }
    cache_set_json(key, payload, 30)
    return success(payload)


def performance_status(row, rule):
    values = {
        "olt_cpu": row.get("cpu_usage"),
        "olt_mem": row.get("mem_usage"),
        "board_cpu": row.get("board_cpu_max"),
        "board_mem": row.get("board_mem_max"),
    }
    latest = parse_dt(row.get("latest_time") or row.get("query_time"))
    if latest and (datetime.now() - latest).total_seconds() > rule["stale_minutes"] * 60:
        return "stale", "采集超时"
    if latest is None:
        return "missing", "暂无性能数据"
    if num_or_none(values["olt_cpu"]) is not None and float(values["olt_cpu"]) >= rule["olt_cpu_critical"]:
        return "critical", "OLT CPU 严重"
    if num_or_none(values["olt_mem"]) is not None and float(values["olt_mem"]) >= rule["olt_mem_critical"]:
        return "critical", "OLT 内存严重"
    if num_or_none(values["board_cpu"]) is not None and float(values["board_cpu"]) >= rule["board_cpu_critical"]:
        return "critical", "板卡 CPU 严重"
    if num_or_none(values["board_mem"]) is not None and float(values["board_mem"]) >= rule["board_mem_critical"]:
        return "critical", "板卡内存严重"
    if num_or_none(values["olt_cpu"]) is not None and float(values["olt_cpu"]) >= rule["olt_cpu_warning"]:
        return "warning", "OLT CPU 告警"
    if num_or_none(values["olt_mem"]) is not None and float(values["olt_mem"]) >= rule["olt_mem_warning"]:
        return "warning", "OLT 内存告警"
    if num_or_none(values["board_cpu"]) is not None and float(values["board_cpu"]) >= rule["board_cpu_warning"]:
        return "warning", "板卡 CPU 告警"
    if num_or_none(values["board_mem"]) is not None and float(values["board_mem"]) >= rule["board_mem_warning"]:
        return "warning", "板卡内存告警"
    return "normal", "运行正常"


def parse_dt(value):
    if isinstance(value, datetime):
        return value
    text = str(value or "").strip()
    if not text or text.startswith("0000"):
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text[:19], fmt)
        except ValueError:
            pass
    return None


def num_or_none(value):
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if result == result else None


def performance_current_rows(olt_ids, keyword, rule):
    clauses = ["d.is_active=1"]
    args = []
    append_region_scope(clauses, args, "d.region")
    if olt_ids:
        clauses.append(f"d.olt_device_id IN ({mysql_placeholders(olt_ids)})")
        args.extend(olt_ids)
    if keyword:
        like = f"%{keyword}%"
        clauses.append("(LOWER(d.name) LIKE %s OR LOWER(d.room_group) LIKE %s OR LOWER(d.room) LIKE %s OR LOWER(d.device_model) LIKE %s OR d.primary_ip LIKE %s)")
        args.extend([like, like, like, like, like])
    rows = query_all(
        f"""
        SELECT d.olt_device_id, d.name, d.room_group, d.room, d.region, d.device_model,
               d.primary_ip, d.backup_ip,
               cpu.metric_num_value AS cpu_usage,
               mem.metric_num_value AS mem_usage,
               GREATEST(COALESCE(cpu.query_time, '1000-01-01'), COALESCE(mem.query_time, '1000-01-01')) AS query_time,
               b.board_count, b.board_cpu_max, b.board_mem_max, b.board_latest_time
        FROM olt_devices d
        LEFT JOIN olt_perf_device_metric_last cpu
          ON cpu.olt_device_id=d.olt_device_id AND cpu.metric_key='cpu_usage'
        LEFT JOIN olt_perf_device_metric_last mem
          ON mem.olt_device_id=d.olt_device_id AND mem.metric_key='mem_usage'
        LEFT JOIN (
          SELECT olt_device_id,
                 COUNT(DISTINCT board_index) AS board_count,
                 MAX(CASE WHEN metric_key='cpu_usage' THEN metric_num_value END) AS board_cpu_max,
                 MAX(CASE WHEN metric_key='mem_usage' THEN metric_num_value END) AS board_mem_max,
                 MAX(query_time) AS board_latest_time
          FROM olt_perf_board_metric_last
          GROUP BY olt_device_id
        ) b ON b.olt_device_id=d.olt_device_id
        WHERE {' AND '.join(clauses)}
        """,
        tuple(args),
    )
    result = []
    for raw in rows:
        row = json_ready(raw)
        latest = max([v for v in [parse_dt(row.get("query_time")), parse_dt(row.get("board_latest_time"))] if v] or [None])
        row["latest_time"] = latest.strftime("%Y-%m-%d %H:%M:%S") if latest else None
        status, status_label = performance_status(row, rule)
        row["status"] = status
        row["status_label"] = status_label
        row["cpu_abnormal"] = (
            (num_or_none(row.get("cpu_usage")) or 0) >= rule["olt_cpu_warning"]
            or (num_or_none(row.get("board_cpu_max")) or 0) >= rule["board_cpu_warning"]
        )
        row["mem_abnormal"] = (
            (num_or_none(row.get("mem_usage")) or 0) >= rule["olt_mem_warning"]
            or (num_or_none(row.get("board_mem_max")) or 0) >= rule["board_mem_warning"]
        )
        row["collect_failure"] = status in ("stale", "missing")
        row["is_abnormal"] = row["cpu_abnormal"] or row["mem_abnormal"] or row["collect_failure"]
        row["max_usage"] = max([v for v in [
            num_or_none(row.get("cpu_usage")),
            num_or_none(row.get("mem_usage")),
            num_or_none(row.get("board_cpu_max")),
            num_or_none(row.get("board_mem_max")),
        ] if v is not None] or [0])
        row["cpu_sort_value"] = num_or_none(row.get("cpu_usage"))
        if row["cpu_sort_value"] is None:
            row["cpu_sort_value"] = num_or_none(row.get("board_cpu_max"))
        row["mem_sort_value"] = num_or_none(row.get("mem_usage"))
        if row["mem_sort_value"] is None:
            row["mem_sort_value"] = num_or_none(row.get("board_mem_max"))
        result.append(row)
    return result


def performance_stats(rows):
    total = len(rows)
    perf_count = sum(1 for r in rows if r.get("query_time") and not str(r.get("query_time")).startswith("1000"))
    board_olt_count = sum(1 for r in rows if int(r.get("board_count") or 0) > 0)
    board_count = sum(int(r.get("board_count") or 0) for r in rows)
    cpu_alarm = sum(1 for r in rows if r.get("cpu_abnormal"))
    mem_alarm = sum(1 for r in rows if r.get("mem_abnormal"))
    collect_failure_count = sum(1 for r in rows if r.get("collect_failure"))
    abnormal = sum(1 for r in rows if r.get("is_abnormal"))
    latest_values = [parse_dt(r.get("latest_time")) for r in rows if parse_dt(r.get("latest_time"))]
    latest = max(latest_values).strftime("%Y-%m-%d %H:%M:%S") if latest_values else "-"
    return {
        "total": total,
        "perf_count": perf_count,
        "board_olt_count": board_olt_count,
        "board_count": board_count,
        "cpu_alarm": cpu_alarm,
        "mem_alarm": mem_alarm,
        "abnormal": abnormal,
        "collect_failure_count": collect_failure_count,
        "latest_time": latest,
    }


def performance_trend(hours, olt_ids, start_at=None, end_at=None, bucket_hours=None):
    id_filter = ""
    if olt_ids:
        id_filter = " AND olt_device_id IN (" + ",".join(str(int(i)) for i in olt_ids) + ")"
    elif allowed_device_regions() is not None:
        id_filter = " AND 1=0"
    bucket_hours = max(1, min(24, int(bucket_hours or (1 if hours <= 168 else 4))))
    bucket = "toStartOfHour(sample_time)" if bucket_hours == 1 else f"toStartOfInterval(sample_time, INTERVAL {bucket_hours} HOUR)"
    if start_at and end_at:
        start = parse_dt(start_at)
        end = parse_dt(end_at)
        if start and end and end > start:
            time_filter = f"sample_time >= toDateTime('{ch_escape(start.strftime('%Y-%m-%d %H:%M:%S'))}') AND sample_time <= toDateTime('{ch_escape(end.strftime('%Y-%m-%d %H:%M:%S'))}')"
        else:
            time_filter = f"sample_time >= now() - INTERVAL {int(hours)} HOUR"
    else:
        time_filter = f"sample_time >= now() - INTERVAL {int(hours)} HOUR"
    return ch_query(
        f"""
        SELECT toString(bucket) AS sample_time,
               round(avgIf(metric_value, metric_scope='device' AND metric_key='cpu_usage'), 2) AS device_cpu_avg,
               round(maxIf(metric_value, metric_scope='device' AND metric_key='cpu_usage'), 2) AS device_cpu_max,
               round(avgIf(metric_value, metric_scope='device' AND metric_key='mem_usage'), 2) AS device_mem_avg,
               round(maxIf(metric_value, metric_scope='device' AND metric_key='mem_usage'), 2) AS device_mem_max,
               round(avgIf(metric_value, metric_scope='board' AND metric_key='cpu_usage'), 2) AS board_cpu_avg,
               round(maxIf(metric_value, metric_scope='board' AND metric_key='cpu_usage'), 2) AS board_cpu_max,
               round(avgIf(metric_value, metric_scope='board' AND metric_key='mem_usage'), 2) AS board_mem_avg,
               round(maxIf(metric_value, metric_scope='board' AND metric_key='mem_usage'), 2) AS board_mem_max
        FROM (
          SELECT {bucket} AS bucket, metric_scope, metric_key, metric_value
          FROM olt_perf_sample
          WHERE {time_filter}{id_filter}
        )
        GROUP BY bucket
        ORDER BY bucket
        FORMAT JSON
        """
    )


@netops2026_bp.get("/olt/performance/trend")
@login_required
def olt_performance_trend():
    hours = int_arg("hours", 24, 1, 8760)
    bucket_hours = int_arg("bucket_hours", 1 if hours <= 168 else 4, 1, 24)
    return success({
        "items": performance_trend(
            hours,
            parse_olt_ids_arg(),
            request.args.get("start"),
            request.args.get("end"),
            bucket_hours,
        ),
        "bucket_hours": bucket_hours,
    })


@netops2026_bp.get("/olt/performance/trend-devices")
@login_required
def olt_performance_trend_devices():
    sample_at = parse_dt(request.args.get("sample_time"))
    bucket_hours = int_arg("bucket_hours", 1, 1, 24)
    if not sample_at:
        return fail(BAD_REQUEST, "sample_time 不能为空")
    end_at = sample_at + timedelta(hours=bucket_hours)
    olt_ids = parse_olt_ids_arg()
    id_filter = ""
    if olt_ids:
        id_filter = " AND olt_device_id IN (" + ",".join(str(int(i)) for i in olt_ids) + ")"
    elif allowed_device_regions() is not None:
        id_filter = " AND 1=0"
    rows = ch_query(
        f"""
        SELECT olt_device_id,
               round(maxIf(metric_value, metric_scope='device' AND metric_key='cpu_usage'), 2) AS device_cpu_max,
               round(maxIf(metric_value, metric_scope='device' AND metric_key='mem_usage'), 2) AS device_mem_max,
               round(maxIf(metric_value, metric_scope='board' AND metric_key='cpu_usage'), 2) AS board_cpu_max,
               round(maxIf(metric_value, metric_scope='board' AND metric_key='mem_usage'), 2) AS board_mem_max
        FROM olt_perf_sample
        WHERE sample_time >= toDateTime('{ch_escape(sample_at.strftime('%Y-%m-%d %H:%M:%S'))}')
          AND sample_time < toDateTime('{ch_escape(end_at.strftime('%Y-%m-%d %H:%M:%S'))}'){id_filter}
        GROUP BY olt_device_id
        ORDER BY greatest(device_cpu_max, device_mem_max, board_cpu_max, board_mem_max) DESC
        LIMIT 200
        FORMAT JSON
        """
    )
    rule = performance_rule()
    abnormal_rows = []
    for raw in rows:
        row = json_ready(raw)
        row["is_abnormal"] = (
            (num_or_none(row.get("device_cpu_max")) or 0) >= rule["olt_cpu_warning"]
            or (num_or_none(row.get("device_mem_max")) or 0) >= rule["olt_mem_warning"]
            or (num_or_none(row.get("board_cpu_max")) or 0) >= rule["board_cpu_warning"]
            or (num_or_none(row.get("board_mem_max")) or 0) >= rule["board_mem_warning"]
        )
        if row["is_abnormal"]:
            abnormal_rows.append(row)
    device_ids = [int(row["olt_device_id"]) for row in abnormal_rows]
    devices = {}
    if device_ids:
        for raw in query_all(
            f"SELECT olt_device_id, name, room_group, room, device_model, primary_ip FROM olt_devices WHERE olt_device_id IN ({mysql_placeholders(device_ids)})",
            tuple(device_ids),
        ):
            device = json_ready(raw)
            devices[int(device["olt_device_id"])] = device
    for row in abnormal_rows:
        row.update(devices.get(int(row["olt_device_id"]), {}))
    return success({
        "sample_time": sample_at.strftime("%Y-%m-%d %H:%M:%S"),
        "end_time": end_at.strftime("%Y-%m-%d %H:%M:%S"),
        "items": abnormal_rows,
    })


@netops2026_bp.get("/olt/performance/detail")
@login_required
def olt_performance_detail():
    device_id = int_arg("olt_device_id", 0, 0, 10000000)
    if not device_id:
        return fail(BAD_REQUEST, "olt_device_id 不能为空")
    if not can_access_device(device_id):
        return fail(UNAUTHORIZED, "无权访问该设备数据", http_status=403)
    rule = performance_rule()
    device_rows = performance_current_rows([device_id], "", rule)
    device = device_rows[0] if device_rows else {}
    boards = query_all(
        """
        SELECT b.olt_device_id, b.board_index AS slot_id, b.board_name,
               MAX(CASE WHEN b.metric_key='cpu_usage' THEN b.metric_num_value END) AS cpu_usage,
               MAX(CASE WHEN b.metric_key='mem_usage' THEN b.metric_num_value END) AS mem_usage,
               MAX(b.query_time) AS query_time
        FROM olt_perf_board_metric_last b
        WHERE b.olt_device_id=%s
        GROUP BY b.olt_device_id, b.board_index, b.board_name
        ORDER BY CAST(b.board_index AS UNSIGNED), b.board_index
        """,
        (device_id,),
    )
    board_items = []
    for raw in boards:
        row = json_ready(raw)
        status = "normal"
        if (num_or_none(row.get("cpu_usage")) or 0) >= rule["board_cpu_critical"] or (num_or_none(row.get("mem_usage")) or 0) >= rule["board_mem_critical"]:
            status = "critical"
        elif (num_or_none(row.get("cpu_usage")) or 0) >= rule["board_cpu_warning"] or (num_or_none(row.get("mem_usage")) or 0) >= rule["board_mem_warning"]:
            status = "warning"
        row["status"] = status
        board_items.append(row)
    ports = []
    try:
        ports = query_all(
            """
            SELECT olt_device_id, if_index, port_category, if_speed_bps, if_admin_status, if_oper_status
            FROM olt_port_profile
            WHERE olt_device_id=%s
            ORDER BY port_category, CAST(if_index AS UNSIGNED), if_index
            LIMIT 300
            """,
            (device_id,),
        )
    except Exception:
        ports = []
    return success({"device": device, "boards": board_items, "ports": [json_ready(r) for r in ports], "rule": rule})


@netops2026_bp.get("/olt/performance/history")
@login_required
def olt_performance_history():
    device_id = int_arg("olt_device_id", 0, 0, 10000000)
    if not device_id:
        return fail(BAD_REQUEST, "olt_device_id 不能为空")
    if not can_access_device(device_id):
        return fail(UNAUTHORIZED, "无权访问该设备数据", http_status=403)
    scope = (request.args.get("scope") or "device").strip()
    slot_id = (request.args.get("slot_id") or "").strip()
    hours = int_arg("hours", 24, 1, 8760)
    slot_filter = ""
    if scope == "board" and slot_id:
        slot_filter = f" AND slot_id = '{ch_escape(slot_id)}'"
    bucket = "toStartOfInterval(sample_time, INTERVAL 10 MINUTE)" if hours <= 48 else "toStartOfHour(sample_time)" if hours <= 336 else "toDate(sample_time)"
    rows = ch_query(
        f"""
        SELECT toString(bucket) AS sample_time,
               round(avgIf(metric_value, metric_key='cpu_usage'), 2) AS cpu_usage,
               round(avgIf(metric_value, metric_key='mem_usage'), 2) AS mem_usage,
               round(maxIf(metric_value, metric_key='cpu_usage'), 2) AS cpu_max,
               round(maxIf(metric_value, metric_key='mem_usage'), 2) AS mem_max
        FROM (
          SELECT {bucket} AS bucket, metric_key, metric_value
          FROM olt_perf_sample
          WHERE olt_device_id = {int(device_id)}
            AND metric_scope = '{ch_escape(scope)}'
            {slot_filter}
            AND sample_time >= now() - INTERVAL {int(hours)} HOUR
        )
        GROUP BY bucket
        ORDER BY bucket
        FORMAT JSON
        """
    )
    return success({"items": rows})


@netops2026_bp.get("/olt/performance/port-history")
@login_required
def olt_performance_port_history():
    device_id = int_arg("olt_device_id", 0, 0, 10000000)
    if_index = (request.args.get("if_index") or "").strip()
    hours = int_arg("hours", 24, 1, 8760)
    if not device_id or not if_index:
        return fail(BAD_REQUEST, "olt_device_id 和 if_index 不能为空")
    if not can_access_device(device_id):
        return fail(UNAUTHORIZED, "无权访问该设备数据", http_status=403)
    rows = ch_query(
        f"""
        SELECT toString(bucket) AS sample_time,
               anyLast(if_admin_status) AS if_admin_status,
               anyLast(if_oper_status) AS if_oper_status,
               anyLast(if_speed_bps) AS if_speed_bps,
               max(if_in_octets) AS if_in_octets,
               max(if_out_octets) AS if_out_octets
        FROM (
          SELECT toStartOfInterval(sample_time, INTERVAL 10 MINUTE) AS bucket,
                 if_admin_status, if_oper_status, if_speed_bps, if_in_octets, if_out_octets
          FROM olt_if_counter_sample
          WHERE olt_device_id = {int(device_id)}
            AND if_index = '{ch_escape(if_index)}'
            AND sample_time >= now() - INTERVAL {int(hours)} HOUR
        )
        GROUP BY bucket
        ORDER BY bucket
        FORMAT JSON
        """
    )
    return success({"items": rows, "sample_count": len(rows)})


@netops2026_bp.post("/onu/realtime-power")
@login_required
def realtime_power():
    payload = request.get_json(silent=True) or {}
    mac = normalize_mac(payload.get("onu_mac") or "")
    if not mac:
        return fail(BAD_REQUEST, "ONU MAC 不能为空")
    if payload.get("olt_device_id") and not can_access_device(payload.get("olt_device_id")):
        return fail(UNAUTHORIZED, "无权访问该设备数据", http_status=403)
    agent_payload = {
        "onu_mac": mac,
        "olt_device_id": payload.get("olt_device_id"),
        "if_index": payload.get("if_index"),
    }
    try:
        return success(agent_post("/api/onu/realtime-power", agent_payload, timeout=25))
    except Exception as exc:
        return fail(SERVER_ERROR, f"236 collector-agent 实时查询失败: {exc}", http_status=500)


# ── Radius management (ClickHouse-backed and platform-authenticated) ─────────

def radius_entry_allowed():
    menu = AppMenu.query.filter_by(menu_key="netops.radius", enabled=True).first()
    if menu is None:
        return False
    role_rank = {"normal_user": 1, "org_admin": 2, "super_admin": 3}
    role = getattr(g.current_user, "role_code", "normal_user") or "normal_user"
    user_type = getattr(g.current_user, "user_type", "internal") or "internal"
    if role_rank.get(role, 1) < role_rank.get(menu.min_role or "normal_user", 1):
        return False
    return role == "super_admin" or menu.user_type in (None, "", "all", user_type)


def radius_guard():
    if radius_entry_allowed():
        return None
    return fail(UNAUTHORIZED, "当前账号没有 Radius 管理权限", http_status=403)


def radius_hours():
    return int_arg("hours", 24, 1, 24 * 180)


_RADIUS_SNAPSHOT_LOCK = threading.Lock()
_RADIUS_SNAPSHOT_REFRESHING = set()


def schedule_radius_snapshot_refresh(snapshot_key, endpoint, query_string, view, user_id):
    """Refresh a shared Radius page snapshot without holding up an operator."""
    with _RADIUS_SNAPSHOT_LOCK:
        if snapshot_key in _RADIUS_SNAPSHOT_REFRESHING:
            return
        _RADIUS_SNAPSHOT_REFRESHING.add(snapshot_key)
    lease_key = "netops2026:radius_refresh:" + hashlib.sha1(snapshot_key.encode("utf-8")).hexdigest()
    if redis_command("SET", lease_key, "1", "NX", "EX", 120) != "OK":
        with _RADIUS_SNAPSHOT_LOCK:
            _RADIUS_SNAPSHOT_REFRESHING.discard(snapshot_key)
        return
    app = current_app._get_current_object()

    def refresh():
        try:
            with app.app_context():
                user = db.session.get(User, int(user_id))
                if user is None or user.status != "active":
                    return
                with app.test_request_context(f"/api/netops2026/radius/{endpoint}?{query_string}&refresh=1"):
                    g.current_user = user
                    view.__wrapped__()
        except Exception:
            app.logger.exception("background Radius snapshot refresh failed: %s", endpoint)
        finally:
            with _RADIUS_SNAPSHOT_LOCK:
                _RADIUS_SNAPSHOT_REFRESHING.discard(snapshot_key)

    threading.Thread(target=refresh, name=f"radius-{endpoint}-refresh", daemon=True).start()


def radius_page_snapshot(name, params, endpoint, view):
    """Return a recent page model immediately and refresh it asynchronously.

    This is intentionally page-level rather than one cache entry per SQL query:
    a Radius page contains several aggregates, and serial cache misses made the
    initial render unnecessarily slow.
    """
    snapshot_key = cache_key("radius_page_snapshot", {"name": name, **params})
    cached = cache_get_json(snapshot_key)
    if cached is not None and request.args.get("refresh") != "1":
        if isinstance(cached, dict) and isinstance(cached.get("payload"), dict):
            payload = cached["payload"]
            age_seconds = max(0, time.time() - float(cached.get("generated_at") or 0))
        else:
            payload, age_seconds = cached, float("inf")
        if age_seconds >= 60:
            query_string = parse.urlencode(params)
            schedule_radius_snapshot_refresh(
                snapshot_key, endpoint, query_string, view, int(g.current_user.id)
            )
        return payload, snapshot_key
    return None, snapshot_key


def store_radius_page_snapshot(snapshot_key, payload):
    # Keep the last successful page model across quiet periods so opening a
    # page never waits for a cold aggregate query.  Data older than one minute
    # is still refreshed asynchronously by ``radius_page_snapshot``.
    cache_set_json(snapshot_key, {"generated_at": time.time(), "payload": payload}, 604800)


def radius_traffic_anomalies(hours):
    """Return every account matching an explicit window-scaled traffic rule."""
    gib = 1024 ** 3
    heavy_threshold = max(10 * gib, int(50 * gib * hours / 24))
    upload_threshold = max(5 * gib, int(20 * gib * hours / 24))
    upload_ratio_threshold = 4
    rows = radius_ch_query(
        f"""
        SELECT username,
               sumIf(input_delta, counter_rollback=0) AS input_bytes,
               sumIf(output_delta, counter_rollback=0) AS output_bytes,
               sumIf(input_delta + output_delta, counter_rollback=0) AS total_bytes,
               round(input_bytes / greatest(output_bytes, 1), 2) AS upload_ratio,
               uniqExact(acct_session_id) AS sessions,
               countIf(counter_rollback=1) AS rollback_records,
               toString(min(event_time)) AS first_seen,
               toString(max(event_time)) AS last_seen,
               round(total_bytes * 8 /
                     greatest(dateDiff('second',min(event_time),max(event_time)),1) /
                     1000000, 2) AS average_mbps,
               toUInt8(total_bytes >= {heavy_threshold}) AS heavy_volume,
               toUInt8(input_bytes >= {upload_threshold}
                       AND upload_ratio >= {upload_ratio_threshold}) AS high_upload
        FROM radius_events
        WHERE event_type='accounting' AND username!=''
          AND event_time >= now() - INTERVAL {hours} HOUR
        GROUP BY username
        HAVING heavy_volume=1 OR high_upload=1
        ORDER BY high_upload DESC,total_bytes DESC
        FORMAT JSON
        """
    )
    return rows, {
        "window_hours": hours,
        "heavy_volume_bytes": heavy_threshold,
        "upload_bytes": upload_threshold,
        "upload_ratio": upload_ratio_threshold,
    }


def radius_time_window():
    """Return a safe ClickHouse time predicate and the selected window metadata.

    The default remains the existing relative ``hours`` window.  Explicit
    ``start_time``/``end_time`` values are intended for protocol evidence
    lookups and make the displayed range auditable for operators.
    """
    now_local = datetime.now(ZoneInfo("Asia/Shanghai")).replace(tzinfo=None)
    default_start = now_local - timedelta(hours=radius_hours())
    start_raw = (request.args.get("start_time") or "").strip()[:32]
    end_raw = (request.args.get("end_time") or "").strip()[:32]

    def parse_local(value, fallback):
        if not value:
            return fallback
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            return fallback

    start_at = parse_local(start_raw, default_start)
    end_at = parse_local(end_raw, now_local)
    earliest = now_local - timedelta(days=180)
    start_at = max(start_at, earliest)
    end_at = min(end_at, now_local + timedelta(minutes=5))
    if end_at <= start_at:
        end_at = min(now_local, start_at + timedelta(hours=1))
    start_text = start_at.strftime("%Y-%m-%d %H:%M:%S")
    end_text = end_at.strftime("%Y-%m-%d %H:%M:%S")
    return (
        "event_time >= toDateTime('" + ch_escape(start_text) + "','Asia/Shanghai') "
        "AND event_time <= toDateTime('" + ch_escape(end_text) + "','Asia/Shanghai')",
        {"start_time": start_text, "end_time": end_text, "explicit": bool(start_raw or end_raw)},
    )


def radius_event_filters(event_type=None, time_clause=None):
    clauses = [time_clause or radius_time_window()[0]]
    if event_type:
        clauses.append(f"event_type='{ch_escape(event_type)}'")
    keyword = (request.args.get("keyword") or "").strip()[:128]
    nas_ip = (request.args.get("nas_ip") or "").strip()[:64]
    result = (request.args.get("result") or "").strip().lower()
    if keyword:
        escaped = ch_escape(keyword)
        clauses.append(
            f"(positionCaseInsensitive(username,'{escaped}')>0 OR "
            f"positionCaseInsensitive(raw_username,'{escaped}')>0 OR "
            f"positionCaseInsensitive(mac_addr,'{escaped}')>0 OR "
            f"positionCaseInsensitive(framed_ip,'{escaped}')>0 OR "
            f"positionCaseInsensitive(acct_session_id,'{escaped}')>0)"
        )
    if nas_ip:
        clauses.append(f"nas_ip='{ch_escape(nas_ip)}'")
    if result == "accept":
        clauses.append("result_code=2")
    elif result == "reject":
        clauses.append("result_code=3")
    return " AND ".join(clauses)


def radius_identity_condition(keyword):
    """Build an exact, normalized GDF/MAC lookup condition for ClickHouse."""
    text = (keyword or "").strip()[:128]
    compact_mac = re.sub(r"[^0-9a-fA-F]", "", text).lower()
    account = text.upper()
    if re.fullmatch(r"GD[FC]\d{4,}", account):
        return (
            f"(upper(username)='{ch_escape(account)}' OR "
            f"upper(subscriber_id)='{ch_escape(account)}')",
            "account",
            account,
        )
    if len(compact_mac) == 12:
        return (
            "lower(replaceRegexpAll(mac_addr,'[^0-9a-fA-F]',''))="
            f"'{ch_escape(compact_mac)}'",
            "mac",
            compact_mac,
        )
    escaped = ch_escape(text)
    return (
        f"(positionCaseInsensitive(username,'{escaped}')>0 OR "
        f"positionCaseInsensitive(subscriber_id,'{escaped}')>0 OR "
        f"positionCaseInsensitive(mac_addr,'{escaped}')>0)",
        "keyword",
        text,
    )


def radius_related_condition(accounts, macs):
    clauses = []
    account_values = [str(v).upper() for v in accounts if str(v).strip() and str(v) != "(未匹配)"][:50]
    mac_values = [re.sub(r"[^0-9a-fA-F]", "", str(v)).lower() for v in macs if v][:50]
    mac_values = [v for v in mac_values if len(v) == 12]
    if account_values:
        quoted = ",".join(f"'{ch_escape(v)}'" for v in account_values)
        clauses.append(f"(upper(username) IN ({quoted}) OR upper(subscriber_id) IN ({quoted}))")
    if mac_values:
        quoted = ",".join(f"'{ch_escape(v)}'" for v in mac_values)
        clauses.append(
            f"lower(replaceRegexpAll(mac_addr,'[^0-9a-fA-F]','')) IN ({quoted})"
        )
    return "(" + " OR ".join(clauses) + ")" if clauses else "0"


@netops2026_bp.get("/radius/profile")
@login_required
def radius_profile():
    """One-click account/MAC history, traffic, session and issue diagnosis."""
    denied = radius_guard()
    if denied:
        return denied
    keyword = (request.args.get("keyword") or "").strip()
    if len(keyword) < 4:
        return fail(BAD_REQUEST, "请输入至少 4 个字符的 GDF 账号或完整 MAC")
    direct_where, query_type, normalized = radius_identity_condition(keyword)
    identity = (radius_ch_query(
        f"""
        SELECT groupUniqArrayIf(50)(
                   username,username!='' AND username!='(未匹配)'
                   AND ((event_type='auth' AND result_code=2) OR event_type='accounting')
               ) AS accounts,
               groupUniqArrayIf(50)(
                   subscriber_id,subscriber_id!=''
                   AND ((event_type='auth' AND result_code=2) OR event_type='accounting')
               ) AS subscriber_ids,
               groupUniqArrayIf(50)(
                   mac_addr,mac_addr!=''
                   AND ((event_type='auth' AND result_code=2) OR event_type='accounting')
               ) AS macs,
               groupUniqArrayIf(20)(
                   username,username!='' AND username!='(未匹配)'
               ) AS attempted_accounts,
               argMaxIf(mac_addr,event_time,event_type='auth' AND result_code=2 AND mac_addr!='') AS latest_accepted_mac,
               argMaxIf(mac_addr,event_time,event_type='accounting' AND mac_addr!='') AS latest_accounting_mac,
               toString(max(event_time)) AS last_seen
        FROM radius_events
        WHERE event_time >= now() - INTERVAL 180 DAY AND {direct_where}
        FORMAT JSON
        """
    ) or [{}])[0]
    accounts = list(dict.fromkeys((identity.get("accounts") or []) + (identity.get("subscriber_ids") or [])))
    if query_type == "account" and normalized not in accounts:
        accounts.insert(0, normalized)
    macs = identity.get("macs") or []
    related_where = radius_related_condition(accounts, macs)
    if related_where == "0":
        if identity.get("last_seen"):
            # Reject-only MACs remain queryable as failure evidence but never
            # expand into a trusted account-terminal relationship.
            related_where = f"({direct_where})"
        else:
            return success({
                "matched": False, "query": {"type": query_type, "value": normalized},
                "identity": {"accounts": accounts, "macs": macs, "last_seen": ""},
                "summary": {}, "flow": [], "sessions": [], "records": [], "associations": [],
                "terminate_causes": [], "issues": [{
                    "level": "warning", "code": "not_found", "title": "未发现 Radius 记录",
                    "detail": "近 180 天没有匹配的认证或 Accounting 数据，请核对账号/MAC。"
                }],
                "health": {"score": 0, "label": "无数据"}, "onu_consistency": None,
            })

    summary = (radius_ch_query(
        f"""
        SELECT countIf(event_type='auth') AS auth_total,
               countIf(event_type='auth' AND result_code=2) AS accept_total,
               countIf(event_type='auth' AND result_code=3) AS reject_total,
               countIf(event_type='accounting') AS accounting_records,
               uniqExactIf(acct_session_id,event_type='accounting' AND acct_session_id!='') AS sessions,
               uniqExactIf(
                   mac_addr,mac_addr!=''
                   AND ((event_type='auth' AND result_code=2) OR event_type='accounting')
               ) AS mac_count,
               uniqExactIf(nas_ip,nas_ip!='') AS nas_count,
               countIf(event_type='accounting' AND acct_status_type=1
                       AND event_time >= now()-INTERVAL 1 HOUR) AS starts_1h,
               countIf(event_type='accounting' AND counter_rollback=1) AS rollback_count,
               sumIf(input_delta,event_type='accounting' AND counter_rollback=0 AND event_time >= now()-INTERVAL 24 HOUR) AS input_24h,
               sumIf(output_delta,event_type='accounting' AND counter_rollback=0 AND event_time >= now()-INTERVAL 24 HOUR) AS output_24h,
               sumIf(input_delta,event_type='accounting' AND counter_rollback=0 AND event_time >= now()-INTERVAL 7 DAY) AS input_7d,
               sumIf(output_delta,event_type='accounting' AND counter_rollback=0 AND event_time >= now()-INTERVAL 7 DAY) AS output_7d,
               sumIf(input_delta,event_type='accounting' AND counter_rollback=0 AND event_time >= now()-INTERVAL 30 DAY) AS input_30d,
               sumIf(output_delta,event_type='accounting' AND counter_rollback=0 AND event_time >= now()-INTERVAL 30 DAY) AS output_30d,
               argMaxIf(result,event_time,event_type='auth') AS latest_auth_result,
               argMaxIf(reason_zh,event_time,event_type='auth') AS latest_auth_reason,
               if(
                   countIf(event_type='auth')=0,
                   '',
                   toString(maxIf(event_time,event_type='auth'))
               ) AS latest_auth_time,
               if(
                   countIf(event_type='accounting')=0,
                   '',
                   toString(maxIf(event_time,event_type='accounting'))
               ) AS latest_accounting_time,
               toString(max(event_time)) AS last_seen
        FROM radius_events
        WHERE event_time >= now() - INTERVAL 180 DAY AND {related_where}
        FORMAT JSON
        """
    ) or [{}])[0]
    flow = radius_ch_query(
        f"""
        SELECT toString(toStartOfHour(event_time)) AS bucket,
               sumIf(input_delta,counter_rollback=0) AS input_bytes,
               sumIf(output_delta,counter_rollback=0) AS output_bytes
        FROM radius_events
        WHERE event_type='accounting' AND event_time >= now()-INTERVAL 7 DAY
          AND {related_where}
        GROUP BY bucket ORDER BY bucket FORMAT JSON
        """
    )
    sessions = radius_ch_query(
        f"""
        SELECT username,acct_session_id,nas_ip,
               argMax(mac_addr,event_time) AS mac_addr,
               argMax(framed_ip,event_time) AS framed_ip,
               argMax(acct_status_type,event_time) AS latest_status,
               max(acct_session_time) AS session_seconds,
               sumIf(input_delta,counter_rollback=0) AS input_bytes,
               sumIf(output_delta,counter_rollback=0) AS output_bytes,
               toString(min(event_time)) AS first_seen,toString(max(event_time)) AS last_seen
        FROM radius_events
        WHERE event_type='accounting' AND event_time >= now()-INTERVAL 30 DAY
          AND acct_session_id!='' AND {related_where}
        GROUP BY username,acct_session_id,nas_ip
        ORDER BY last_seen DESC LIMIT 30 FORMAT JSON
        """
    )
    records = radius_ch_query(
        f"""
        SELECT toString(event_time) AS event_time,event_type,username,mac_addr,nas_ip,
               framed_ip,result,result_code,reason_zh,acct_status_type,acct_session_id,
               input_delta,output_delta,terminate_cause,counter_rollback
        FROM radius_events
        WHERE event_time >= now()-INTERVAL 30 DAY AND {related_where}
        ORDER BY event_time DESC LIMIT 80 FORMAT JSON
        """
    )
    associations = radius_ch_query(
        f"""
        SELECT username,mac_addr,
               countIf(event_type='auth' AND result_code=2) AS accept_count,
               countIf(event_type='auth' AND result_code=3) AS reject_count,
               countIf(event_type='accounting') AS accounting_count,
               sumIf(input_delta+output_delta,event_type='accounting' AND counter_rollback=0) AS traffic_bytes,
               toString(max(event_time)) AS last_seen
        FROM radius_events
        WHERE event_time >= now()-INTERVAL 30 DAY AND username!='' AND mac_addr!=''
          AND {related_where}
        GROUP BY username,mac_addr
        HAVING accept_count>0 OR accounting_count>0
        ORDER BY last_seen DESC LIMIT 50 FORMAT JSON
        """
    )
    terminate_causes = radius_ch_query(
        f"""
        SELECT terminate_cause,
               multiIf(terminate_cause=1,'用户请求',terminate_cause=2,'载波丢失',
                       terminate_cause=4,'空闲超时',terminate_cause=5,'会话超时',
                       terminate_cause=6,'管理员复位',terminate_cause=7,'管理员重启',
                       terminate_cause=8,'端口错误',terminate_cause=9,'NAS 错误',
                       terminate_cause=10,'NAS 请求',terminate_cause=11,'NAS 重启',
                       terminate_cause=15,'服务不可用','其他') AS name,
               count() AS value
        FROM radius_events
        WHERE event_type='accounting' AND acct_status_type=2
          AND event_time >= now()-INTERVAL 30 DAY AND {related_where}
        GROUP BY terminate_cause,name ORDER BY value DESC LIMIT 12 FORMAT JSON
        """
    )

    auth_total = int(summary.get("auth_total") or 0)
    reject_total = int(summary.get("reject_total") or 0)
    reject_rate = reject_total / max(auth_total, 1)
    input_24h = int(summary.get("input_24h") or 0)
    output_24h = int(summary.get("output_24h") or 0)
    issues, score = [], 100
    if reject_total >= 3 and reject_rate >= 0.5:
        issues.append({"level": "high", "code": "auth_reject",
                       "title": "近期认证失败率偏高",
                       "detail": f"近 180 天 {reject_total}/{auth_total} 次认证被拒绝，最近原因：{summary.get('latest_auth_reason') or '未知'}"})
        score -= 30
    if int(summary.get("mac_count") or 0) >= 2:
        mac_count = int(summary.get("mac_count") or 0)
        issues.append({"level": "medium", "code": "multi_mac",
                       "title": "账号存在多终端拨号风险",
                       "detail": f"近 180 天已关联 {mac_count} 个可信 MAC；可信关系仅来自成功认证或 Accounting，请核实换机、路由器更换或账号共享。"})
        score -= 20 if mac_count == 2 else 30
    if int(summary.get("starts_1h") or 0) >= 3:
        issues.append({"level": "medium", "code": "frequent_reconnect",
                       "title": "一小时内频繁重连",
                       "detail": f"最近 1 小时出现 {summary.get('starts_1h')} 次 Accounting Start。"})
        score -= 20
    if int(summary.get("rollback_count") or 0) > 0:
        issues.append({"level": "medium", "code": "counter_rollback",
                       "title": "发现计数器回退",
                       "detail": f"发现 {summary.get('rollback_count')} 次计数器回退，可能是会话复用或 NAS 重置。"})
        score -= 10
    if input_24h >= 20 * 1024 ** 3 and input_24h / max(output_24h, 1) >= 4:
        issues.append({"level": "medium", "code": "upload_pattern",
                       "title": "疑似异常高上行流量",
                       "detail": "近 24 小时上行量和上下载比例同时偏高，仅作疑似提示，需结合业务核验。"})
        score -= 15
    if int(summary.get("accounting_records") or 0) == 0 and auth_total:
        issues.append({"level": "warning", "code": "no_accounting",
                       "title": "有认证但无 Accounting",
                       "detail": "已看到认证记录，但近 180 天没有匹配的计费会话。"})
        score -= 20
    if not issues:
        issues.append({"level": "ok", "code": "healthy", "title": "未发现明显异常",
                       "detail": "认证、终端关联和流量结构未触发当前规则。"})
    health = {"score": max(0, score), "label": "正常" if score >= 85 else "关注" if score >= 60 else "异常"}
    primary_terminal_mac = identity.get("latest_accepted_mac") or identity.get("latest_accounting_mac")
    onu_consistency = None
    if len(normalize_mac(primary_terminal_mac)) == 12:
        onu_consistency = terminal_mac_onu_result(primary_terminal_mac).get("terminal_resolution")
    return success({
        "matched": True,
        "query": {"type": query_type, "value": normalized},
        "identity": {
            "accounts": accounts, "macs": macs,
            "attempted_accounts": identity.get("attempted_accounts") or [],
            "last_seen": identity.get("last_seen") or "",
        },
        "summary": summary, "flow": flow, "sessions": sessions, "records": records,
        "associations": associations, "terminate_causes": terminate_causes,
        "issues": issues, "health": health, "onu_consistency": onu_consistency,
    })


@netops2026_bp.get("/radius/overview")
@login_required
def radius_overview():
    denied = radius_guard()
    if denied:
        return denied
    hours = radius_hours()
    where = f"event_time >= now() - INTERVAL {hours} HOUR"
    overview = (radius_ch_query(
        f"""
        SELECT countIf(event_type='auth') AS auth_total,
               countIf(event_type='auth' AND result_code=2) AS accept_total,
               countIf(event_type='auth' AND result_code=3) AS reject_total,
               uniqExactIf(username, event_type='auth' AND username!='') AS auth_users,
               countIf(event_type='accounting') AS accounting_total,
               uniqExactIf(acct_session_id, event_type='accounting' AND acct_session_id!='') AS sessions,
               sumIf(input_delta + output_delta, event_type='accounting' AND counter_rollback=0) AS traffic_bytes,
               countIf(event_type='control') AS control_total,
               countIf(event_type='accounting' AND acct_status_type IN (7,8)) AS nas_restart_events,
               toString(max(event_time)) AS latest_event_time
        FROM radius_events WHERE {where}
        FORMAT JSON
        """
    ) or [{}])[0]
    trend = radius_ch_query(
        f"""
        SELECT toString(toStartOfInterval(event_time, INTERVAL 10 MINUTE)) AS bucket,
               countIf(event_type='auth' AND result_code=2) AS accepts,
               countIf(event_type='auth' AND result_code=3) AS rejects,
               sumIf(input_delta + output_delta, event_type='accounting' AND counter_rollback=0) AS traffic_bytes
        FROM radius_events WHERE {where}
        GROUP BY bucket ORDER BY bucket
        FORMAT JSON
        """
    )
    return success({"overview": overview, "trend": trend, "hours": hours})


@netops2026_bp.get("/radius/records")
@login_required
def radius_records():
    denied = radius_guard()
    if denied:
        return denied
    event_type = (request.args.get("event_type") or "auth").strip().lower()
    if event_type not in ("auth", "accounting", "control"):
        return fail(BAD_REQUEST, "event_type 必须为 auth、accounting 或 control")
    page = int_arg("page", 1, 1, 1000000)
    page_size = int_arg("page_size", 30, 1, 200)
    time_clause, window = radius_time_window()
    where = radius_event_filters(event_type, time_clause)
    sort_by = (request.args.get("sort_by") or "event_time").strip().lower()
    sort_by = sort_by if sort_by in {"event_time", "username", "result_code", "nas_ip"} else "event_time"
    sort_order = (request.args.get("sort_order") or "desc").strip().lower()
    sort_order = "ASC" if sort_order == "asc" else "DESC"
    total = (radius_ch_query(f"SELECT count() AS total FROM radius_events WHERE {where} FORMAT JSON") or [{"total": 0}])[0]["total"]
    items = radius_ch_query(
        f"""
        SELECT event_id,toString(event_time) AS event_time,event_type,username,raw_username,
               nas_ip,nas_identifier,nas_port,nas_port_id,nas_port_type,service_type,
               framed_protocol,calling_sta,mac_addr,called_sta,framed_ip,framed_ip_netmask,
               class_attr,src_ip,dst_ip,src_port,dst_port,packet_identifier,
               result_code,result,reply_raw,reason_zh,risk,acct_status_type,
               acct_session_id,acct_multi_session_id,acct_authentic,acct_session_time,
               connect_info,error_cause,input_total,output_total,input_delta,
               output_delta,input_packets,output_packets,terminate_cause
        FROM radius_events WHERE {where}
        ORDER BY {sort_by} {sort_order},event_time DESC
        LIMIT {(page - 1) * page_size},{page_size}
        FORMAT JSON
        """
    )
    observed = (radius_ch_query(
        f"SELECT if(count()=0,'',toString(min(event_time))) AS first_event_time,"
        f"if(count()=0,'',toString(max(event_time))) AS last_event_time "
        f"FROM radius_events WHERE {where} FORMAT JSON"
    ) or [{}])[0]
    return success({"items": items, "total": total, "page": page, "page_size": page_size,
                    "window": window, "observed": observed,
                    "sort_by": sort_by, "sort_order": sort_order.lower()})


@netops2026_bp.get("/radius/analytics")
@login_required
def radius_analytics():
    denied = radius_guard()
    if denied:
        return denied
    hours = radius_hours()
    section = (request.args.get("section") or "auth").strip().lower()
    if section not in ("auth", "session", "all"):
        return fail(BAD_REQUEST, "section 必须为 auth、session 或 all")
    cached_payload, snapshot_key = radius_page_snapshot(
        "analytics", {"hours": hours, "section": section}, "analytics", radius_analytics
    )
    if cached_payload is not None:
        return success(cached_payload)
    if section == "auth":
        auth_where = f"event_type='auth' AND event_time >= now() - INTERVAL {hours} HOUR"
        reasons = radius_ch_query(
            f"""SELECT if(reason_zh='', '未知', reason_zh) AS name,count() AS value
                FROM radius_events WHERE {auth_where} AND result_code=3
                GROUP BY name ORDER BY value DESC LIMIT 20 FORMAT JSON"""
        )
        nas = radius_ch_query(
            f"""SELECT if(nas_ip='', '未知', nas_ip) AS nas_ip,count() AS total,
                       countIf(result_code=2) AS accepts,countIf(result_code=3) AS rejects,
                       round(rejects / greatest(total,1) * 100,2) AS reject_rate
                FROM radius_events WHERE {auth_where}
                GROUP BY nas_ip ORDER BY total DESC LIMIT 50 FORMAT JSON"""
        )
        control_events = radius_ch_query(
            f"""SELECT toString(event_time) AS event_time,result,result_code,username,mac_addr,
                       nas_ip,acct_session_id,error_cause,src_ip,dst_ip
                FROM radius_events
                WHERE event_type='control' AND event_time >= now() - INTERVAL {hours} HOUR
                ORDER BY event_time DESC LIMIT 100 FORMAT JSON"""
        )
        payload = {"section": section, "reasons": reasons, "nas": nas,
                   "control_events": control_events,
                   "hours": hours}
        store_radius_page_snapshot(snapshot_key, payload)
        return success(payload)
    if section == "session":
        reconnects = radius_ch_query(
            f"""SELECT username,countIf(acct_status_type=1) AS start_count,
                       uniqExact(mac_addr) AS mac_count,uniqExact(nas_ip) AS nas_count,
                       toString(max(event_time)) AS last_seen
                FROM radius_events
                WHERE event_type='accounting' AND username!=''
                  AND event_time >= now() - INTERVAL {hours} HOUR
                GROUP BY username HAVING start_count >= 3
                ORDER BY start_count DESC,last_seen DESC LIMIT 100 FORMAT JSON"""
        )
        online_sessions = radius_ch_query(
            f"""SELECT username,acct_session_id,nas_ip,mac_addr,framed_ip,
                       toString(last_seen) AS last_seen,session_seconds,input_bytes,output_bytes
                FROM
                (
                    SELECT username,acct_session_id,nas_ip,
                           argMax(mac_addr,event_time) AS mac_addr,
                           argMax(framed_ip,event_time) AS framed_ip,
                           argMax(acct_status_type,event_time) AS latest_status,
                           max(acct_session_time) AS session_seconds,
                           sumIf(input_delta,counter_rollback=0) AS input_bytes,
                           sumIf(output_delta,counter_rollback=0) AS output_bytes,
                           max(event_time) AS last_seen
                    FROM radius_events
                    WHERE event_type='accounting' AND acct_session_id!=''
                      AND event_time >= now() - INTERVAL {hours} HOUR
                    GROUP BY username,acct_session_id,nas_ip
                )
                WHERE latest_status IN (1,3) AND last_seen >= now() - INTERVAL 60 MINUTE
                ORDER BY last_seen DESC LIMIT 100 FORMAT JSON"""
        )
        terminate_causes = radius_ch_query(
            f"""SELECT terminate_cause,
                       concat(multiIf(
                           terminate_cause=1,'用户主动下线',terminate_cause=2,'链路载波丢失',
                           terminate_cause=3,'接入服务丢失',terminate_cause=4,'空闲超时',
                           terminate_cause=5,'会话时长到期',terminate_cause=6,'管理员复位',
                           terminate_cause=7,'管理员重启',terminate_cause=8,'端口错误',
                           terminate_cause=9,'NAS 错误',terminate_cause=10,'NAS 主动结束',
                           terminate_cause=11,'NAS 重启',terminate_cause=12,'端口不再需要',
                           terminate_cause=13,'端口被抢占',terminate_cause=14,'端口挂起',
                           terminate_cause=15,'服务不可用',terminate_cause=16,'回呼结束',
                           terminate_cause=17,'用户侧错误',terminate_cause=18,'主机请求',
                           terminate_cause=19,'终端重启',terminate_cause=20,'重新认证失败',
                           terminate_cause=21,'端口重新初始化',terminate_cause=22,'端口禁用',
                           terminate_cause=23,'设备掉电',terminate_cause=24,'策略触发',
                           terminate_cause=25,'终端响应超时',terminate_cause=26,'MAC 未授权',
                           '未知原因'), '（代码 ', toString(terminate_cause), '）') AS name,
                       count() AS value
                FROM radius_events
                WHERE event_type='accounting' AND acct_status_type=2
                  AND event_time >= now() - INTERVAL {hours} HOUR
                GROUP BY terminate_cause,name ORDER BY value DESC LIMIT 20 FORMAT JSON"""
        )
        terminal_sharing = radius_ch_query(
            f"""SELECT mac_addr,uniqExact(username) AS account_count,
                       arrayStringConcat(arraySlice(groupUniqArray(20)(username),1,10),', ') AS accounts,
                       uniqExact(nas_ip) AS nas_count,toString(max(event_time)) AS last_seen
                FROM radius_events
                WHERE event_time >= now() - INTERVAL {hours} HOUR
                  AND username!='' AND username!='(未匹配)' AND mac_addr!=''
                  AND ((event_type='auth' AND result_code=2) OR event_type='accounting')
                GROUP BY mac_addr HAVING account_count>=2
                ORDER BY account_count DESC,last_seen DESC LIMIT 100 FORMAT JSON"""
        )
        ip_conflicts = radius_ch_query(
            """SELECT framed_ip,uniqExact(username) AS account_count,
                       arrayStringConcat(arraySlice(groupUniqArray(20)(username),1,10),', ') AS accounts,
                       uniqExact(mac_addr) AS mac_count,uniqExact(nas_ip) AS nas_count,
                       toString(max(event_time)) AS last_seen
                FROM radius_events
                WHERE event_type='accounting' AND framed_ip!='' AND username!=''
                  AND event_time >= now() - INTERVAL 15 MINUTE
                GROUP BY framed_ip HAVING account_count>=2
                ORDER BY last_seen DESC LIMIT 100 FORMAT JSON"""
        )
        session_summary = {
            "active_sessions": len(online_sessions),
            "reconnect_accounts": len(reconnects),
            "stop_records": sum(int(row.get("value") or 0) for row in terminate_causes),
            "top_terminate_cause": (terminate_causes[0].get("name") if terminate_causes else ""),
            "activity_window_minutes": 60,
        }
        payload = {"section": section, "summary": session_summary, "reconnects": reconnects,
                   "online_sessions": online_sessions, "terminate_causes": terminate_causes,
                   "terminal_sharing": terminal_sharing, "ip_conflicts": ip_conflicts,
                   "hours": hours}
        store_radius_page_snapshot(snapshot_key, payload)
        return success(payload)
    where = f"event_type='auth' AND event_time >= now() - INTERVAL {hours} HOUR"
    reasons = radius_ch_query(
        f"""SELECT if(reason_zh='', '未知', reason_zh) AS name,count() AS value
            FROM radius_events WHERE {where} AND result_code=3
            GROUP BY name ORDER BY value DESC LIMIT 20 FORMAT JSON"""
    )
    nas = radius_ch_query(
        f"""SELECT if(nas_ip='', '未知', nas_ip) AS nas_ip,count() AS total,
                   countIf(result_code=2) AS accepts,countIf(result_code=3) AS rejects,
                   round(rejects / greatest(total,1) * 100,2) AS reject_rate
            FROM radius_events WHERE {where}
            GROUP BY nas_ip ORDER BY total DESC LIMIT 50 FORMAT JSON"""
    )
    reconnects = radius_ch_query(
        f"""SELECT username,countIf(acct_status_type=1) AS start_count,
                   uniqExact(mac_addr) AS mac_count,uniqExact(nas_ip) AS nas_count,
                   toString(max(event_time)) AS last_seen
            FROM radius_events
            WHERE event_type='accounting' AND username!=''
              AND event_time >= now() - INTERVAL {hours} HOUR
            GROUP BY username HAVING start_count >= 3
            ORDER BY start_count DESC,last_seen DESC LIMIT 100 FORMAT JSON"""
    )
    traffic_patterns, traffic_rules = radius_traffic_anomalies(hours)
    online_sessions = radius_ch_query(
        f"""SELECT username,acct_session_id,nas_ip,mac_addr,framed_ip,
                   toString(last_seen) AS last_seen,session_seconds,input_bytes,output_bytes
            FROM
            (
                SELECT username,acct_session_id,nas_ip,
                       argMax(mac_addr,event_time) AS mac_addr,
                       argMax(framed_ip,event_time) AS framed_ip,
                       argMax(acct_status_type,event_time) AS latest_status,
                       max(acct_session_time) AS session_seconds,
                       sumIf(input_delta,counter_rollback=0) AS input_bytes,
                       sumIf(output_delta,counter_rollback=0) AS output_bytes,
                       max(event_time) AS last_seen
                FROM radius_events
                WHERE event_type='accounting' AND acct_session_id!=''
                  AND event_time >= now() - INTERVAL {hours} HOUR
                GROUP BY username,acct_session_id,nas_ip
            )
            WHERE latest_status IN (1,3) AND last_seen >= now() - INTERVAL 15 MINUTE
            ORDER BY last_seen DESC LIMIT 100 FORMAT JSON"""
    )
    terminate_causes = radius_ch_query(
        f"""SELECT terminate_cause,
                   multiIf(terminate_cause=1,'用户请求',terminate_cause=2,'载波丢失',
                           terminate_cause=4,'空闲超时',terminate_cause=5,'会话超时',
                           terminate_cause=6,'管理员复位',terminate_cause=7,'管理员重启',
                           terminate_cause=8,'端口错误',terminate_cause=9,'NAS 错误',
                           terminate_cause=10,'NAS 请求',terminate_cause=11,'NAS 重启',
                           terminate_cause=15,'服务不可用','其他') AS name,count() AS value
            FROM radius_events
            WHERE event_type='accounting' AND acct_status_type=2
              AND event_time >= now() - INTERVAL {hours} HOUR
            GROUP BY terminate_cause,name ORDER BY value DESC LIMIT 20 FORMAT JSON"""
    )
    nas_restarts = radius_ch_query(
        f"""SELECT nas_ip,acct_status_type,
                   if(acct_status_type=7,'Accounting-On','Accounting-Off') AS event_name,
                   count() AS value,toString(max(event_time)) AS last_seen
            FROM radius_events
            WHERE event_type='accounting' AND acct_status_type IN (7,8)
              AND event_time >= now() - INTERVAL {hours} HOUR
            GROUP BY nas_ip,acct_status_type,event_name
            ORDER BY last_seen DESC LIMIT 100 FORMAT JSON"""
    )
    control_events = radius_ch_query(
        f"""SELECT toString(event_time) AS event_time,result,result_code,username,mac_addr,
                   nas_ip,acct_session_id,error_cause,src_ip,dst_ip
            FROM radius_events
            WHERE event_type='control' AND event_time >= now() - INTERVAL {hours} HOUR
            ORDER BY event_time DESC LIMIT 100 FORMAT JSON"""
    )
    protocol_quality = (radius_ch_query(
        f"""SELECT countIf(event_type='auth' AND result_code=11) AS access_challenges,
                   countIf(event_type='control') AS control_packets,
                   countIf(event_type='control' AND result_code IN (42,45)) AS control_naks,
                   countIf(event_type='accounting' AND acct_delay_time>30) AS delayed_accounting,
                   countIf(event_type='accounting' AND acct_status_type IN (7,8)) AS nas_restart_events
            FROM radius_events
            WHERE event_time >= now() - INTERVAL {hours} HOUR FORMAT JSON"""
    ) or [{}])[0]
    terminal_sharing = radius_ch_query(
        f"""SELECT mac_addr,uniqExact(username) AS account_count,
                   arrayStringConcat(arraySlice(groupUniqArray(20)(username),1,10),', ') AS accounts,
                   uniqExact(nas_ip) AS nas_count,toString(max(event_time)) AS last_seen
            FROM radius_events
            WHERE event_time >= now() - INTERVAL {hours} HOUR
              AND username!='' AND username!='(未匹配)' AND mac_addr!=''
              AND ((event_type='auth' AND result_code=2) OR event_type='accounting')
            GROUP BY mac_addr HAVING account_count>=2
            ORDER BY account_count DESC,last_seen DESC LIMIT 100 FORMAT JSON"""
    )
    ip_conflicts = radius_ch_query(
        f"""SELECT framed_ip,uniqExact(username) AS account_count,
                   arrayStringConcat(arraySlice(groupUniqArray(20)(username),1,10),', ') AS accounts,
                   uniqExact(mac_addr) AS mac_count,uniqExact(nas_ip) AS nas_count,
                   toString(max(event_time)) AS last_seen
            FROM radius_events
            WHERE event_type='accounting' AND framed_ip!='' AND username!=''
              AND event_time >= now() - INTERVAL 15 MINUTE
            GROUP BY framed_ip HAVING account_count>=2
            ORDER BY last_seen DESC LIMIT 100 FORMAT JSON"""
    )
    payload = {
        "reasons": reasons, "nas": nas, "reconnects": reconnects,
        "traffic_patterns": traffic_patterns, "traffic_rules": traffic_rules,
        "online_sessions": online_sessions,
        "terminate_causes": terminate_causes, "nas_restarts": nas_restarts,
        "control_events": control_events, "protocol_quality": protocol_quality,
        "terminal_sharing": terminal_sharing, "ip_conflicts": ip_conflicts, "hours": hours,
    }
    store_radius_page_snapshot(snapshot_key, payload)
    return success(payload)


@netops2026_bp.get("/radius/risk/reject")
@login_required
def radius_reject_risk():
    denied = radius_guard()
    if denied:
        return denied
    hours = radius_hours()
    limit = int_arg("limit", 100, 1, 500)
    rows = radius_ch_query(
        f"""
        SELECT username,count() AS reject_count,
               uniqExactIf(mac_addr,mac_addr!='') AS mac_count,
               uniqExactIf(nas_ip,nas_ip!='') AS nas_count,toString(max(event_time)) AS last_seen,
               arrayStringConcat(arraySlice(groupUniqArray(20)(reason_zh),1,5), '、') AS reasons
        FROM radius_events
        WHERE event_type='auth' AND result_code=3 AND username!=''
          AND event_time >= now() - INTERVAL {hours} HOUR
        GROUP BY username ORDER BY reject_count DESC LIMIT {limit}
        FORMAT JSON
        """
    )
    return success({"items": rows, "hours": hours})


@netops2026_bp.get("/radius/risk/multi-mac")
@login_required
def radius_multi_mac_risk():
    denied = radius_guard()
    if denied:
        return denied
    hours = radius_hours()
    min_macs = int_arg("min_macs", 2, 2, 1000)
    snapshot_params = {"hours": hours, "min_macs": min_macs}
    cached_payload, snapshot_key = radius_page_snapshot(
        "multi_mac", snapshot_params, "risk/multi-mac", radius_multi_mac_risk
    )
    if cached_payload is not None:
        return success(cached_payload)
    limit_clause = ""
    if request.args.get("limit") is not None:
        limit_clause = f" LIMIT {int_arg('limit', 100, 1, 500)}"
    rows = radius_ch_query(
        f"""
        SELECT username,uniqExact(mac_addr) AS mac_count,
               countIf(event_type='auth' AND result_code=2) AS auth_count,
               countIf(event_type='accounting') AS accounting_count,
               uniqExact(nas_ip) AS nas_count,toString(max(event_time)) AS last_seen,
               arrayStringConcat(arraySlice(groupUniqArray(50)(mac_addr),1,10), ', ') AS macs
        FROM radius_events
        WHERE username!='' AND username!='(未匹配)' AND mac_addr!=''
          AND event_time >= now() - INTERVAL {hours} HOUR
          AND ((event_type='auth' AND result_code=2) OR event_type='accounting')
        GROUP BY username HAVING mac_count >= {min_macs}
        ORDER BY mac_count DESC,auth_count DESC{limit_clause}
        FORMAT JSON
        """
    )
    payload = {"items": rows, "hours": hours, "min_macs": min_macs}
    store_radius_page_snapshot(snapshot_key, payload)
    return success(payload)


@netops2026_bp.get("/radius/accounting")
@login_required
def radius_accounting():
    denied = radius_guard()
    if denied:
        return denied
    hours = radius_hours()
    cached_payload, snapshot_key = radius_page_snapshot(
        "accounting", {"hours": hours}, "accounting", radius_accounting
    )
    if cached_payload is not None:
        return success(cached_payload)
    where = f"event_type='accounting' AND event_time >= now() - INTERVAL {hours} HOUR"
    summary = (radius_ch_query(
        f"""SELECT count() AS records,uniqExact(acct_session_id) AS sessions,
                   uniqExact(username) AS users,
                   sumIf(input_delta,counter_rollback=0) AS input_bytes,
                   sumIf(output_delta,counter_rollback=0) AS output_bytes,
                   toString(max(event_time)) AS latest_event_time
            FROM radius_events WHERE {where} FORMAT JSON"""
    ) or [{}])[0]
    traffic = radius_ch_query(
        f"""SELECT toString(toStartOfInterval(event_time, INTERVAL 10 MINUTE)) AS bucket,
                   sumIf(input_delta,counter_rollback=0) AS input_bytes,
                   sumIf(output_delta,counter_rollback=0) AS output_bytes
            FROM radius_events WHERE {where}
            GROUP BY bucket ORDER BY bucket FORMAT JSON"""
    )
    quality = (radius_ch_query(
        f"""SELECT countIf(counter_rollback=0 AND input_delta+output_delta>0) AS delta_records,
                   countIf(counter_rollback=1) AS rollback_records,
                   countIf(acct_status_type=1) AS starts,
                   countIf(acct_status_type=2) AS stops,
                   countIf(acct_status_type=3) AS interim_updates
            FROM radius_events WHERE {where} FORMAT JSON"""
    ) or [{}])[0]
    coverage = (radius_ch_query(
        f"""SELECT toString(min(event_time)) AS first_event_time,
                   toString(max(event_time)) AS last_event_time,
                   dateDiff('second',min(event_time),max(event_time)) AS observed_seconds
            FROM radius_events WHERE {where} FORMAT JSON"""
    ) or [{}])[0]
    anomalies, anomaly_rules = radius_traffic_anomalies(hours)
    payload = {"summary": summary, "traffic": traffic,
               "quality": quality,
               "coverage": coverage, "anomalies": anomalies,
               "anomaly_rules": anomaly_rules, "hours": hours}
    store_radius_page_snapshot(snapshot_key, payload)
    return success(payload)


@netops2026_bp.get("/radius/ingest/status")
@login_required
def radius_ingest_status():
    denied = radius_guard()
    if denied:
        return denied
    rows = radius_ch_query(
        """SELECT event_id,toString(metric_time) AS metric_time,captured_packets,parsed_records,
                  auth_records,accounting_records,control_records,challenge_records,
                  interim_sampled_out,pending_auth_requests,unmatched_auth_responses,
                  expired_auth_requests,pending_auth_evictions,malformed_packets,
                  accounting_responses,unknown_radius_codes,
                  tcpdump_captured,tcpdump_received_by_filter,tcpdump_kernel_dropped,
                  sink_accepted,sink_spooled,sink_sent,sink_retries,spool_pending,spool_bytes,last_error
           FROM radius_collector_metrics ORDER BY metric_time DESC LIMIT 1 FORMAT JSON"""
    )
    latest = rows[0] if rows else {}
    latest_event = radius_ch_query(
        """SELECT toString(max(event_time)) AS latest_event_time,
                  dateDiff('second',max(event_time),now()) AS lag_seconds
           FROM radius_events FORMAT JSON"""
    )
    quality = radius_ch_query(
        """SELECT count() AS records_1h,
                  countIf(username='' OR username='(未匹配)') AS missing_username,
                  countIf(mac_addr='') AS missing_terminal_mac,
                  countIf(event_type='auth' AND result_code=11) AS challenges,
                  countIf(event_type='control') AS control_packets,
                  countIf(event_type='accounting' AND acct_status_type IN (7,8)) AS nas_restart_events,
                  countIf(event_type='accounting' AND acct_delay_time>30) AS delayed_accounting
           FROM radius_events
           WHERE event_time >= now() - INTERVAL 1 HOUR FORMAT JSON"""
    )
    return success({
        "collector": latest,
        "data": latest_event[0] if latest_event else {},
        "quality": quality[0] if quality else {},
    })


@netops2026_bp.get("/radius/export.csv")
@login_required
def radius_export_csv():
    denied = radius_guard()
    if denied:
        return denied
    event_type = (request.args.get("event_type") or "auth").strip().lower()
    if event_type not in ("auth", "accounting", "control"):
        return fail(BAD_REQUEST, "event_type 必须为 auth、accounting 或 control")
    time_clause, _ = radius_time_window()
    where = radius_event_filters(event_type, time_clause)
    rows = radius_ch_query(
        f"""SELECT toString(event_time) AS event_time,username,raw_username,nas_ip,nas_identifier,
                   mac_addr,framed_ip,result,result_code,reply_raw,reason_zh,
                   acct_status_type,acct_session_id,acct_multi_session_id,acct_authentic,
                   acct_session_time,service_type,framed_protocol,connect_info,error_cause,
                   src_ip,dst_ip,src_port,dst_port,input_total,output_total,input_delta,output_delta
            FROM radius_events WHERE {where} ORDER BY event_time DESC LIMIT 10000 FORMAT JSON"""
    )
    stream = io.StringIO()
    columns = list(rows[0].keys()) if rows else [
        "event_time", "username", "raw_username", "nas_ip", "nas_identifier",
        "mac_addr", "framed_ip", "result", "reply_raw", "reason_zh",
    ]
    writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    filename = f"radius-{event_type}-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
    return Response(
        "\ufeff" + stream.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store"},
    )

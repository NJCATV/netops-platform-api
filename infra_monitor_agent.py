#!/usr/bin/env python3
"""Minimal authenticated host monitor for the NetOps infrastructure cockpit.

It deliberately uses only the Python standard library so it can run beside the
existing services on 233/236/20 without adding a package or container.  The
central BFF is the only caller; bind it to the internal interface and protect
it with a per-environment bearer token.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib import parse as urlparse
from urllib import error as urlerror
from urllib import request as urlrequest


PROFILES = {
    "platform": [
        ("web", "统一前端 / Nginx", "process", "nginx"),
        ("bff", "网管后端 BFF", "tcp", ("127.0.0.1", 7001)),
        ("database", "平台业务数据库", "process", "mysqld"),
        ("redis", "平台缓存 Redis", "tcp", ("127.0.0.1", 6379)),
    ],
    "collector": [
        ("collector", "采集引擎", "process", "bin/collector"),
        ("collector_api", "采集服务 API", "http", "http://127.0.0.1:18086/health"),
        ("collector_database", "采集数据库", "process", "mysqld"),
        ("query", "设备查询服务", "process", "PycharmProjects/newalert/venv/bin/python run.py"),
    ],
    "aiops": [
        ("aiops_api", "AIOps 后端", "http", "http://127.0.0.1:18080/api/health"),
        ("aiops_database", "AIOps 数据库", "process", "mysqld"),
        ("elasticsearch", "Elasticsearch", "http", "http://127.0.0.1:9200/_cluster/health"),
        ("kibana", "Kibana", "tcp", ("127.0.0.1", 5601)),
        ("logstash", "Logstash", "process", "org.logstash.Logstash"),
    ],
    "radius": [
        ("radius_sniffer", "Radius 抓包与解析", "process", "/opt/radius_monitor/sniffer.py"),
        ("packet_capture", "UDP 1812 / 1813 / 3799 被动抓包", "process", "tcpdump.*udp port 1812"),
        ("clickhouse_sink", "ClickHouse 数据落库", "http", "http://172.25.194.212:8123/ping"),
    ],
}

# Only curated service logs are exposed.  This agent never accepts a file path
# from the caller, so the central cockpit cannot be used to browse host files.
LOG_SOURCES = {
    "platform": {
        "bff": {"kind": "file", "paths": [
            "/home/yvesyuan/PycharmProjects/anbo_wx/backend/logs/netops7001.log",
            "/home/yvesyuan/PycharmProjects/anbo_wx/backend/logs/api-7001.log",
        ], "label": "网管 BFF"},
        "web": {"kind": "file", "paths": ["/home/yvesyuan/PycharmProjects/anbo_wx/backend/logs/run.log"], "label": "平台 Web"},
    },
    "collector": {
        "collector": {"kind": "file", "paths": ["/home/jscn123/PycharmProjects/newalert/logs/onu_self_collect/onu_self_collect.log"], "label": "ONU 采集"},
        "collector_api": {"kind": "file", "paths": ["/home/jscn123/PycharmProjects/newalertApi/logs/onu_api/onu_api.log"], "label": "采集 API"},
        "query": {"kind": "file", "paths": ["/home/jscn123/PycharmProjects/newalert/logs/scheduler/scheduler.log"], "label": "采集调度"},
    },
    "aiops": {
        "aiops_api": {"kind": "file", "paths": ["/home/yvesyuan/jscn-aiops-releases/20260717-161200/runtime/api.log"], "label": "AIOps API"},
        "logstash": {"kind": "file", "paths": ["/home/yvesyuan/jscn-aiops-releases/20260717-161200/runtime/scope-sync.log"], "label": "AIOps 范围同步"},
    },
    "radius": {
        "radius_sniffer": {"kind": "journal", "unit": "radius-sniffer.service", "label": "Radius 抓包解析"},
        "packet_capture": {"kind": "journal", "unit": "radius-sniffer.service", "label": "UDP 抓包"},
        "clickhouse_sink": {"kind": "journal", "unit": "radius-sniffer.service", "label": "Radius 落库"},
        "radius_database": {"kind": "journal", "unit": "mysql.service", "label": "Radius MySQL"},
    },
}


def read_cpu_jiffies():
    with open("/proc/stat", encoding="ascii") as stream:
        values = next(line.split() for line in stream if line.startswith("cpu "))[1:]
    numbers = [int(value) for value in values]
    total = sum(numbers)
    idle = numbers[3] + (numbers[4] if len(numbers) > 4 else 0)
    return total, idle


CPU_LAST = (*read_cpu_jiffies(), time.monotonic())


def cpu_snapshot():
    global CPU_LAST
    total, idle = read_cpu_jiffies()
    old_total, old_idle, _ = CPU_LAST
    CPU_LAST = (total, idle, time.monotonic())
    delta_total, delta_idle = total - old_total, idle - old_idle
    percent = round(max(0.0, min(100.0, (1 - delta_idle / delta_total) * 100)), 1) if delta_total else 0.0
    return percent


def mem_snapshot():
    values = {}
    with open("/proc/meminfo", encoding="ascii") as stream:
        for line in stream:
            key, value = line.split(":", 1)
            values[key] = int(value.split()[0]) * 1024
    total = values.get("MemTotal", 0)
    available = values.get("MemAvailable", values.get("MemFree", 0))
    used = max(0, total - available)
    return {"total_bytes": total, "used_bytes": used, "available_bytes": available, "used_percent": round(used * 100 / total, 1) if total else 0}


def disk_snapshot():
    total, used, free = shutil.disk_usage("/")
    return {"path": "/", "total_bytes": total, "used_bytes": used, "free_bytes": free, "used_percent": round(used * 100 / total, 1) if total else 0}


def process_ok(pattern):
    try:
        output = subprocess.check_output(["pgrep", "-af", pattern], text=True, stderr=subprocess.DEVNULL, timeout=3)
        lines = [line for line in output.splitlines() if "infra_monitor_agent.py" not in line]
        return bool(lines), lines[0][:180] if lines else "未找到进程"
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False, "未找到进程"


def tcp_ok(host, port):
    started = time.monotonic()
    try:
        with socket.create_connection((host, int(port)), timeout=2):
            return True, f"TCP {port} · {round((time.monotonic() - started) * 1000)} ms"
    except OSError as exc:
        return False, f"TCP {port} 不可达：{exc.__class__.__name__}"


def http_ok(url):
    started = time.monotonic()
    try:
        with urlrequest.urlopen(url, timeout=3) as response:
            ok = 200 <= int(response.status) < 400
            return ok, f"HTTP {response.status} · {round((time.monotonic() - started) * 1000)} ms"
    except (urlerror.URLError, OSError) as exc:
        return False, f"HTTP 不可达：{exc.__class__.__name__}"


def service_snapshot(profile):
    rows = []
    for key, label, kind, target in PROFILES[profile]:
        if kind == "process":
            ok, detail = process_ok(target)
        elif kind == "tcp":
            ok, detail = tcp_ok(*target)
        else:
            ok, detail = http_ok(target)
        rows.append({"key": key, "label": label, "status": "ok" if ok else "failed", "detail": detail})
    return rows


def build_payload(profile):
    load = os.getloadavg()
    return {
        "status": "ok",
        "observed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "hostname": socket.gethostname(),
        "profile": profile,
        "resources": {
            "cpu_percent": cpu_snapshot(),
            "cpu_cores": os.cpu_count() or 1,
            "load_1": round(load[0], 2),
            "load_5": round(load[1], 2),
            "memory": mem_snapshot(),
            "disk": disk_snapshot(),
        },
        "services": service_snapshot(profile),
    }


def tail_file(path, limit):
    """Read a bounded tail without invoking a shell or following caller input."""
    with open(path, "rb") as stream:
        stream.seek(0, os.SEEK_END)
        size = stream.tell()
        stream.seek(max(0, size - 128 * 1024))
        text = stream.read().decode("utf-8", "replace")
    return [line for line in text.splitlines() if line][-limit:]


def service_log_payload(profile, service, limit):
    source = LOG_SOURCES.get(profile, {}).get(service)
    if not source:
        return {"status": "not_available", "service": service, "message": "该服务尚未配置受控日志源", "lines": []}
    try:
        if source["kind"] == "file":
            path = next((item for item in source["paths"] if os.path.isfile(item)), None)
            if not path:
                return {"status": "not_available", "service": service, "message": "日志文件尚未生成或当前探针无读取权限", "lines": []}
            lines = tail_file(path, limit)
            source_info = {"kind": "file", "label": source["label"], "name": os.path.basename(path)}
        else:
            result = subprocess.run(
                ["journalctl", "-u", source["unit"], "--no-pager", "-o", "short-iso", "-n", str(limit)],
                capture_output=True, text=True, timeout=6,
            )
            if result.returncode:
                return {"status": "not_available", "service": service, "message": "系统日志当前不可读取", "lines": []}
            lines = [line for line in result.stdout.splitlines() if line][-limit:]
            source_info = {"kind": "journal", "label": source["label"], "name": source["unit"]}
        return {"status": "ok", "service": service, "observed_at": time.strftime("%Y-%m-%d %H:%M:%S"), "source": source_info, "lines": lines}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"status": "not_available", "service": service, "message": f"读取日志失败：{exc.__class__.__name__}", "lines": []}


class Handler(BaseHTTPRequestHandler):
    token = ""
    profile = "platform"

    def do_GET(self):
        parsed = urlparse.urlparse(self.path)
        if parsed.path not in ("/healthz", "/v1/overview", "/v1/logs"):
            self.send_error(404)
            return
        if self.headers.get("Authorization", "") != "Bearer " + self.token:
            self.send_error(401)
            return
        if parsed.path == "/v1/logs":
            query = urlparse.parse_qs(parsed.query)
            service = (query.get("service") or [""])[0]
            try:
                limit = max(1, min(200, int((query.get("limit") or ["80"])[0])))
            except ValueError:
                limit = 80
            payload = service_log_payload(self.profile, service, limit)
        else:
            payload = build_payload(self.profile)
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, fmt, *args):
        return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", choices=sorted(PROFILES), required=True)
    parser.add_argument("--token")
    parser.add_argument("--token-file")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=18190)
    args = parser.parse_args()
    token = args.token
    if args.token_file:
        with open(args.token_file, encoding="utf-8") as stream:
            token = stream.read().strip()
    if not token:
        parser.error("one of --token or --token-file is required")
    Handler.token, Handler.profile = token, args.profile
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()

# 智维平台 API

本目录保存南京安播智维平台的 Flask 路由模块及生产验收工具。

本模块的架构、数据库、端口与安全边界见
[`docs/module-contract.md`](docs/module-contract.md)；完整跨模块拓扑见 `NJCATV/netops-ops`。

| 项目 | 路径/值 |
| --- | --- |
| 规范路由源 | `ops_platform_api.py` |
| 宿主适配副本 | `platform-adapter/host-application/backend/app/routes/netops2026.py` |
| 233 部署文件 | `/srv/netops/netops-littleProgram/backend/app/routes/netops2026.py` |
| 公共 API 前缀 | `/api/netops2026` |
| Nginx 对外前缀 | `/api/netops2026` |

当前模块以路由适配层方式嵌入 `netops-littleProgram` 宿主应用，复用统一登录、JWT、用户、组织和审计能力。历史 MySQL schema 仍可能名为 `anbo_wx`，但该名称不再用于部署路径、服务名或公开 API。未来如果平台后端独立部署，应再拆分为标准 Flask 包：应用工厂、配置、路由、服务层和数据访问层。

每次修改路由时必须同时更新“规范路由源”和“宿主适配副本”，并在发布窗口内将适配副本同步到 233；不得直接用 Git 覆盖用户正在编辑的宿主工作区。

## 本地检查

```bash
python -m py_compile backend/ops-platform-api/ops_platform_api.py
```

| 脚本 | 用途 |
| --- | --- |
| `apply_aiops_navigation.py` | 初始化或修复 AIOps 菜单 |
| `verify_admin_navigation.py` | 检查真实 admin 菜单和权限 |
| `verify_aiops_integration.py` | 检查管理员、安播中心和未授权用户边界 |
| `run_aiops_analysis_acceptance.py` | 执行受控 AI 分析验收 |
| `apply_infrastructure_navigation.py` | 初始化基础设施监控菜单 |
| `configure_infrastructure_monitor.py` | 配置基础设施探针所需的非秘密项 |
| `verify_radius_integration.py` | 核验 Radius BFF、菜单和数据链路 |

## 运行配置

敏感配置从 `/home/yvesyuan/.netops2026.json` 或环境变量读取：

| 环境变量 | 用途 |
| --- | --- |
| `GO_COLLECTOR_MYSQL_HOST` | 236 MySQL 地址 |
| `GO_COLLECTOR_MYSQL_PORT` | 236 MySQL 端口 |
| `GO_COLLECTOR_MYSQL_USER` | 采集数据只读账号 |
| `GO_COLLECTOR_MYSQL_PASSWORD` | 采集数据库密码 |
| `GO_COLLECTOR_MYSQL_DB` | 采集数据库名 |
| `GO_COLLECTOR_CLICKHOUSE_URL` | 212 ClickHouse HTTP 地址 |

AIOps BFF 从 `/home/yvesyuan/.netops2026.json` 读取 `aiops` 配置：

```json
{
  "aiops": {
    "base_url": "http://172.25.60.20:18080",
    "shared_secret": "使用独立的长随机密钥",
    "timeout": 150
  }
}
```

20 上 AIOps API 必须配置相同的 `AIOPS_INTERNAL_SHARED_SECRET`。该密钥只用于 233 到 20 的服务身份签名，不会发送到浏览器。

## 生产部署结论

| 模块 | 服务器 | 结论 |
| --- | --- | --- |
| 统一 Web 和 BFF | 233 | 使用网管统一登录和权限 |
| AIOps API、Scheduler、MySQL、Elasticsearch | 20 | 保持独立，避免日志/AI 负载影响 233 |
| 网络方向 | 233 → 20 | 单向服务调用 |
| AIOps 权限 | 233 BFF | 有页面权限即查看全局数据，不按设备组织过滤 |

严禁提交 `.netops2026.json`、`.env`、数据库密码、共享密钥、Token 或生产运行配置。

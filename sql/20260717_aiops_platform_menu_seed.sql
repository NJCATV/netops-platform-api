-- Target schema: anbo_wx on JSCN-233.
-- Adds the AIOps user and administration entry points. Internal APIs remain capability-gated by the BFF.

INSERT INTO app_menus
  (menu_key, name, icon, path, group_name, min_role, user_type, enabled, sort_order, remark)
VALUES
  ('netops.aiops', 'AIOps 智能运维', 'BrainCircuit', '/aiops', '智能运维', 'normal_user', 'internal', 1, 70, 'AIOps 看板和运维中心入口'),
  ('netops.ai_assistant', 'AI 问答', 'Bot', '/ai-assistant', '智能运维', 'normal_user', 'internal', 1, 71, '独立 AI 运维问答入口'),
  ('netops.aiops_knowledge', '知识库', 'DatabaseZap', '/aiops/knowledge', '智能运维', 'normal_user', 'internal', 1, 72, 'AIOps 故障知识库入口'),
  ('netops.aiops_admin', 'AIOps 系统管理', 'MonitorCog', '/aiops/admin', '系统管理', 'org_admin', 'internal', 1, 90, '模型、运行参数和审计统一入口')
ON DUPLICATE KEY UPDATE
  name=VALUES(name), icon=VALUES(icon), path=VALUES(path), group_name=VALUES(group_name),
  min_role=VALUES(min_role), user_type=VALUES(user_type), enabled=VALUES(enabled),
  sort_order=VALUES(sort_order), remark=VALUES(remark);

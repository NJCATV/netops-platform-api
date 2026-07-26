-- AIOps identity projection migration for the unified operations platform.
-- Target schema: jscn_aiops (MySQL 8.0)
-- Apply to a restored backup first. This migration is intentionally additive.

ALTER TABLE users
  ADD COLUMN identity_source VARCHAR(32) NOT NULL DEFAULT 'local' AFTER id,
  ADD COLUMN external_subject VARCHAR(128) NULL AFTER identity_source,
  ADD COLUMN external_role_code VARCHAR(64) NULL AFTER role,
  ADD COLUMN external_org_id BIGINT NULL AFTER external_role_code,
  ADD COLUMN external_org_name VARCHAR(128) NULL AFTER external_org_id,
  ADD COLUMN last_synced_at DATETIME NULL AFTER last_login_at,
  ADD UNIQUE KEY uk_users_external_identity (identity_source, external_subject),
  ADD KEY idx_users_external_org (external_org_id);

ALTER TABLE ai_analysis_runs
  ADD COLUMN scope_subject VARCHAR(128) NULL AFTER run_uid,
  ADD COLUMN scope_org_id BIGINT NULL AFTER scope_subject,
  ADD COLUMN scope_regions_json JSON NULL AFTER scope_org_id,
  ADD KEY idx_ai_analysis_runs_scope_subject (scope_subject),
  ADD KEY idx_ai_analysis_runs_scope_org (scope_org_id);

ALTER TABLE report_tasks
  ADD COLUMN scope_subject VARCHAR(128) NULL AFTER id,
  ADD COLUMN scope_org_id BIGINT NULL AFTER scope_subject,
  ADD COLUMN scope_regions_json JSON NULL AFTER scope_org_id,
  ADD KEY idx_report_tasks_scope_subject (scope_subject),
  ADD KEY idx_report_tasks_scope_org (scope_org_id);

CREATE TABLE IF NOT EXISTS platform_identity_audit (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  aiops_user_id INT NULL,
  identity_source VARCHAR(32) NOT NULL,
  external_subject VARCHAR(128) NOT NULL,
  username VARCHAR(128) NULL,
  role_code VARCHAR(64) NULL,
  org_id BIGINT NULL,
  org_name VARCHAR(128) NULL,
  regions_json JSON NULL,
  permissions_json JSON NULL,
  request_id VARCHAR(64) NULL,
  client_ip VARCHAR(64) NULL,
  authenticated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY idx_platform_identity_audit_subject (identity_source, external_subject, authenticated_at),
  KEY idx_platform_identity_audit_user (aiops_user_id, authenticated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS platform_device_scope (
  id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  source_system VARCHAR(64) NOT NULL DEFAULT 'go_collector',
  device_type VARCHAR(32) NOT NULL,
  source_device_id VARCHAR(64) NOT NULL,
  device_name VARCHAR(255) NULL,
  ip_address VARCHAR(64) NOT NULL,
  region_code VARCHAR(64) NOT NULL,
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uk_platform_device_scope_source (source_system, device_type, source_device_id),
  KEY idx_platform_device_scope_region_active (region_code, is_active),
  KEY idx_platform_device_scope_ip (ip_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Existing local users remain valid during the controlled transition.
UPDATE users
SET identity_source = 'local'
WHERE identity_source IS NULL OR identity_source = '';

-- Rollback: IDP entities and related tables
-- Drop triggers first
DROP TRIGGER IF EXISTS update_system_configs_modtime ON system_configs;
DROP TRIGGER IF EXISTS update_api_keys_modtime ON api_keys;
DROP TRIGGER IF EXISTS update_teams_modtime ON teams;
DROP TRIGGER IF EXISTS update_institutions_modtime ON institutions;
DROP TRIGGER IF EXISTS update_idp_entities_modtime ON idp_entities;

-- Drop indexes
DROP INDEX IF EXISTS idx_institutions_entity_id;
DROP INDEX IF EXISTS idx_teams_entity_id;
DROP INDEX IF EXISTS idx_teams_institution_id;
DROP INDEX IF EXISTS idx_idp_entities_parent_id;
DROP INDEX IF EXISTS idx_idp_entities_type;
DROP INDEX IF EXISTS idx_idp_entities_keycloak_id;
DROP INDEX IF EXISTS idx_admin_audit_logs_timestamp;
DROP INDEX IF EXISTS idx_admin_audit_logs_admin;
DROP INDEX IF EXISTS idx_api_keys_entity_id;
DROP INDEX IF EXISTS idx_api_keys_key_value;

-- Drop views
DROP VIEW IF EXISTS active_api_keys;

-- Drop tables (in reverse order to respect foreign key constraints)
DROP TABLE IF EXISTS admin_audit_logs;
DROP TABLE IF EXISTS system_configs;
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS teams;
DROP TABLE IF EXISTS institutions;
DROP TABLE IF EXISTS idp_entities;
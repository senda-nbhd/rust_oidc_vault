-- Rollback: IDP entities and related tables
-- Drop views first
DROP VIEW IF EXISTS teams_with_institutions_view;
DROP VIEW IF EXISTS institution_members_view;
DROP VIEW IF EXISTS team_members_view;

-- Drop triggers
DROP TRIGGER IF EXISTS update_system_configs_modtime ON system_configs;
DROP TRIGGER IF EXISTS update_user_roles_modtime ON user_roles;
DROP TRIGGER IF EXISTS update_teams_modtime ON teams;
DROP TRIGGER IF EXISTS update_institutions_modtime ON institutions;
DROP TRIGGER IF EXISTS update_idp_entities_modtime ON idp_entities;

-- Drop indexes
DROP INDEX IF EXISTS idx_user_roles_role;
DROP INDEX IF EXISTS idx_user_roles_institution_id;
DROP INDEX IF EXISTS idx_user_roles_team_id;
DROP INDEX IF EXISTS idx_user_roles_user_entity_id;
DROP INDEX IF EXISTS idx_institutions_entity_id;
DROP INDEX IF EXISTS idx_teams_entity_id;
DROP INDEX IF EXISTS idx_teams_institution_id;
DROP INDEX IF EXISTS idx_idp_entities_email;
DROP INDEX IF EXISTS idx_idp_entities_name;
DROP INDEX IF EXISTS idx_idp_entities_parent_id;
DROP INDEX IF EXISTS idx_idp_entities_type;
DROP INDEX IF EXISTS idx_admin_audit_logs_timestamp;
DROP INDEX IF EXISTS idx_admin_audit_logs_admin;

-- Drop tables (in reverse order to respect foreign key constraints)
DROP TABLE IF EXISTS admin_audit_logs;
DROP TABLE IF EXISTS system_configs;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS teams;
DROP TABLE IF EXISTS institutions;
DROP TABLE IF EXISTS idp_entities;
-- Create a central entity table for all Keycloak entities
CREATE TABLE idp_entities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    type VARCHAR(50) NOT NULL CHECK (type IN ('user', 'team', 'institution', 'group')),
    name VARCHAR(255) NOT NULL,              -- Cached from Keycloak for display
    path VARCHAR(255),                       -- Hierarchical path from Keycloak
    email VARCHAR(255),                      -- Only for users
    attributes JSONB,                        -- Any additional attributes cached from Keycloak
    parent_id UUID REFERENCES idp_entities(id), -- For hierarchical relationships
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_sync_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create a table for institutional relationships
CREATE TABLE institutions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    entity_id UUID NOT NULL REFERENCES idp_entities(id),
    domain VARCHAR(255) UNIQUE,              -- If needed for lookups (can be null)
    description TEXT,                        -- Longer description for the institution
    website_url VARCHAR(255),                -- Institution's website
    logo_url VARCHAR(255),                   -- URL to the institution's logo
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create teams table with competition-specific attributes
CREATE TABLE teams (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    entity_id UUID NOT NULL REFERENCES idp_entities(id),
    institution_id UUID REFERENCES institutions(id),
    competition_year INTEGER,
    description TEXT,                        -- Team description
    logo_url VARCHAR(255),                   -- URL to team logo
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create a table for institutional relationships
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    entity_id UUID NOT NULL REFERENCES idp_entities(id),
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL, 
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    attributes JSONB,  -- Stores any additional attributes as JSON
    role VARCHAR(50) NOT NULL CHECK (role IN ('admin', 'advisor', 'captain', 'student', 'spectator')),
    team_id UUID REFERENCES teams(id), -- Foreign key to teams table
    institution_id UUID REFERENCES institutions(id), -- Foreign key to institutions table
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create system configuration table for LLM settings
CREATE TABLE system_configs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key VARCHAR(255) UNIQUE NOT NULL,
    value TEXT,
    description TEXT,
    is_sensitive BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by UUID REFERENCES idp_entities(id),
    updated_by UUID REFERENCES idp_entities(id)
);

-- Create audit log for administrative actions
CREATE TABLE admin_audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    administrator_id UUID REFERENCES idp_entities(id),
    action VARCHAR(255) NOT NULL,
    entity_type VARCHAR(50) NOT NULL,
    entity_id UUID,
    details JSONB,
    ip_address INET,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Add indexes for performance
-- Create an index for faster lookups by username
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_team_id ON users(team_id);
CREATE INDEX idx_users_institution_id ON users(institution_id);
CREATE INDEX idx_admin_audit_logs_admin ON admin_audit_logs(administrator_id);
CREATE INDEX idx_admin_audit_logs_timestamp ON admin_audit_logs(timestamp);
CREATE INDEX idx_idp_entities_type ON idp_entities(type);
CREATE INDEX idx_idp_entities_parent_id ON idp_entities(parent_id);
CREATE INDEX idx_idp_entities_name ON idp_entities(name);
CREATE INDEX idx_idp_entities_email ON idp_entities(email) WHERE email IS NOT NULL;
CREATE INDEX idx_teams_institution_id ON teams(institution_id);
CREATE INDEX idx_teams_entity_id ON teams(entity_id);
CREATE INDEX idx_institutions_entity_id ON institutions(entity_id);

-- Create views for easier querying

-- View for team members with their roles
CREATE VIEW team_members_view AS
SELECT 
    t.id AS team_id,
    t.entity_id AS team_entity_id,
    te.name AS team_name,
    u.id AS user_entity_id,
    u.username,
    u.email,
    u.attributes,
    u.role,
    i.id AS institution_id,
    ie.name AS institution_name
FROM 
    teams t
JOIN idp_entities te ON t.entity_id = te.id
JOIN users u ON u.team_id = t.id
LEFT JOIN institutions i ON t.institution_id = i.id
LEFT JOIN idp_entities ie ON i.entity_id = ie.id;

-- View for institution members
CREATE VIEW institution_members_view AS
SELECT 
    i.id AS institution_id,
    i.entity_id AS institution_entity_id,
    ie.name AS institution_name,
    u.id AS user_entity_id,
    u.username,
    u.email,
    u.attributes,
    u.role
FROM 
    institutions i
JOIN idp_entities ie ON i.entity_id = ie.id
JOIN users u ON u.institution_id = i.id;

-- View for all teams with institution info
CREATE VIEW teams_with_institutions_view AS
SELECT 
    t.id AS team_id,
    t.entity_id AS team_entity_id,
    te.name AS team_name,
    t.description AS team_description,
    t.logo_url AS team_logo_url,
    t.competition_year,
    i.id AS institution_id,
    i.entity_id AS institution_entity_id,
    ie.name AS institution_name,
    i.domain AS institution_domain,
    i.website_url AS institution_website,
    i.logo_url AS institution_logo_url,
    (SELECT COUNT(*) FROM users ur WHERE ur.team_id = t.id) AS member_count,
    (SELECT COUNT(*) FROM users ur WHERE ur.team_id = t.id AND ur.role = 'captain') AS captain_count,
    (SELECT COUNT(*) FROM users ur WHERE ur.team_id = t.id AND ur.role = 'student') AS student_count
FROM 
    teams t
JOIN idp_entities te ON t.entity_id = te.id
LEFT JOIN institutions i ON t.institution_id = i.id
LEFT JOIN idp_entities ie ON i.entity_id = ie.id;

-- Triggers to automatically update timestamps
CREATE TRIGGER update_idp_entities_modtime
    BEFORE UPDATE ON idp_entities
    FOR EACH ROW
    EXECUTE FUNCTION update_modified_column();

CREATE TRIGGER update_institutions_modtime
    BEFORE UPDATE ON institutions
    FOR EACH ROW
    EXECUTE FUNCTION update_modified_column();

CREATE TRIGGER update_teams_modtime
    BEFORE UPDATE ON teams
    FOR EACH ROW
    EXECUTE FUNCTION update_modified_column();

CREATE TRIGGER update_users_modtime
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_modified_column();

CREATE TRIGGER update_system_configs_modtime
    BEFORE UPDATE ON system_configs
    FOR EACH ROW
    EXECUTE FUNCTION update_modified_column();
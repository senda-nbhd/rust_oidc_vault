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
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create teams table with competition-specific attributes
CREATE TABLE teams (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    entity_id UUID NOT NULL REFERENCES idp_entities(id),
    institution_id UUID REFERENCES institutions(id),
    competition_year INTEGER,
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
CREATE INDEX idx_admin_audit_logs_admin ON admin_audit_logs(administrator_id);
CREATE INDEX idx_admin_audit_logs_timestamp ON admin_audit_logs(timestamp);
CREATE INDEX idx_idp_entities_type ON idp_entities(type);
CREATE INDEX idx_idp_entities_parent_id ON idp_entities(parent_id);
CREATE INDEX idx_teams_institution_id ON teams(institution_id);
CREATE INDEX idx_teams_entity_id ON teams(entity_id);
CREATE INDEX idx_institutions_entity_id ON institutions(entity_id);

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

CREATE TRIGGER update_system_configs_modtime
    BEFORE UPDATE ON system_configs
    FOR EACH ROW
    EXECUTE FUNCTION update_modified_column();
select * from users;
-- Create users table (Spring Boot will auto-create with JPA, but here's the manual schema)
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    auth_provider VARCHAR(20) NOT NULL DEFAULT 'LOCAL',
    provider_id VARCHAR(255),
    enabled BOOLEAN NOT NULL DEFAULT true,
    account_non_expired BOOLEAN NOT NULL DEFAULT true,
    account_non_locked BOOLEAN NOT NULL DEFAULT true,
    credentials_non_expired BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP,
    last_login TIMESTAMP
);

-- Create indexes for better query performance
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_auth_provider ON users(auth_provider);
CREATE INDEX idx_users_created_at ON users(created_at);

-- Create a table for refresh tokens (optional, for token management)
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    token VARCHAR(500) NOT NULL UNIQUE,
    expiry_date TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create index for refresh tokens
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(token);

-- Create a table for token blacklist (for logout functionality)
CREATE TABLE IF NOT EXISTS token_blacklist (
    id BIGSERIAL PRIMARY KEY,
    token VARCHAR(500) NOT NULL UNIQUE,
    blacklisted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expiry_date TIMESTAMP NOT NULL
);

-- Create index for token blacklist
CREATE INDEX idx_token_blacklist_token ON token_blacklist(token);
CREATE INDEX idx_token_blacklist_expiry ON token_blacklist(expiry_date);

-- Create a table for audit logs (optional, for security tracking)
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT,
    action VARCHAR(50) NOT NULL,
    details TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Create indexes for audit logs
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);

-- Insert sample data (optional, for testing)
-- Password is 'password123' hashed with BCrypt
INSERT INTO users (username, email, password, first_name, last_name, auth_provider) VALUES
('admin', 'admin@example.com', '$2a$10$slYQmyNdGzTn7ZLBXBChFOC9f6kFjAqPhccnP6DxlWXx2lPk1C3G6', 'Admin', 'User', 'LOCAL'),
('johndoe', 'john@example.com', '$2a$10$slYQmyNdGzTn7ZLBXBChFOC9f6kFjAqPhccnP6DxlWXx2lPk1C3G6', 'John', 'Doe', 'LOCAL');

-- Create a function to clean up expired tokens (run periodically)
CREATE OR REPLACE FUNCTION cleanup_expired_tokens()
RETURNS void AS $$
BEGIN
    DELETE FROM refresh_tokens WHERE expiry_date < CURRENT_TIMESTAMP;
    DELETE FROM token_blacklist WHERE expiry_date < CURRENT_TIMESTAMP;
END;
$$ LANGUAGE plpgsql;

-- Create a trigger to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Grant privileges (if using a specific user)
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO sso_user;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO sso_user;

-- Display table structures
\d users
\d refresh_tokens
\d token_blacklist
\d audit_logs

-- Display sample data
SELECT id, username, email, auth_provider, created_at FROM users;

-- Success message
SELECT 'Database initialization completed successfully!' AS status;

ALTER TABLE users
ADD COLUMN roles VARCHAR(255) NOT NULL DEFAULT 'ROLE_USER';

UPDATE users SET roles = 'ROLE_USER,ROLE_ADMIN' WHERE email = 'newssouser1@gmail.com'; -- Or choose another user

SELECT roles FROM users WHERE id = 4;

SELECT id, username, email, roles
FROM users
WHERE roles LIKE '%ROLE_ADMIN%';


-- Add to your PostgreSQL schema (sso_auth_db)
CREATE TABLE sso_provider_configs (
    id BIGSERIAL PRIMARY KEY,
    provider_id VARCHAR(100) UNIQUE NOT NULL, -- e.g., 'oidc_miniorange', 'jwt_miniorange', 'saml_okta'
    provider_type VARCHAR(20) NOT NULL, -- 'OIDC', 'JWT', 'SAML'
    display_name VARCHAR(100) NOT NULL, -- Name shown in UI
    enabled BOOLEAN NOT NULL DEFAULT false,

    -- Common Fields (nullable)
    issuer_uri VARCHAR(512),
    client_id VARCHAR(255),
    client_secret VARCHAR(512), -- Store securely if possible (e.g., encrypted)
    scopes VARCHAR(512), -- Comma-separated

    -- OIDC Specific (nullable)
    authorization_uri VARCHAR(512),
    token_uri VARCHAR(512),
    user_info_uri VARCHAR(512),
    jwk_set_uri VARCHAR(512),
    user_name_attribute VARCHAR(100),

    -- Manual JWT Specific (nullable)
    jwt_sso_url VARCHAR(512),
    jwt_certificate TEXT, -- Store certificate content directly or path

    -- SAML Specific (nullable)
    saml_sso_url VARCHAR(512),
    saml_entity_id VARCHAR(512),
    saml_certificate TEXT, -- Store certificate content

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
);

-- Add indexes for faster lookups
CREATE INDEX idx_sso_provider_id ON sso_provider_configs(provider_id);
CREATE INDEX idx_sso_provider_enabled ON sso_provider_configs(enabled);

-- Trigger to update updated_at timestamp (if not already created for 'users' table)
CREATE OR REPLACE FUNCTION update_sso_config_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
   NEW.updated_at = CURRENT_TIMESTAMP;
   RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_sso_config_updated_at
BEFORE UPDATE ON sso_provider_configs
FOR EACH ROW
EXECUTE FUNCTION update_sso_config_updated_at_column();

-- Optional: Insert initial placeholder rows (disabled) for your existing configs
-- INSERT INTO sso_provider_configs (provider_id, provider_type, display_name, enabled, ...)
-- VALUES ('oidc_miniorange', 'OIDC', 'miniOrange OIDC', false, ...); -- Add other fields
-- INSERT INTO sso_provider_configs (provider_id, provider_type, display_name, enabled, ...)
-- VALUES ('jwt_miniorange', 'JWT', 'miniOrange JWT', false, ...); -- Add other fields

INSERT INTO sso_provider_configs
(provider_id, provider_type, display_name, enabled, created_at, updated_at)
VALUES
('oidc_miniorange', 'OIDC', 'MiniOrange OIDC', false, NOW(), NOW());

-- Insert a default, disabled JWT configuration
-- The provider_id 'jwt_miniorange' MUST match the ID from your login.html
INSERT INTO sso_provider_configs
(provider_id, provider_type, display_name, enabled, created_at, updated_at)
VALUES
('jwt_miniorange', 'JWT', 'MiniOrange JWT', false, NOW(), NOW());

-- Insert a default, disabled SAML configuration
INSERT INTO sso_provider_configs
(provider_id, provider_type, display_name, enabled, created_at, updated_at)
VALUES
('saml_miniorange', 'SAML', 'MiniOrange SAML', false, NOW(), NOW());

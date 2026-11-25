-- =============================================================================
-- PROYECTO: SecureVault (Laboratorio_NodeJS)
-- MOTOR: PostgreSQL 15+ / Supabase
-- DESCRIPCIÓN: Esquema relacional endurecido conforme a OWASP Top 10:2025
-- =============================================================================

BEGIN;

-- Extensión nativa para generación criptográfica de UUIDs v4
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- -----------------------------------------------------------------------------
-- Función utilitaria para actualizar automáticamente la columna updated_at
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- -----------------------------------------------------------------------------
-- 1. TABLA: users (Soporta RF-01, RF-02, RF-03, RF-05, RF-06, RF-07 y OWASP A04/A07)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL CHECK (char_length(trim(name)) >= 2),
    email VARCHAR(255) NOT NULL UNIQUE CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    -- Almacena exclusivamente hashes Argon2id ($argon2id$...) o bcrypt ($2b$...)
    password_hash TEXT NOT NULL CHECK (password_hash ~ '^(\$argon2id\$|\$2[abxy]\$)'),
    -- Control estricto de roles en base de datos (RF-03 / OWASP A01)
    role VARCHAR(10) NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    -- Campo sensible de perfil cifrado con AES-256-GCM (IV + AuthTag + Ciphertext en Base64)
    sensitive_data_enc TEXT NULL,
    -- Versión de la llave maestra AES utilizada (facilita rotación de llaves sin pérdida)
    key_version SMALLINT NOT NULL DEFAULT 1 CHECK (key_version >= 1),
    -- Controles de bloqueo progresivo ante fuerza bruta (OWASP A07)
    failed_login_attempts SMALLINT NOT NULL DEFAULT 0 CHECK (failed_login_attempts >= 0),
    locked_until TIMESTAMPTZ NULL,
    -- Marca temporal para invalidar globalmente JWTs emitidos antes de un cambio de contraseña o rol
    tokens_valid_after TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

DROP TRIGGER IF EXISTS trg_users_updated_at ON users;
CREATE TRIGGER trg_users_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION set_updated_at_timestamp();

-- -----------------------------------------------------------------------------
-- 2. TABLA: notes (Soporta RF-04 y OWASP A01/A04/A06)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS notes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title VARCHAR(120) NOT NULL CHECK (char_length(trim(title)) >= 1),
    -- Contenido cifrado con AES-256-GCM; límite de longitud para mitigar abuso (OWASP A06)
    content_enc TEXT NOT NULL CHECK (char_length(content_enc) <= 65535),
    key_version SMALLINT NOT NULL DEFAULT 1 CHECK (key_version >= 1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

DROP TRIGGER IF EXISTS trg_notes_updated_at ON notes;
CREATE TRIGGER trg_notes_updated_at
BEFORE UPDATE ON notes
FOR EACH ROW
EXECUTE FUNCTION set_updated_at_timestamp();

-- -----------------------------------------------------------------------------
-- 3. TABLA: password_reset_tokens (Soporta RF-06 y OWASP A04/A07)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Hash SHA-256 en hexadecimal (64 caracteres exactos) del token generado con crypto.randomBytes(32)
    token_hash CHAR(64) NOT NULL UNIQUE CHECK (token_hash ~ '^[a-fA-F0-9]{64}$'),
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CHECK (expires_at > created_at)
);

-- -----------------------------------------------------------------------------
-- 4. TABLA: revoked_tokens (Soporta RF-02: Invalidación de JWT en logout)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti UUID PRIMARY KEY,
    user_id UUID NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- -----------------------------------------------------------------------------
-- 5. TABLA: audit_logs (Soporta RF-07 y OWASP A09: Bitácora de seguridad)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- ON DELETE SET NULL preserva la evidencia forense aunque el usuario sea eliminado
    user_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(50) NOT NULL CHECK (
        event_type IN (
            'USER_REGISTERED',
            'LOGIN_SUCCESS',
            'LOGIN_FAILED',
            'ACCOUNT_LOCKED',
            'LOGOUT',
            'PASSWORD_RESET_REQUESTED',
            'PASSWORD_RESET_COMPLETED',
            'ROLE_CHANGED',
            'ACCESS_DENIED',
            'CRYPTO_INTEGRITY_FAILURE',
            'NOTE_CREATED',
            'NOTE_UPDATED',
            'NOTE_DELETED'
        )
    ),
    ip_address INET NOT NULL,
    user_agent TEXT NULL,
    -- Metadatos estructurados (jamás debe almacenar contraseñas, tokens ni texto plano de notas)
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- ÍNDICES DE RENDIMIENTO Y SEGURIDAD
-- =============================================================================

-- Acelera las consultas parametrizadas WHERE owner_id = $1 (Mitigación IDOR y listado de notas)
CREATE INDEX IF NOT EXISTS idx_notes_owner_id ON notes(owner_id, created_at DESC);

-- Optimiza la validación de tokens de recuperación activos y no expirados
CREATE INDEX IF NOT EXISTS idx_reset_tokens_user_active 
    ON password_reset_tokens(user_id, expires_at) 
    WHERE used = FALSE;

-- Acelera la limpieza (TTL purge) de JWTs revocados que ya expiraron naturalmente
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires_at ON revoked_tokens(expires_at);

-- Optimiza el panel de administración (RF-07) y la detección de N fallos consecutivos (OWASP A09)
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_ip ON audit_logs(event_type, ip_address, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);

COMMIT;

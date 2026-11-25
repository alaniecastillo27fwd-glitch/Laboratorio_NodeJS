import { pool, query } from '../config/db.js';

/**
 * Crea un nuevo usuario con rol estricto 'user' forzado en el servidor (RF-01 / OWASP A01).
 * Nunca devuelve password_hash.
 */
export const createUser = async ({ name, email, passwordHash, sensitiveDataEnc = null }) => {
  const sql = `
    INSERT INTO users (name, email, password_hash, role, sensitive_data_enc)
    VALUES ($1, LOWER(TRIM($2)), $3, 'user', $4)
    RETURNING id, name, email, role, created_at
  `;
  const result = await query(sql, [name.trim(), email, passwordHash, sensitiveDataEnc]);
  return result.rows[0];
};

/**
 * Busca un usuario por correo electrónico (para autenticación interna).
 */
export const findUserByEmail = async (email) => {
  const sql = `
    SELECT
      id,
      name,
      email,
      password_hash,
      role,
      sensitive_data_enc,
      key_version,
      failed_login_attempts,
      locked_until,
      tokens_valid_after,
      created_at
    FROM users
    WHERE email = LOWER(TRIM($1))
    LIMIT 1
  `;
  const result = await query(sql, [email]);
  return result.rows[0] || null;
};

/**
 * Busca un usuario por ID sin devolver jamás password_hash (para middleware auth y perfil).
 */
export const findUserById = async (id) => {
  const sql = `
    SELECT
      id,
      name,
      email,
      role,
      sensitive_data_enc,
      key_version,
      failed_login_attempts,
      locked_until,
      tokens_valid_after,
      created_at,
      updated_at
    FROM users
    WHERE id = $1
    LIMIT 1
  `;
  const result = await query(sql, [id]);
  return result.rows[0] || null;
};

/**
 * Incrementa el contador de intentos fallidos de login.
 * Si alcanza 5 o más intentos, bloquea la cuenta por 15 minutos (OWASP A07).
 */
export const recordFailedLoginAttempt = async (userId) => {
  const sql = `
    UPDATE users
    SET
      failed_login_attempts = failed_login_attempts + 1,
      locked_until = CASE
        WHEN failed_login_attempts + 1 >= 5 THEN CURRENT_TIMESTAMP + INTERVAL '15 minutes'
        ELSE locked_until
      END
    WHERE id = $1
    RETURNING failed_login_attempts, locked_until
  `;
  const result = await query(sql, [userId]);
  return result.rows[0];
};

/**
 * Reinicia el contador de fallos y desbloquea la cuenta tras un login exitoso.
 */
export const resetFailedLoginAttempts = async (userId) => {
  const sql = `
    UPDATE users
    SET failed_login_attempts = 0,
        locked_until = NULL
    WHERE id = $1
  `;
  await query(sql, [userId]);
};

/**
 * Registra un JTI en la lista de tokens revocados al cerrar sesión (RF-02).
 */
export const revokeTokenJti = async ({ jti, userId, expiresAt }) => {
  const sql = `
    INSERT INTO revoked_tokens (jti, user_id, expires_at)
    VALUES ($1, $2, $3)
    ON CONFLICT (jti) DO NOTHING
  `;
  await query(sql, [jti, userId, expiresAt]);
};

/**
 * Verifica si el JTI de un JWT fue revocado en logout.
 */
export const isTokenRevoked = async (jti) => {
  const sql = `
    SELECT 1
    FROM revoked_tokens
    WHERE jti = $1
    LIMIT 1
  `;
  const result = await query(sql, [jti]);
  return result.rowCount > 0;
};

/**
 * Invalida tokens previos y guarda únicamente el hash SHA-256 del nuevo token
 * de recuperación con expiración de 15 minutos (RF-06 / OWASP A04).
 */
export const savePasswordResetTokenHash = async ({ userId, tokenHash }) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    await client.query(
      `UPDATE password_reset_tokens
       SET used = TRUE
       WHERE user_id = $1 AND used = FALSE`,
      [userId]
    );

    const insertSql = `
      INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, used)
      VALUES ($1, $2, CURRENT_TIMESTAMP + INTERVAL '15 minutes', FALSE)
      RETURNING id, expires_at
    `;
    const result = await client.query(insertSql, [userId, tokenHash]);

    await client.query('COMMIT');
    return result.rows[0];
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
};

/**
 * Verifica y consume atómicamente un token de recuperación (un solo uso, no expirado)
 * y actualiza la contraseña con el nuevo hash Argon2id (RF-06).
 */
export const consumeResetTokenAndUpdatePassword = async ({ tokenHash, newPasswordHash }) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const tokenRes = await client.query(
      `UPDATE password_reset_tokens
       SET used = TRUE
       WHERE token_hash = $1
         AND used = FALSE
         AND expires_at > CURRENT_TIMESTAMP
       RETURNING id, user_id`,
      [tokenHash]
    );

    if (tokenRes.rowCount === 0) {
      await client.query('ROLLBACK');
      return null;
    }

    const { user_id: userId } = tokenRes.rows[0];

    await client.query(
      `UPDATE users
       SET password_hash = $1,
           failed_login_attempts = 0,
           locked_until = NULL,
           tokens_valid_after = CURRENT_TIMESTAMP
       WHERE id = $2`,
      [newPasswordHash, userId]
    );

    await client.query('COMMIT');
    return { userId };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
};

/**
 * Actualiza el campo sensible cifrado (AES-256-GCM) del perfil del usuario autenticado (RF-05).
 */
export const updateUserSensitiveData = async ({ userId, sensitiveDataEnc }) => {
  const sql = `
    UPDATE users
    SET sensitive_data_enc = $2
    WHERE id = $1
    RETURNING id, name, email, role, sensitive_data_enc, updated_at
  `;
  const result = await query(sql, [userId, sensitiveDataEnc]);
  return result.rows[0] || null;
};

/**
 * Lista todos los usuarios para el panel de administración proyectando únicamente
 * columnas explícitas y excluyendo estrictamente password_hash (RF-07).
 */
export const listAllUsersForAdmin = async () => {
  const sql = `
    SELECT
      id,
      name,
      email,
      role,
      sensitive_data_enc,
      failed_login_attempts,
      locked_until,
      created_at
    FROM users
    ORDER BY created_at DESC
    LIMIT 100
  `;
  const result = await query(sql);
  return result.rows;
};

/**
 * Actualiza el rol de un usuario ('user' o 'admin') e invalida tokens previos (RF-07).
 */
export const updateUserRoleById = async ({ userId, role }) => {
  const sql = `
    UPDATE users
    SET role = $2,
        tokens_valid_after = CURRENT_TIMESTAMP
    WHERE id = $1
    RETURNING id, name, email, role, updated_at
  `;
  const result = await query(sql, [userId, role]);
  return result.rows[0] || null;
};


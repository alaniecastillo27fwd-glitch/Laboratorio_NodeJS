import { query } from '../config/db.js';
import { logger } from '../utils/logger.js';

/**
 * Registra un evento de seguridad tanto en la tabla audit_logs de PostgreSQL
 * como en el logger estructurado JSON (Winston) sin incluir jamás secretos (OWASP A09).
 */
export const createAuditLog = async ({
  userId = null,
  eventType,
  ipAddress = '0.0.0.0',
  userAgent = null,
  details = {},
}) => {
  const safeIp = ipAddress || '0.0.0.0';
  const safeDetails = typeof details === 'object' && details !== null ? details : {};

  logger.info(`Security Audit Event: ${eventType}`, {
    event: eventType,
    userId,
    ipAddress: safeIp,
    userAgent,
    details: safeDetails,
  });

  try {
    const sql = `
      INSERT INTO audit_logs (user_id, event_type, ip_address, user_agent, details)
      VALUES ($1, $2, $3, $4, $5::jsonb)
      RETURNING id, created_at
    `;
    const result = await query(sql, [
      userId,
      eventType,
      safeIp,
      userAgent ? String(userAgent).slice(0, 500) : null,
      JSON.stringify(safeDetails),
    ]);
    return result.rows[0];
  } catch (err) {
    logger.error('Fallo al persistir evento en audit_logs', {
      event: 'AUDIT_LOG_DB_ERROR',
      originalEvent: eventType,
      userId,
      errorMessage: err.message,
      errorCode: err.code,
    });
    return null;
  }
};

/**
 * Cuenta cuántos fallos de login consecutivos recientes tiene una IP en los últimos 15 minutos
 * para disparar alertas tempranas ante ataques de fuerza bruta (OWASP A09).
 */
export const countRecentFailedLoginsByIp = async (ipAddress, windowMinutes = 15) => {
  const sql = `
    SELECT COUNT(*)::int AS count
    FROM audit_logs
    WHERE event_type = 'LOGIN_FAILED'
      AND ip_address = $1
      AND created_at >= CURRENT_TIMESTAMP - ($2::int * INTERVAL '1 minute')
  `;
  const result = await query(sql, [ipAddress || '0.0.0.0', windowMinutes]);
  return result.rows[0]?.count || 0;
};

/**
 * Obtiene los registros de la bitácora de auditoría paginados para el panel de administración (RF-07).
 * Permite hasta 100 registros ordenados por fecha descendente.
 */
export const getAuditLogs = async ({ limit = 100, offset = 0 } = {}) => {
  const safeLimit = Math.min(Math.max(Number(limit) || 100, 1), 100);
  const safeOffset = Math.max(Number(offset) || 0, 0);

  const sql = `
    SELECT
      a.id,
      a.user_id,
      u.email AS user_email,
      a.event_type,
      host(a.ip_address) AS ip_address,
      a.user_agent,
      a.details,
      a.created_at
    FROM audit_logs a
    LEFT JOIN users u ON u.id = a.user_id
    ORDER BY a.created_at DESC
    LIMIT $1 OFFSET $2
  `;
  const result = await query(sql, [safeLimit, safeOffset]);
  return result.rows;
};

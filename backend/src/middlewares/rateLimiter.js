import rateLimit from 'express-rate-limit';
import { logger } from '../utils/logger.js';
import { createAuditLog } from '../models/auditModel.js';

/**
 * Rate limiter estricto para inicio de sesión (OWASP A07 / A09):
 * Bloquea con HTTP 429 tras 5 intentos fallidos en una ventana de 15 minutos.
 */
export const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 5,
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  handler: async (req, res) => {
    logger.warn('Bloqueo por Rate Limit en endpoint de login (Fuerza Bruta detectada)', {
      alert: 'BRUTE_FORCE_DETECTED',
      event: 'LOGIN_RATE_LIMIT_EXCEEDED',
      ip: req.ip,
      path: req.originalUrl,
    });

    await createAuditLog({
      userId: null,
      eventType: 'LOGIN_FAILED',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: {
        reason: 'rate_limit_exceeded',
        alert: 'BRUTE_FORCE_DETECTED',
      },
    });

    return res.status(429).json({
      error: 'Demasiados intentos de inicio de sesión. Por favor, intente nuevamente en 15 minutos.',
    });
  },
});

/**
 * Rate limiter para registro y solicitud de recuperación de contraseña (RF-01 / RF-06).
 */
export const authActionRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn('Límite de peticiones excedido en acción de autenticación', {
      event: 'AUTH_ACTION_RATE_LIMIT',
      ip: req.ip,
      path: req.originalUrl,
    });
    return res.status(429).json({
      error: 'Demasiadas solicitudes desde esta dirección IP. Intente más tarde.',
    });
  },
});

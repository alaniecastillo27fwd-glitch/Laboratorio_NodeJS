import jwt from 'jsonwebtoken';
import { findUserById, isTokenRevoked } from '../models/userModel.js';
import { createAuditLog } from '../models/auditModel.js';

export const AUTH_COOKIE_NAME = 'sv_token';

/**
 * Middleware de autenticación que deniega por defecto (401), verifica el JWT
 * forzando el algoritmo fijo HS256 (OWASP A08), comprueba que el jti no esté
 * en revoked_tokens (RF-02) y consulta el rol vigente del usuario en PostgreSQL (RF-03).
 */
export const requireAuth = async (req, res, next) => {
  try {
    const token = req.cookies?.[AUTH_COOKIE_NAME];

    if (!token || typeof token !== 'string') {
      return res.status(401).json({
        error: 'Autenticación requerida',
      });
    }

    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      throw new Error('Configuración incompleta: JWT_SECRET no definido');
    }

    let payload;
    try {
      payload = jwt.verify(token, jwtSecret, {
        algorithms: ['HS256'],
      });
    } catch {
      return res.status(401).json({
        error: 'Sesión inválida o expirada',
      });
    }

    if (!payload?.sub || !payload?.jti) {
      return res.status(401).json({
        error: 'Token de sesión malformado',
      });
    }

    // 1. Verificar que el token no haya sido invalidado en logout (RF-02)
    const revoked = await isTokenRevoked(payload.jti);
    if (revoked) {
      return res.status(401).json({
        error: 'La sesión fue cerrada previamente',
      });
    }

    // 2. Consultar usuario y su rol actual directamente en el servidor/BD (RF-03)
    const user = await findUserById(payload.sub);
    if (!user) {
      return res.status(401).json({
        error: 'Usuario no válido',
      });
    }

    // 3. Verificar que el token no sea anterior a un restablecimiento de contraseña
    if (user.tokens_valid_after && payload.iat) {
      const validAfterSec = Math.floor(new Date(user.tokens_valid_after).getTime() / 1000);
      if (payload.iat + 1 < validAfterSec) {
        return res.status(401).json({
          error: 'Sesión invalidada por cambio de credenciales',
        });
      }
    }

    req.user = {
      id: user.id,
      sub: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      jti: payload.jti,
      exp: payload.exp,
    };

    return next();
  } catch (err) {
    return next(err);
  }
};

/**
 * Middleware de autorización basado en roles (RBAC - RF-03 / OWASP A01).
 * Verifica el rol en el servidor; si falla, registra ACCESS_DENIED en audit_logs y responde 403.
 */
export const requireRole = (...allowedRoles) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          error: 'Autenticación requerida',
        });
      }

      if (!allowedRoles.includes(req.user.role)) {
        await createAuditLog({
          userId: req.user.id,
          eventType: 'ACCESS_DENIED',
          ipAddress: req.ip,
          userAgent: req.get('user-agent'),
          details: {
            reason: 'insufficient_role',
            requiredRoles: allowedRoles,
            currentRole: req.user.role,
            path: req.originalUrl,
            method: req.method,
          },
        });

        return res.status(403).json({
          error: 'Acceso denegado: permisos insuficientes',
        });
      }

      return next();
    } catch (err) {
      return next(err);
    }
  };
};

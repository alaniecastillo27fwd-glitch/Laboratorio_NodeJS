import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import {
  hashPassword,
  verifyPassword,
  encrypt,
  generateResetToken,
  hashToken,
} from '../utils/crypto.js';
import {
  createUser,
  findUserByEmail,
  recordFailedLoginAttempt,
  resetFailedLoginAttempts,
  revokeTokenJti,
  savePasswordResetTokenHash,
  consumeResetTokenAndUpdatePassword,
} from '../models/userModel.js';
import { createAuditLog, countRecentFailedLoginsByIp } from '../models/auditModel.js';
import { AUTH_COOKIE_NAME } from '../middlewares/authMiddleware.js';
import { logger } from '../utils/logger.js';

const JWT_EXPIRATION_SECONDS = 30 * 60; // 30 minutos (RF-02)

// Política de complejidad de contraseña (RF-01 / OWASP A07):
// Mínimo 10 caracteres, máx 72, al menos 1 mayúscula, 1 minúscula, 1 número y 1 símbolo.
const passwordPolicySchema = z
  .string()
  .min(10, 'La contraseña debe tener al menos 10 caracteres')
  .max(72, 'La contraseña no puede exceder 72 caracteres')
  .regex(/[A-Z]/, 'La contraseña debe incluir al menos una letra mayúscula')
  .regex(/[a-z]/, 'La contraseña debe incluir al menos una letra minúscula')
  .regex(/[0-9]/, 'La contraseña debe incluir al menos un número')
  .regex(/[^A-Za-z0-9]/, 'La contraseña debe incluir al menos un carácter especial');

const registerSchema = z.object({
  name: z.string().trim().min(2, 'El nombre debe tener al menos 2 caracteres').max(100),
  email: z.string().trim().email('Correo electrónico inválido').max(255),
  password: passwordPolicySchema,
  sensitiveData: z.string().trim().min(4).max(64).optional(),
});

const loginSchema = z.object({
  email: z.string().trim().email('Credenciales inválidas').max(255),
  password: z.string().min(1, 'Credenciales inválidas').max(128),
});

const forgotPasswordSchema = z.object({
  email: z.string().trim().email('Correo electrónico inválido').max(255),
});

const resetPasswordSchema = z.object({
  token: z
    .string()
    .trim()
    .regex(/^[a-fA-F0-9]{64}$/, 'Formato de token inválido'),
  newPassword: passwordPolicySchema,
});

/**
 * Construye las opciones seguras de la cookie de sesión (RF-02 / OWASP A02, A04).
 */
const getSessionCookieOptions = () => {
  const isProduction = process.env.NODE_ENV === 'production';
  return {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'none' : 'lax',
    maxAge: JWT_EXPIRATION_SECONDS * 1000,
    path: '/',
  };
};

/**
 * 1. REGISTRO DE USUARIO (RF-01 - POST /api/auth/register)
 * Ignora cualquier campo 'role' enviado por el cliente y asigna 'user' en servidor.
 */
export const register = async (req, res, next) => {
  try {
    const parsed = registerSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        error: 'Datos de registro inválidos',
        details: parsed.error.issues.map((i) => ({
          field: i.path.join('.'),
          message: i.message,
        })),
      });
    }

    const { name, email, password, sensitiveData } = parsed.data;

    const existing = await findUserByEmail(email);
    if (existing) {
      return res.status(409).json({
        error: 'No fue posible completar el registro con el correo proporcionado',
      });
    }

    const passwordHash = await hashPassword(password);
    const sensitiveDataEnc = sensitiveData ? encrypt(sensitiveData) : null;

    const newUser = await createUser({
      name,
      email,
      passwordHash,
      sensitiveDataEnc,
    });

    await createAuditLog({
      userId: newUser.id,
      eventType: 'USER_REGISTERED',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: { role: newUser.role },
    });

    return res.status(201).json({
      message: 'Usuario registrado exitosamente',
      user: {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email,
        role: newUser.role,
        createdAt: newUser.created_at,
      },
    });
  } catch (err) {
    return next(err);
  }
};

/**
 * 2. INICIO DE SESIÓN (RF-02 - POST /api/auth/login)
 * Incluye bloqueo progresivo en BD, mensajes de error genéricos, emisión de JWT HS256
 * con jti en cookie HttpOnly y alerta ante 5 fallos consecutivos (OWASP A07 / A09).
 */
export const login = async (req, res, next) => {
  try {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(401).json({
        error: 'Credenciales inválidas',
      });
    }

    const { email, password } = parsed.data;
    const user = await findUserByEmail(email);

    // Si el usuario no existe, registramos el fallo sin revelar que el correo no existe
    if (!user) {
      await createAuditLog({
        userId: null,
        eventType: 'LOGIN_FAILED',
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        details: { reason: 'invalid_credentials' },
      });

      const recentIpFailures = await countRecentFailedLoginsByIp(req.ip, 15);
      if (recentIpFailures >= 5) {
        logger.warn({
          alert: 'BRUTE_FORCE_DETECTED',
          ipAddress: req.ip,
          consecutiveFailures: recentIpFailures,
        });
      }

      return res.status(401).json({
        error: 'Credenciales inválidas',
      });
    }

    // Verificar si la cuenta se encuentra temporalmente bloqueada (locked_until)
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      await createAuditLog({
        userId: user.id,
        eventType: 'LOGIN_FAILED',
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        details: { reason: 'account_locked', lockedUntil: user.locked_until },
      });

      return res.status(429).json({
        error: 'Demasiados intentos fallidos. La cuenta se encuentra temporalmente bloqueada.',
      });
    }

    const isPasswordValid = await verifyPassword(user.password_hash, password);

    if (!isPasswordValid) {
      const updatedLockState = await recordFailedLoginAttempt(user.id);
      const attempts = updatedLockState?.failed_login_attempts || 1;

      await createAuditLog({
        userId: user.id,
        eventType: 'LOGIN_FAILED',
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        details: {
          reason: 'invalid_credentials',
          failedAttempts: attempts,
        },
      });

      if (attempts >= 5) {
        logger.warn({
          alert: 'BRUTE_FORCE_DETECTED',
          userId: user.id,
          ipAddress: req.ip,
          failedAttempts: attempts,
          lockedUntil: updatedLockState?.locked_until,
        });

        await createAuditLog({
          userId: user.id,
          eventType: 'ACCOUNT_LOCKED',
          ipAddress: req.ip,
          userAgent: req.get('user-agent'),
          details: {
            alert: 'BRUTE_FORCE_DETECTED',
            failedAttempts: attempts,
            lockedUntil: updatedLockState?.locked_until,
          },
        });
      }

      return res.status(401).json({
        error: 'Credenciales inválidas',
      });
    }

    // Login exitoso: reiniciar contador de fallos en BD
    await resetFailedLoginAttempts(user.id);

    const jwtSecret = process.env.JWT_SECRET;
    if (!jwtSecret) {
      throw new Error('Configuración incompleta: JWT_SECRET no definido');
    }

    const jti = crypto.randomUUID();
    const token = jwt.sign(
      {
        sub: user.id,
        role: user.role,
        jti,
      },
      jwtSecret,
      {
        algorithm: 'HS256',
        expiresIn: JWT_EXPIRATION_SECONDS,
      }
    );

    res.cookie(AUTH_COOKIE_NAME, token, getSessionCookieOptions());

    await createAuditLog({
      userId: user.id,
      eventType: 'LOGIN_SUCCESS',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: { role: user.role, jti },
    });

    return res.status(200).json({
      message: 'Inicio de sesión exitoso',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    return next(err);
  }
};

/**
 * 3. CIERRE DE SESIÓN CON REVOCACIÓN DE JTI (RF-02 - POST /api/auth/logout)
 */
export const logout = async (req, res, next) => {
  try {
    const { id: userId, jti, exp } = req.user;
    const expiresAt = exp
      ? new Date(exp * 1000)
      : new Date(Date.now() + JWT_EXPIRATION_SECONDS * 1000);

    await revokeTokenJti({
      jti,
      userId,
      expiresAt,
    });

    const isProduction = process.env.NODE_ENV === 'production';
    res.clearCookie(AUTH_COOKIE_NAME, {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? 'none' : 'lax',
      path: '/',
    });

    await createAuditLog({
      userId,
      eventType: 'LOGOUT',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: { revokedJti: jti },
    });

    return res.status(200).json({
      message: 'Sesión cerrada e invalidada correctamente',
    });
  } catch (err) {
    return next(err);
  }
};

/**
 * 4. SOLICITUD DE RECUPERACIÓN DE CONTRASEÑA (RF-06 - POST /api/auth/forgot-password)
 * Genera token aleatorio de 32 bytes y guarda SOLO su hash SHA-256 en BD.
 */
export const forgotPassword = async (req, res, next) => {
  try {
    const parsed = forgotPasswordSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        error: 'Formato de correo electrónico inválido',
      });
    }

    const { email } = parsed.data;
    const genericMessage =
      'Si el correo electrónico se encuentra registrado, recibirá instrucciones para restablecer su contraseña.';

    const user = await findUserByEmail(email);
    if (!user) {
      return res.status(200).json({ message: genericMessage });
    }

    const rawToken = generateResetToken();
    const tokenHash = hashToken(rawToken);

    await savePasswordResetTokenHash({
      userId: user.id,
      tokenHash,
    });

    await createAuditLog({
      userId: user.id,
      eventType: 'PASSWORD_RESET_REQUESTED',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: { expiresMinutes: 15 },
    });

    // En desarrollo se devuelve el token en la respuesta para facilitar pruebas locales;
    // en producción jamás se expone en respuesta ni en logs.
    const isDevelopment = process.env.NODE_ENV !== 'production';
    return res.status(200).json({
      message: genericMessage,
      ...(isDevelopment && { devResetToken: rawToken }),
    });
  } catch (err) {
    return next(err);
  }
};

/**
 * 5. RESTABLECIMIENTO DE CONTRASEÑA CON TOKEN DE UN SOLO USO (RF-06 - POST /api/auth/reset-password)
 */
export const resetPassword = async (req, res, next) => {
  try {
    const parsed = resetPasswordSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        error: 'Datos de restablecimiento inválidos',
        details: parsed.error.issues.map((i) => ({
          field: i.path.join('.'),
          message: i.message,
        })),
      });
    }

    const { token, newPassword } = parsed.data;
    const tokenHash = hashToken(token);
    const newPasswordHash = await hashPassword(newPassword);

    const updated = await consumeResetTokenAndUpdatePassword({
      tokenHash,
      newPasswordHash,
    });

    if (!updated) {
      return res.status(400).json({
        error: 'El token de recuperación es inválido, ya fue utilizado o ha expirado',
      });
    }

    await createAuditLog({
      userId: updated.userId,
      eventType: 'PASSWORD_RESET_COMPLETED',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: { allPreviousSessionsInvalidated: true },
    });

    return res.status(200).json({
      message: 'Contraseña actualizada exitosamente. Ya puede iniciar sesión.',
    });
  } catch (err) {
    return next(err);
  }
};

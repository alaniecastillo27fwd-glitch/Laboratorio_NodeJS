import { z } from 'zod';
import { decrypt, maskSensitiveData } from '../utils/crypto.js';
import { listAllUsersForAdmin, updateUserRoleById, findUserById } from '../models/userModel.js';
import { getAuditLogs, createAuditLog } from '../models/auditModel.js';

const uuidSchema = z.string().uuid('Identificador de usuario inválido');

const roleUpdateSchema = z.object({
  role: z.enum(['user', 'admin'], {
    errorMap: () => ({ message: "El rol debe ser exclusivamente 'user' o 'admin'" }),
  }),
});

/**
 * GET /api/admin/users — Lista usuarios proyectando únicamente columnas seguras
 * (jamás password_hash) y mostrando el dato sensible siempre enmascarado (RF-07).
 */
export const listUsers = async (_req, res, next) => {
  try {
    const rows = await listAllUsersForAdmin();

    const users = rows.map((u) => {
      let maskedSensitive = null;
      if (u.sensitive_data_enc) {
        try {
          const plain = decrypt(u.sensitive_data_enc);
          maskedSensitive = maskSensitiveData(plain);
        } catch {
          maskedSensitive = '[ERROR_INTEGRIDAD_CIFRADO]';
        }
      }

      return {
        id: u.id,
        name: u.name,
        email: u.email,
        role: u.role,
        sensitive_data: maskedSensitive,
        failedLoginAttempts: u.failed_login_attempts,
        lockedUntil: u.locked_until,
        createdAt: u.created_at,
      };
    });

    return res.status(200).json({ users });
  } catch (err) {
    return next(err);
  }
};

/**
 * PATCH /api/admin/users/:id/role — Cambia el rol de un usuario ('user' | 'admin')
 * y registra el evento ROLE_CHANGED en audit_logs (RF-07 / OWASP A09).
 */
export const changeUserRole = async (req, res, next) => {
  try {
    const idCheck = uuidSchema.safeParse(req.params.id);
    if (!idCheck.success) {
      return res.status(400).json({ error: 'Identificador de usuario inválido' });
    }

    const parsed = roleUpdateSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        error: 'Rol inválido',
        details: parsed.error.issues.map((i) => ({
          field: i.path.join('.'),
          message: i.message,
        })),
      });
    }

    const targetUserId = idCheck.data;
    const { role: newRole } = parsed.data;

    // Prevenir que el administrador actual se quite su propio rol admin accidentalmente
    if (targetUserId === req.user.id && newRole !== 'admin') {
      return res.status(400).json({
        error: 'Un administrador no puede degradar su propio rol desde su sesión activa',
      });
    }

    const targetUser = await findUserById(targetUserId);
    if (!targetUser) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const previousRole = targetUser.role;
    const updatedUser = await updateUserRoleById({
      userId: targetUserId,
      role: newRole,
    });

    await createAuditLog({
      userId: req.user.id,
      eventType: 'ROLE_CHANGED',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: {
        targetUserId,
        targetUserEmail: updatedUser.email,
        previousRole,
        newRole,
      },
    });

    return res.status(200).json({
      message: 'Rol de usuario actualizado correctamente',
      user: {
        id: updatedUser.id,
        name: updatedUser.name,
        email: updatedUser.email,
        role: updatedUser.role,
        updatedAt: updatedUser.updated_at,
      },
    });
  } catch (err) {
    return next(err);
  }
};

/**
 * GET /api/admin/audit-logs — Devuelve los últimos 100 eventos de seguridad
 * ordenados por fecha descendente (RF-07 / OWASP A09).
 */
export const listAuditLogs = async (req, res, next) => {
  try {
    const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 100);
    const offset = Math.max(Number(req.query.offset) || 0, 0);

    const logs = await getAuditLogs({ limit, offset });
    return res.status(200).json({ auditLogs: logs });
  } catch (err) {
    return next(err);
  }
};

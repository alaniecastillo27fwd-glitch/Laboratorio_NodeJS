import { z } from 'zod';
import { encrypt, decrypt, maskSensitiveData } from '../utils/crypto.js';
import { findUserById, updateUserSensitiveData } from '../models/userModel.js';
import { createAuditLog } from '../models/auditModel.js';

// Validación Zod para teléfono o número de documento sensible (RF-05 / OWASP A05)
const sensitiveDataSchema = z.object({
  sensitiveData: z
    .string()
    .trim()
    .min(4, 'El dato sensible debe tener al menos 4 caracteres')
    .max(64, 'El dato sensible no puede exceder 64 caracteres')
    .regex(
      /^[A-Za-z0-9+\-\s]+$/,
      'El dato sensible solo puede contener caracteres alfanuméricos, espacios o guiones'
    ),
});

/**
 * GET /api/profile — Devuelve el perfil del usuario autenticado con el campo
 * sensible enmascarado (***-***-1234) por defecto, o completo si ?reveal=true (RF-05).
 */
export const getProfile = async (req, res, next) => {
  try {
    const user = await findUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const shouldReveal = req.query.reveal === 'true';
    let sensitiveDataOutput = null;

    if (user.sensitive_data_enc) {
      try {
        const plainSensitive = decrypt(user.sensitive_data_enc);
        sensitiveDataOutput = shouldReveal ? plainSensitive : maskSensitiveData(plainSensitive);
      } catch (err) {
        await createAuditLog({
          userId: req.user.id,
          eventType: 'CRYPTO_INTEGRITY_FAILURE',
          ipAddress: req.ip,
          userAgent: req.get('user-agent'),
          details: {
            resource: 'user_profile_sensitive_data',
            reason: 'gcm_auth_tag_verification_failed',
          },
        });
        throw err;
      }
    }

    return res.status(200).json({
      profile: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        sensitive_data: sensitiveDataOutput,
        revealed: Boolean(shouldReveal && user.sensitive_data_enc),
        createdAt: user.created_at,
        updatedAt: user.updated_at,
      },
    });
  } catch (err) {
    return next(err);
  }
};

/**
 * PUT /api/profile/sensitive — Valida, cifra con AES-256-GCM y almacena el dato
 * sensible de perfil del usuario autenticado (RF-05).
 */
export const updateSensitiveProfileData = async (req, res, next) => {
  try {
    const parsed = sensitiveDataSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        error: 'Dato sensible inválido',
        details: parsed.error.issues.map((i) => ({
          field: i.path.join('.'),
          message: i.message,
        })),
      });
    }

    const { sensitiveData } = parsed.data;
    const sensitiveDataEnc = encrypt(sensitiveData);

    const updatedUser = await updateUserSensitiveData({
      userId: req.user.id,
      sensitiveDataEnc,
    });

    if (!updatedUser) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    return res.status(200).json({
      message: 'Dato sensible actualizado y cifrado correctamente',
      profile: {
        id: updatedUser.id,
        name: updatedUser.name,
        email: updatedUser.email,
        role: updatedUser.role,
        sensitive_data: maskSensitiveData(sensitiveData),
        updatedAt: updatedUser.updated_at,
      },
    });
  } catch (err) {
    return next(err);
  }
};

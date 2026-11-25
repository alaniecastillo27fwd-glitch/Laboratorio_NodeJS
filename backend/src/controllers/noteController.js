import { z } from 'zod';
import { encrypt, decrypt } from '../utils/crypto.js';
import {
  countNotesByOwner,
  createNote,
  findNotesByOwner,
  findNoteByIdAndOwner,
  updateNoteByIdAndOwner,
  deleteNoteByIdAndOwner,
} from '../models/noteModel.js';
import { createAuditLog } from '../models/auditModel.js';

const MAX_NOTES_PER_USER = 50; // Límite de negocio OWASP A06

const uuidSchema = z.string().uuid('Identificador de nota inválido');

const notePayloadSchema = z.object({
  title: z
    .string()
    .trim()
    .min(1, 'El título es obligatorio')
    .max(120, 'El título no puede exceder 120 caracteres'),
  content: z
    .string()
    .min(1, 'El contenido de la nota no puede estar vacío')
    .max(5000, 'El contenido de la nota no puede exceder 5,000 caracteres'),
});

/**
 * Descifra una fila de nota de forma segura; si el AuthTag de 16 bytes de AES-256-GCM
 * falla por manipulación en la BD, registra CRYPTO_INTEGRITY_FAILURE (OWASP A04 / A08 / A09).
 */
const decryptNoteRow = async (noteRow, req) => {
  try {
    const plainContent = decrypt(noteRow.content_enc);
    return {
      id: noteRow.id,
      ownerId: noteRow.owner_id,
      title: noteRow.title,
      content: plainContent,
      createdAt: noteRow.created_at,
      updatedAt: noteRow.updated_at,
    };
  } catch (err) {
    await createAuditLog({
      userId: req.user?.id || null,
      eventType: 'CRYPTO_INTEGRITY_FAILURE',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: {
        noteId: noteRow.id,
        reason: 'gcm_auth_tag_verification_failed',
      },
    });
    throw err;
  }
};

/**
 * GET /api/notes — Lista todas las notas privadas del usuario autenticado (RF-04).
 */
export const listNotes = async (req, res, next) => {
  try {
    const rows = await findNotesByOwner(req.user.id);
    const notes = [];
    for (const row of rows) {
      notes.push(await decryptNoteRow(row, req));
    }
    return res.status(200).json({ notes });
  } catch (err) {
    return next(err);
  }
};

/**
 * GET /api/notes/:id — Obtiene una nota específica verificando WHERE id = $1 AND owner_id = $2 (A01).
 */
export const getNoteById = async (req, res, next) => {
  try {
    const idCheck = uuidSchema.safeParse(req.params.id);
    if (!idCheck.success) {
      return res.status(400).json({ error: 'Identificador de nota inválido' });
    }

    const noteRow = await findNoteByIdAndOwner(idCheck.data, req.user.id);

    if (!noteRow) {
      await createAuditLog({
        userId: req.user.id,
        eventType: 'ACCESS_DENIED',
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        details: {
          resource: 'note',
          action: 'READ',
          targetNoteId: idCheck.data,
        },
      });
      return res.status(404).json({ error: 'Nota no encontrada' });
    }

    const note = await decryptNoteRow(noteRow, req);
    return res.status(200).json({ note });
  } catch (err) {
    return next(err);
  }
};

/**
 * POST /api/notes — Crea una nota privada cifrada validando cuota máxima de 50 notas (RF-04 / A06).
 */
export const createNewNote = async (req, res, next) => {
  try {
    const parsed = notePayloadSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        error: 'Datos de nota inválidos',
        details: parsed.error.issues.map((i) => ({
          field: i.path.join('.'),
          message: i.message,
        })),
      });
    }

    const currentCount = await countNotesByOwner(req.user.id);
    if (currentCount >= MAX_NOTES_PER_USER) {
      return res.status(400).json({
        error: `Ha alcanzado el límite máximo permitido de ${MAX_NOTES_PER_USER} notas por usuario`,
      });
    }

    const { title, content } = parsed.data;
    const contentEnc = encrypt(content);

    const createdRow = await createNote({
      ownerId: req.user.id,
      title,
      contentEnc,
    });

    await createAuditLog({
      userId: req.user.id,
      eventType: 'NOTE_CREATED',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: { noteId: createdRow.id },
    });

    return res.status(201).json({
      message: 'Nota creada y cifrada exitosamente',
      note: {
        id: createdRow.id,
        ownerId: createdRow.owner_id,
        title: createdRow.title,
        content,
        createdAt: createdRow.created_at,
        updatedAt: createdRow.updated_at,
      },
    });
  } catch (err) {
    return next(err);
  }
};

/**
 * PUT /api/notes/:id — Actualiza una nota cifrada verificando WHERE id = $1 AND owner_id = $2 (RF-04 / A01).
 */
export const updateNote = async (req, res, next) => {
  try {
    const idCheck = uuidSchema.safeParse(req.params.id);
    if (!idCheck.success) {
      return res.status(400).json({ error: 'Identificador de nota inválido' });
    }

    const parsed = notePayloadSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        error: 'Datos de nota inválidos',
        details: parsed.error.issues.map((i) => ({
          field: i.path.join('.'),
          message: i.message,
        })),
      });
    }

    const { title, content } = parsed.data;
    const contentEnc = encrypt(content);

    const updatedRow = await updateNoteByIdAndOwner({
      noteId: idCheck.data,
      ownerId: req.user.id,
      title,
      contentEnc,
    });

    if (!updatedRow) {
      await createAuditLog({
        userId: req.user.id,
        eventType: 'ACCESS_DENIED',
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        details: {
          resource: 'note',
          action: 'UPDATE',
          targetNoteId: idCheck.data,
        },
      });
      return res.status(404).json({ error: 'Nota no encontrada' });
    }

    await createAuditLog({
      userId: req.user.id,
      eventType: 'NOTE_UPDATED',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: { noteId: updatedRow.id },
    });

    return res.status(200).json({
      message: 'Nota actualizada exitosamente',
      note: {
        id: updatedRow.id,
        ownerId: updatedRow.owner_id,
        title: updatedRow.title,
        content,
        createdAt: updatedRow.created_at,
        updatedAt: updatedRow.updated_at,
      },
    });
  } catch (err) {
    return next(err);
  }
};

/**
 * DELETE /api/notes/:id — Elimina una nota verificando WHERE id = $1 AND owner_id = $2 (RF-04 / A01).
 */
export const deleteNote = async (req, res, next) => {
  try {
    const idCheck = uuidSchema.safeParse(req.params.id);
    if (!idCheck.success) {
      return res.status(400).json({ error: 'Identificador de nota inválido' });
    }

    const deleted = await deleteNoteByIdAndOwner(idCheck.data, req.user.id);

    if (!deleted) {
      await createAuditLog({
        userId: req.user.id,
        eventType: 'ACCESS_DENIED',
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        details: {
          resource: 'note',
          action: 'DELETE',
          targetNoteId: idCheck.data,
        },
      });
      return res.status(404).json({ error: 'Nota no encontrada' });
    }

    await createAuditLog({
      userId: req.user.id,
      eventType: 'NOTE_DELETED',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: { noteId: deleted.id },
    });

    return res.status(200).json({
      message: 'Nota eliminada correctamente',
    });
  } catch (err) {
    return next(err);
  }
};

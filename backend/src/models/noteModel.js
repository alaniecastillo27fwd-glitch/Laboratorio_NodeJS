import { query } from '../config/db.js';

/**
 * Cuenta el total de notas activas pertenecientes a un usuario
 * para aplicar el límite de negocio de máximo 50 notas (OWASP A06).
 */
export const countNotesByOwner = async (ownerId) => {
  const sql = `
    SELECT COUNT(*)::int AS count
    FROM notes
    WHERE owner_id = $1
  `;
  const result = await query(sql, [ownerId]);
  return result.rows[0]?.count || 0;
};

/**
 * Crea una nueva nota con el contenido cifrado en AES-256-GCM (RF-04 / OWASP A04).
 */
export const createNote = async ({ ownerId, title, contentEnc }) => {
  const sql = `
    INSERT INTO notes (owner_id, title, content_enc)
    VALUES ($1, $2, $3)
    RETURNING id, owner_id, title, content_enc, key_version, created_at, updated_at
  `;
  const result = await query(sql, [ownerId, title.trim(), contentEnc]);
  return result.rows[0];
};

/**
 * Lista únicamente las notas que pertenecen al usuario autenticado (WHERE owner_id = $1).
 */
export const findNotesByOwner = async (ownerId) => {
  const sql = `
    SELECT id, owner_id, title, content_enc, key_version, created_at, updated_at
    FROM notes
    WHERE owner_id = $1
    ORDER BY created_at DESC
    LIMIT 50
  `;
  const result = await query(sql, [ownerId]);
  return result.rows;
};

/**
 * Busca una nota por ID y propietario en una única consulta parametrizada
 * para prevención estricta de IDOR (WHERE id = $1 AND owner_id = $2 - OWASP A01).
 */
export const findNoteByIdAndOwner = async (noteId, ownerId) => {
  const sql = `
    SELECT id, owner_id, title, content_enc, key_version, created_at, updated_at
    FROM notes
    WHERE id = $1 AND owner_id = $2
    LIMIT 1
  `;
  const result = await query(sql, [noteId, ownerId]);
  return result.rows[0] || null;
};

/**
 * Actualiza el título y contenido cifrado de una nota verificando estrictamente
 * la propiedad en la cláusula WHERE (WHERE id = $1 AND owner_id = $2 - OWASP A01).
 */
export const updateNoteByIdAndOwner = async ({ noteId, ownerId, title, contentEnc }) => {
  const sql = `
    UPDATE notes
    SET title = $3,
        content_enc = $4
    WHERE id = $1 AND owner_id = $2
    RETURNING id, owner_id, title, content_enc, key_version, created_at, updated_at
  `;
  const result = await query(sql, [noteId, ownerId, title.trim(), contentEnc]);
  return result.rows[0] || null;
};

/**
 * Elimina una nota verificando estrictamente la propiedad en la cláusula WHERE
 * (WHERE id = $1 AND owner_id = $2 - OWASP A01).
 */
export const deleteNoteByIdAndOwner = async (noteId, ownerId) => {
  const sql = `
    DELETE FROM notes
    WHERE id = $1 AND owner_id = $2
    RETURNING id
  `;
  const result = await query(sql, [noteId, ownerId]);
  return result.rows[0] || null;
};

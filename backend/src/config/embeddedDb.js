import crypto from 'node:crypto';
import { hashPassword, encrypt } from '../utils/crypto.js';
import { logger } from '../utils/logger.js';

/**
 * Motor compatible con el pool de 'pg' que actúa como respaldo automático en memoria
 * cuando PostgreSQL local no está levantado, garantizando las mismas validaciones,
 * hashes Argon2id ($argon2id$), cifrado AES-256-GCM y bitácora de auditoría.
 */
class EmbeddedPgFallback {
  constructor() {
    this.users = [];
    this.notes = [];
    this.password_reset_tokens = [];
    this.revoked_tokens = [];
    this.audit_logs = [];
    this.seedPromise = null;
  }

  async ensureSeeded() {
    if (this.seedPromise) {
      return this.seedPromise;
    }

    this.seedPromise = (async () => {
      try {
        const adminPasswordHash = await hashPassword('AdminSecure2025!');
        const userPasswordHash = await hashPassword('UserSecure2025!');
        const adminSensitiveEnc = encrypt('506-8888-9999');
        const userSensitiveEnc = encrypt('506-7777-1234');
        const now = new Date().toISOString();

        const adminId = crypto.randomUUID();
        const userId = crypto.randomUUID();

        this.users.push(
          {
            id: adminId,
            name: 'Administrador SecureVault',
            email: 'admin@securevault.com',
            password_hash: adminPasswordHash,
            role: 'admin',
            sensitive_data_enc: adminSensitiveEnc,
            key_version: 1,
            failed_login_attempts: 0,
            locked_until: null,
            tokens_valid_after: now,
            created_at: now,
            updated_at: now,
          },
          {
            id: userId,
            name: 'Usuario Estándar Demo',
            email: 'usuario@securevault.com',
            password_hash: userPasswordHash,
            role: 'user',
            sensitive_data_enc: userSensitiveEnc,
            key_version: 1,
            failed_login_attempts: 0,
            locked_until: null,
            tokens_valid_after: now,
            created_at: now,
            updated_at: now,
          }
        );

        this.notes.push({
          id: crypto.randomUUID(),
          owner_id: adminId,
          title: 'Nota Cifrada del Administrador (AES-256-GCM)',
          content_enc: encrypt(
            'Contenido confidencial del administrador protegido con AES-256-GCM e IV único de 12 bytes.'
          ),
          key_version: 1,
          created_at: now,
          updated_at: now,
        });

        this.audit_logs.push({
          id: crypto.randomUUID(),
          user_id: adminId,
          event_type: 'USER_REGISTERED',
          ip_address: '127.0.0.1',
          user_agent: 'System-Seed/1.0',
          details: { role: 'admin', info: 'Cuenta de administrador inicializada' },
          created_at: now,
        });
      } catch (err) {
        logger.error('Error al inicializar usuarios demo en memoria', { message: err.message });
      }
    })();

    return this.seedPromise;
  }

  async connect() {
    await this.ensureSeeded();
    return {
      query: (text, params) => this.query(text, params),
      release: () => {},
    };
  }

  async end() {}

  async query(text, params = []) {
    await this.ensureSeeded();
    const sql = text.replace(/\s+/g, ' ').trim();
    const now = new Date().toISOString();

    // Transacciones y healthcheck
    if (/^(BEGIN|COMMIT|ROLLBACK)$/i.test(sql) || /^SELECT 1$/i.test(sql)) {
      return { rows: [{ '?column?': 1 }], rowCount: 1 };
    }

    // 1. audit_logs INSERT
    if (sql.startsWith('INSERT INTO audit_logs')) {
      const [user_id, event_type, ip_address, user_agent, detailsJson] = params;
      const entry = {
        id: crypto.randomUUID(),
        user_id: user_id || null,
        event_type,
        ip_address: ip_address || '127.0.0.1',
        user_agent: user_agent || null,
        details: typeof detailsJson === 'string' ? JSON.parse(detailsJson) : detailsJson || {},
        created_at: now,
      };
      this.audit_logs.unshift(entry);
      return { rows: [{ id: entry.id, created_at: entry.created_at }], rowCount: 1 };
    }

    // 2. audit_logs COUNT recent failed logins by IP
    if (sql.includes('FROM audit_logs') && sql.includes("event_type = 'LOGIN_FAILED'")) {
      const [ip, windowMinutes] = params;
      const cutoff = Date.now() - (Number(windowMinutes) || 15) * 60 * 1000;
      const count = this.audit_logs.filter(
        (l) =>
          l.event_type === 'LOGIN_FAILED' &&
          l.ip_address === ip &&
          new Date(l.created_at).getTime() >= cutoff
      ).length;
      return { rows: [{ count }], rowCount: 1 };
    }

    // 3. audit_logs SELECT paginado con JOIN users
    if (sql.includes('FROM audit_logs a') && sql.includes('LEFT JOIN users u')) {
      const [limit, offset] = params;
      const slice = this.audit_logs.slice(offset || 0, (offset || 0) + (limit || 100)).map((a) => {
        const u = this.users.find((usr) => usr.id === a.user_id);
        return {
          ...a,
          user_email: u ? u.email : null,
        };
      });
      return { rows: slice, rowCount: slice.length };
    }

    // 4. users INSERT
    if (sql.startsWith('INSERT INTO users')) {
      const [name, email, password_hash, sensitive_data_enc] = params;
      const roleMatch = sql.includes("'admin'") ? 'admin' : 'user';
      const newUser = {
        id: crypto.randomUUID(),
        name,
        email: String(email).toLowerCase().trim(),
        password_hash,
        role: roleMatch,
        sensitive_data_enc: sensitive_data_enc || null,
        key_version: 1,
        failed_login_attempts: 0,
        locked_until: null,
        tokens_valid_after: now,
        created_at: now,
        updated_at: now,
      };
      this.users.unshift(newUser);
      return { rows: [newUser], rowCount: 1 };
    }

    // 5. users SELECT by email
    if (sql.includes('FROM users') && sql.includes('WHERE email = LOWER(TRIM($1))')) {
      const email = String(params[0] || '').toLowerCase().trim();
      const user = this.users.find((u) => u.email === email);
      return { rows: user ? [user] : [], rowCount: user ? 1 : 0 };
    }

    // 6. users SELECT by id
    if (sql.includes('FROM users') && sql.includes('WHERE id = $1')) {
      const user = this.users.find((u) => u.id === params[0]);
      return { rows: user ? [user] : [], rowCount: user ? 1 : 0 };
    }

    // 7. users UPDATE failed_login_attempts (recordFailedLoginAttempt)
    if (sql.startsWith('UPDATE users') && sql.includes('failed_login_attempts = failed_login_attempts + 1')) {
      const user = this.users.find((u) => u.id === params[0]);
      if (!user) return { rows: [], rowCount: 0 };
      user.failed_login_attempts += 1;
      if (user.failed_login_attempts >= 5) {
        user.locked_until = new Date(Date.now() + 15 * 60 * 1000).toISOString();
      }
      user.updated_at = now;
      return {
        rows: [
          {
            failed_login_attempts: user.failed_login_attempts,
            locked_until: user.locked_until,
          },
        ],
        rowCount: 1,
      };
    }

    // 8. users UPDATE resetFailedLoginAttempts
    if (sql.startsWith('UPDATE users') && sql.includes('SET failed_login_attempts = 0')) {
      const user = this.users.find((u) => u.id === params[0]);
      if (user) {
        user.failed_login_attempts = 0;
        user.locked_until = null;
        user.updated_at = now;
      }
      return { rows: [], rowCount: user ? 1 : 0 };
    }

    // 9. users UPDATE password_hash on resetPassword
    if (sql.startsWith('UPDATE users') && sql.includes('SET password_hash = $1')) {
      const [newPasswordHash, userId] = params;
      const user = this.users.find((u) => u.id === userId);
      if (user) {
        user.password_hash = newPasswordHash;
        user.failed_login_attempts = 0;
        user.locked_until = null;
        user.tokens_valid_after = now;
        user.updated_at = now;
      }
      return { rows: user ? [user] : [], rowCount: user ? 1 : 0 };
    }

    // 10. users UPDATE sensitive_data_enc
    if (sql.startsWith('UPDATE users') && sql.includes('SET sensitive_data_enc = $2')) {
      const [userId, sensitiveDataEnc] = params;
      const user = this.users.find((u) => u.id === userId);
      if (!user) return { rows: [], rowCount: 0 };
      user.sensitive_data_enc = sensitiveDataEnc;
      user.updated_at = now;
      return { rows: [user], rowCount: 1 };
    }

    // 11. users SELECT all for admin
    if (sql.includes('FROM users') && sql.includes('ORDER BY created_at DESC')) {
      return { rows: [...this.users], rowCount: this.users.length };
    }

    // 12. users UPDATE role
    if (sql.startsWith('UPDATE users') && sql.includes('SET role = $2')) {
      const [userId, role] = params;
      const user = this.users.find((u) => u.id === userId);
      if (!user) return { rows: [], rowCount: 0 };
      user.role = role;
      user.tokens_valid_after = now;
      user.updated_at = now;
      return { rows: [user], rowCount: 1 };
    }

    // 13. revoked_tokens INSERT & SELECT
    if (sql.startsWith('INSERT INTO revoked_tokens')) {
      const [jti, user_id, expires_at] = params;
      if (!this.revoked_tokens.some((t) => t.jti === jti)) {
        this.revoked_tokens.push({ jti, user_id, expires_at, revoked_at: now });
      }
      return { rows: [], rowCount: 1 };
    }

    if (sql.includes('FROM revoked_tokens') && sql.includes('WHERE jti = $1')) {
      const found = this.revoked_tokens.some((t) => t.jti === params[0]);
      return { rows: found ? [{ '?column?': 1 }] : [], rowCount: found ? 1 : 0 };
    }

    // 14. password_reset_tokens UPDATE & INSERT
    if (sql.startsWith('UPDATE password_reset_tokens') && sql.includes('WHERE user_id = $1 AND used = FALSE')) {
      this.password_reset_tokens.forEach((t) => {
        if (t.user_id === params[0] && !t.used) t.used = true;
      });
      return { rows: [], rowCount: 1 };
    }

    if (sql.startsWith('INSERT INTO password_reset_tokens')) {
      const [user_id, token_hash] = params;
      const tokenRow = {
        id: crypto.randomUUID(),
        user_id,
        token_hash,
        expires_at: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
        used: false,
        created_at: now,
      };
      this.password_reset_tokens.push(tokenRow);
      return { rows: [tokenRow], rowCount: 1 };
    }

    if (sql.startsWith('UPDATE password_reset_tokens') && sql.includes('WHERE token_hash = $1')) {
      const [tokenHash] = params;
      const tokenRow = this.password_reset_tokens.find(
        (t) =>
          t.token_hash === tokenHash &&
          !t.used &&
          new Date(t.expires_at).getTime() > Date.now()
      );
      if (!tokenRow) return { rows: [], rowCount: 0 };
      tokenRow.used = true;
      return { rows: [{ id: tokenRow.id, user_id: tokenRow.user_id }], rowCount: 1 };
    }

    // 15. notes COUNT, INSERT, SELECT, UPDATE, DELETE (con verificación estricta owner_id)
    if (sql.includes('SELECT COUNT(*)::int AS count FROM notes WHERE owner_id = $1')) {
      const count = this.notes.filter((n) => n.owner_id === params[0]).length;
      return { rows: [{ count }], rowCount: 1 };
    }

    if (sql.startsWith('INSERT INTO notes')) {
      const [owner_id, title, content_enc] = params;
      const note = {
        id: crypto.randomUUID(),
        owner_id,
        title,
        content_enc,
        key_version: 1,
        created_at: now,
        updated_at: now,
      };
      this.notes.unshift(note);
      return { rows: [note], rowCount: 1 };
    }

    if (sql.includes('FROM notes') && sql.includes('WHERE id = $1 AND owner_id = $2')) {
      const [noteId, ownerId] = params;
      const note = this.notes.find((n) => n.id === noteId && n.owner_id === ownerId);
      return { rows: note ? [note] : [], rowCount: note ? 1 : 0 };
    }

    if (sql.includes('FROM notes') && sql.includes('WHERE owner_id = $1')) {
      const userNotes = this.notes.filter((n) => n.owner_id === params[0]);
      return { rows: userNotes, rowCount: userNotes.length };
    }

    if (sql.startsWith('UPDATE notes') && sql.includes('WHERE id = $1 AND owner_id = $2')) {
      const [noteId, ownerId, title, content_enc] = params;
      const note = this.notes.find((n) => n.id === noteId && n.owner_id === ownerId);
      if (!note) return { rows: [], rowCount: 0 };
      note.title = title;
      note.content_enc = content_enc;
      note.updated_at = now;
      return { rows: [note], rowCount: 1 };
    }

    if (sql.startsWith('DELETE FROM notes') && sql.includes('WHERE id = $1 AND owner_id = $2')) {
      const [noteId, ownerId] = params;
      const idx = this.notes.findIndex((n) => n.id === noteId && n.owner_id === ownerId);
      if (idx === -1) return { rows: [], rowCount: 0 };
      const [deleted] = this.notes.splice(idx, 1);
      return { rows: [{ id: deleted.id }], rowCount: 1 };
    }

    return { rows: [], rowCount: 0 };
  }
}

export const embeddedDb = new EmbeddedPgFallback();

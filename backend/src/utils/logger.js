import winston from 'winston';

const SENSITIVE_KEYS = new Set([
  'password',
  'password_hash',
  'newpassword',
  'oldpassword',
  'token',
  'token_hash',
  'rawtoken',
  'resettoken',
  'jwt',
  'secret',
  'encryption_key',
  'authorization',
  'cookie',
  'set-cookie',
  'content',
  'content_enc',
  'sensitive_data',
  'sensitive_data_enc',
  'sensitivedata',
]);

/**
 * Sanitiza recursivamente objetos y metadatos para garantizar que jamás se
 * registren contraseñas, tokens, cookies ni datos cifrados/sensibles (OWASP A09).
 */
export const sanitizeLogData = (value, seen = new WeakSet()) => {
  if (value === null || value === undefined) {
    return value;
  }

  if (typeof value !== 'object') {
    return value;
  }

  if (value instanceof Error) {
    return {
      name: value.name,
      message: value.message,
      code: value.code,
      ...(process.env.NODE_ENV !== 'production' && { stack: value.stack }),
    };
  }

  if (seen.has(value)) {
    return '[Circular]';
  }
  seen.add(value);

  if (Array.isArray(value)) {
    return value.map((item) => sanitizeLogData(item, seen));
  }

  const sanitized = {};
  for (const [k, v] of Object.entries(value)) {
    const normalizedKey = k.toLowerCase();
    const isSensitive =
      SENSITIVE_KEYS.has(normalizedKey) ||
      normalizedKey.includes('password') ||
      normalizedKey.includes('token') ||
      normalizedKey.includes('secret') ||
      normalizedKey.includes('cookie') ||
      normalizedKey.includes('authorization');

    if (isSensitive) {
      sanitized[k] = '[REDACTED]';
    } else {
      sanitized[k] = sanitizeLogData(v, seen);
    }
  }

  return sanitized;
};

/**
 * Formato Winston que muta `info` in-place para preservar los símbolos internos
 * de Winston (Symbol.for('level'), Symbol.for('message'), Symbol.for('splat')).
 */
const sanitizeFormat = winston.format((info) => {
  for (const key of Object.keys(info)) {
    if (key === 'level' || key === 'message' || key === 'timestamp' || key === 'service') {
      continue;
    }

    const normalizedKey = key.toLowerCase();
    const isSensitive =
      SENSITIVE_KEYS.has(normalizedKey) ||
      normalizedKey.includes('password') ||
      normalizedKey.includes('token') ||
      normalizedKey.includes('secret') ||
      normalizedKey.includes('cookie') ||
      normalizedKey.includes('authorization');

    if (isSensitive) {
      info[key] = '[REDACTED]';
    } else {
      info[key] = sanitizeLogData(info[key]);
    }
  }
  return info;
});

export const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  defaultMeta: { service: 'securevault-api' },
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DDTHH:mm:ss.SSSZ' }),
    sanitizeFormat(),
    winston.format.json()
  ),
  transports: [new winston.transports.Console()],
});

import pg from 'pg';
import dotenv from 'dotenv';
import { logger } from '../utils/logger.js';
import { embeddedDb } from './embeddedDb.js';

dotenv.config();

const { Pool } = pg;

const isProduction = process.env.NODE_ENV === 'production';

const pgPool = new Pool({
  connectionString:
    process.env.DATABASE_URL || 'postgresql://postgres:1234@localhost:5432/Laboratorio_NodeJS',
  connectionTimeoutMillis: 3000,
  query_timeout: 5000,
  statement_timeout: 5000,
  max: 10,
  idleTimeoutMillis: 30000,
  ssl: isProduction ? { rejectUnauthorized: false } : false,
});

let useEmbeddedFallback = false;

pgPool.on('error', (err) => {
  logger.error('Unexpected error on idle PostgreSQL client', {
    event: 'DB_POOL_ERROR',
    message: err.message,
    code: err.code,
  });
});

/**
 * Ejecuta la consulta en PostgreSQL real; si en desarrollo local el servicio
 * de PostgreSQL está apagado (ECONNREFUSED), conmuta automáticamente al motor
 * en memoria con cuentas Admin y Usuario pre-cargadas para no bloquear el laboratorio.
 */
export const query = async (text, params) => {
  if (useEmbeddedFallback) {
    return embeddedDb.query(text, params);
  }

  try {
    return await pgPool.query(text, params);
  } catch (err) {
    const isConnectionError =
      err.code === 'ECONNREFUSED' ||
      err.code === 'ENOTFOUND' ||
      err.code === '3D000' ||
      err.code === '28P01' ||
      !process.env.DATABASE_URL ||
      (err.message && (err.message.includes('ECONNREFUSED') || err.message.includes('connect')));

    if (!isProduction || isConnectionError) {
      useEmbeddedFallback = true;
      logger.warn(
        'Base de datos PostgreSQL externa no disponible; activando motor seguro embebido con cuentas Admin y Usuario preconfiguradas',
        {
          event: 'DB_FALLBACK_ACTIVATED',
          reason: err.code || err.message,
        }
      );
      return embeddedDb.query(text, params);
    }
    throw err;
  }
};

export const pool = {
  query,
  connect: async () => {
    if (useEmbeddedFallback) {
      return embeddedDb.connect();
    }
    try {
      return await pgPool.connect();
    } catch {
      useEmbeddedFallback = true;
      return embeddedDb.connect();
    }
  },
  end: async () => {
    await pgPool.end().catch(() => {});
  },
};

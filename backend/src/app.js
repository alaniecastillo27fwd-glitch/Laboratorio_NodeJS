import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { query } from './config/db.js';
import { logger } from './utils/logger.js';
import authRoutes from './routes/authRoutes.js';
import noteRoutes from './routes/noteRoutes.js';
import profileRoutes from './routes/profileRoutes.js';
import adminRoutes from './routes/adminRoutes.js';
import { notFoundHandler, errorHandler } from './middlewares/errorHandler.js';

const app = express();

// 1. Confiar en el primer salto del proxy inverso (Render) para cookies Secure y Rate Limiting (Sección 6)
app.set('trust proxy', 1);

// 2. Desactivar cabecera X-Powered-By para evitar fuga de tecnología (OWASP A02)
app.disable('x-powered-by');

// 3. Cabeceras de seguridad HTTP con Helmet: CSP estricta (sin unsafe-inline) y HSTS (OWASP A02 / A05)
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'", process.env.FRONTEND_URL].filter(Boolean),
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null,
      },
    },
    strictTransportSecurity: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
    frameguard: { action: 'deny' },
    referrerPolicy: { policy: 'no-referrer' },
    noSniff: true,
  })
);

// 4. Configuración estricta de CORS restringida al dominio del Frontend (OWASP A02)
const allowedOrigins = new Set(
  [
    process.env.FRONTEND_URL,
    process.env.NODE_ENV !== 'production' && 'http://localhost:5173',
    process.env.NODE_ENV !== 'production' && 'http://127.0.0.1:5173',
    process.env.NODE_ENV !== 'production' && 'http://localhost:5174',
    process.env.NODE_ENV !== 'production' && 'http://127.0.0.1:5174',
  ].filter(Boolean)
);

app.use(
  cors({
    origin: (origin, callback) => {
      if (
        !origin ||
        allowedOrigins.has(origin) ||
        /^https:\/\/[a-z0-9-]+\.vercel\.app$/i.test(origin) ||
        (process.env.NODE_ENV !== 'production' && /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin))
      ) {
        return callback(null, true);
      }
      logger.warn('Intento de acceso CORS desde origen no autorizado', {
        event: 'CORS_BLOCKED',
        origin,
      });
      const corsError = new Error('Origen no permitido por política CORS');
      corsError.statusCode = 403;
      corsError.expose = true;
      return callback(corsError);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
  })
);

// 5. Límite estricto de tamaño de payload JSON (10kb) y parser de cookies (OWASP A06)
app.use(express.json({ limit: '10kb', strict: true }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(cookieParser());

// 6. Endpoint de salud (RF-08): Verifica conexión a BD sin revelar versiones ni datos internos
const healthCheckHandler = async (_req, res) => {
  try {
    await query('SELECT 1');
    return res.status(200).json({ status: 'ok' });
  } catch (err) {
    logger.error('Fallo en verificación de salud de base de datos', {
      event: 'HEALTHCHECK_FAILED',
      code: err.code,
      message: err.message,
    });
    return res.status(503).json({ status: 'error' });
  }
};

app.get('/health', healthCheckHandler);
app.get('/api/health', healthCheckHandler);

// 7. Rutas de la API REST (RF-01 a RF-07)
app.use('/api/auth', authRoutes);
app.use('/api/notes', noteRoutes);
app.use('/api/profile', profileRoutes);
app.use('/api/admin', adminRoutes);

// 8. Manejadores de rutas inexistentes y errores globales (OWASP A10 - Fail-Closed)
app.use(notFoundHandler);
app.use(errorHandler);

export default app;

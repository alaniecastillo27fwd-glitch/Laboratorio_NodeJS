import dotenv from 'dotenv';
import app from './src/app.js';
import { pool } from './src/config/db.js';
import { logger } from './src/utils/logger.js';

dotenv.config();

const PORT = Number(process.env.PORT) || 3000;

const server = app.listen(PORT, () => {
  logger.info(`Servidor SecureVault escuchando en http://localhost:${PORT}`, {
    event: 'SERVER_STARTED',
    port: PORT,
    environment: process.env.NODE_ENV || 'development',
  });
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    logger.error(
      `El puerto ${PORT} ya está en uso por otra instancia de SecureVault (http://localhost:${PORT} ya está activo).`,
      {
        event: 'PORT_ALREADY_IN_USE',
        port: PORT,
      }
    );
    process.exit(1);
  }

  logger.error('Error al iniciar el servidor HTTP', {
    event: 'SERVER_LISTEN_ERROR',
    errorName: err.name,
    errorMessage: err.message,
  });
  process.exit(1);
});

const gracefulShutdown = (signal, exitCode = 0) => {
  logger.info(`Señal ${signal} recibida. Cerrando servidor de forma segura...`, {
    event: 'SERVER_SHUTDOWN',
    signal,
  });

  if (!server.listening) {
    process.exit(exitCode);
    return;
  }

  server.close(async () => {
    try {
      await pool.end();
      logger.info('Pool de conexiones PostgreSQL cerrado correctamente', {
        event: 'DB_POOL_CLOSED',
      });
    } catch (err) {
      logger.error('Error al cerrar el pool de PostgreSQL', {
        event: 'DB_POOL_CLOSE_ERROR',
        message: err.message,
      });
    } finally {
      process.exit(exitCode);
    }
  });

  setTimeout(() => {
    logger.error('Tiempo de espera agotado para cierre limpio; forzando salida', {
      event: 'FORCED_SHUTDOWN',
    });
    process.exit(1);
  }, 10000).unref();
};

// Manejo seguro de condiciones excepcionales a nivel de proceso (OWASP A10)
process.on('unhandledRejection', (reason) => {
  logger.error('Promesa rechazada no controlada (unhandledRejection)', {
    event: 'UNHANDLED_REJECTION',
    reason: reason instanceof Error ? reason.message : String(reason),
  });
  gracefulShutdown('unhandledRejection', 1);
});

process.on('uncaughtException', (err) => {
  logger.error('Excepción crítica no capturada (uncaughtException)', {
    event: 'UNCAUGHT_EXCEPTION',
    errorName: err.name,
    errorMessage: err.message,
  });
  gracefulShutdown('uncaughtException', 1);
});

process.on('SIGTERM', () => gracefulShutdown('SIGTERM', 0));
process.on('SIGINT', () => gracefulShutdown('SIGINT', 0));

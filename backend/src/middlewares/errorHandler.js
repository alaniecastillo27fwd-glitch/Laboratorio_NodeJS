import { logger } from '../utils/logger.js';

/**
 * Manejador global de rutas no encontradas (404).
 */
export const notFoundHandler = (req, res, _next) => {
  res.status(404).json({
    error: 'Recurso no encontrado',
  });
};

/**
 * Manejador global de errores (OWASP A02 / A10 - Fail-Closed).
 * Registra el detalle técnico internamente en formato JSON estructurado y
 * devuelve al cliente únicamente una respuesta genérica sin stack traces.
 */
export const errorHandler = (err, req, res, _next) => {
  if (err?.type === 'entity.too.large') {
    logger.warn('Payload JSON excede el límite permitido (10kb)', {
      event: 'PAYLOAD_TOO_LARGE',
      path: req.originalUrl,
      method: req.method,
      ip: req.ip,
    });
    return res.status(413).json({
      error: 'El tamaño de la solicitud excede el límite permitido',
    });
  }

  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    logger.warn('JSON malformado en la solicitud', {
      event: 'MALFORMED_JSON',
      path: req.originalUrl,
      method: req.method,
      ip: req.ip,
    });
    return res.status(400).json({
      error: 'Formato JSON inválido',
    });
  }

  const statusCode =
    Number.isInteger(err.statusCode) && err.statusCode >= 400 && err.statusCode < 600
      ? err.statusCode
      : 500;

  logger.error('Excepción capturada en manejador global', {
    event: 'UNHANDLED_ROUTE_ERROR',
    statusCode,
    path: req.originalUrl,
    method: req.method,
    ip: req.ip,
    userId: req.user?.sub || null,
    errorName: err.name,
    errorMessage: err.message,
    errorCode: err.code,
    ...(process.env.NODE_ENV !== 'production' && { stack: err.stack }),
  });

  const isClientError = statusCode >= 400 && statusCode < 500 && err.expose === true;

  return res.status(statusCode).json({
    error: isClientError ? err.message : 'Error interno del servidor',
  });
};

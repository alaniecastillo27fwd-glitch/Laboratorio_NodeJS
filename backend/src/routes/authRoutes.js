import { Router } from 'express';
import {
  register,
  login,
  logout,
  forgotPassword,
  resetPassword,
} from '../controllers/authController.js';
import { requireAuth } from '../middlewares/authMiddleware.js';
import { loginRateLimiter, authActionRateLimiter } from '../middlewares/rateLimiter.js';

const router = Router();

// RF-01: Registro de usuario (fuerza role = 'user' en servidor)
router.post('/register', authActionRateLimiter, register);

// RF-02: Inicio y cierre de sesión con Rate Limit (HTTP 429) y revocación de JTI
router.post('/login', loginRateLimiter, login);
router.post('/logout', requireAuth, logout);

// RF-06: Recuperación de contraseña con token de un solo uso hasheado en SHA-256
router.post('/forgot-password', authActionRateLimiter, forgotPassword);
router.post('/reset-password', authActionRateLimiter, resetPassword);

export default router;

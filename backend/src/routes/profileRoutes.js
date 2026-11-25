import { Router } from 'express';
import { requireAuth } from '../middlewares/authMiddleware.js';
import { getProfile, updateSensitiveProfileData } from '../controllers/profileController.js';

const router = Router();

router.use(requireAuth);

// RF-05: Consulta y actualización del dato sensible cifrado con AES-256-GCM
router.get('/', getProfile);
router.put('/sensitive', updateSensitiveProfileData);

export default router;

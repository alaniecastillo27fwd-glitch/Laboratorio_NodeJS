import { Router } from 'express';
import { requireAuth, requireRole } from '../middlewares/authMiddleware.js';
import { listUsers, changeUserRole, listAuditLogs } from '../controllers/adminController.js';

const router = Router();

// RF-03 y RF-07: Todas las rutas administrativas verifican autenticación y rol 'admin' en el servidor
router.use(requireAuth, requireRole('admin'));

router.get('/users', listUsers);
router.patch('/users/:id/role', changeUserRole);
router.get('/audit-logs', listAuditLogs);

export default router;

import { Router } from 'express';
import { requireAuth } from '../middlewares/authMiddleware.js';
import {
  listNotes,
  getNoteById,
  createNewNote,
  updateNote,
  deleteNote,
} from '../controllers/noteController.js';

const router = Router();

// Todas las rutas de notas exigen sesión autenticada válida (RF-04 / OWASP A01)
router.use(requireAuth);

router.get('/', listNotes);
router.post('/', createNewNote);
router.get('/:id', getNoteById);
router.put('/:id', updateNote);
router.delete('/:id', deleteNote);

export default router;

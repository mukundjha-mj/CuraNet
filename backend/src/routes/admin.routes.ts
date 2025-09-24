import express from 'express';
import { authenticateToken, requireAdmin } from '../middlewares/authMiddleware';
import admin, { bootstrapAdmin } from '../controllers/admin.controller';

const router = express.Router();

// List pending providers (admin only)
router.post('/providers/pending', authenticateToken, requireAdmin, admin.listPendingProviders);

// Approve a provider (admin only)
router.post('/providers/approve/:id', authenticateToken, requireAdmin, admin.approveProvider);

export default router;

// Dev-only admin bootstrap (no auth, token-protected)
router.post('/bootstrap', bootstrapAdmin);

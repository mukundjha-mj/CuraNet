import express from 'express';
import authController from '../controllers/auth.controller';
import type { Request, Response } from 'express';
import { 
    authenticateToken, 
    rateLimitByIP 
} from '../middlewares/authMiddleware';

const router = express.Router();

// Local type to include user added by authenticateToken middleware
type AuthedRequest = Request & { user?: { id: string } };

// Rate limiting for auth endpoints
const authRateLimit = rateLimitByIP(10, 15 * 60 * 1000); // 10 requests per 15 minutes
const strictRateLimit = rateLimitByIP(5, 60 * 1000); // 5 requests per minute

// Public routes (with rate limiting)
router.post('/register', authRateLimit, authController.register);
router.post('/verify-email', authRateLimit, authController.verifyEmail);
router.post('/login', authRateLimit, authController.login);
router.post('/request-password-reset', strictRateLimit, authController.requestPasswordReset);
router.post('/reset-password', authRateLimit, authController.resetPassword);

// Protected routes (require authentication)
router.post('/refresh', authController.refresh);
router.post('/logout', authenticateToken, authController.logout);
router.post('/profile', authenticateToken, authController.profile);

// Health check
router.post('/health', authController.health);

// Additional utility routes for token management
router.post('/revoke-all-sessions', authenticateToken, async (req: AuthedRequest, res: Response) => {
    try {
        const userId = req.user?.id;
        if (!userId) {
            return res.status(401).json({ message: 'User not authenticated' });
        }

        const { PrismaClient } = require('@prisma/client');
        const prisma = new PrismaClient();

        // Revoke all refresh tokens for the user
        await prisma.refreshToken.updateMany({
            where: { userId },
            data: { revokedAt: new Date() }
        });

        res.clearCookie('refreshToken');
        res.json({ message: 'All sessions revoked successfully' });
    } catch (error) {
        console.error('Revoke all sessions error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Get active sessions
router.post('/sessions', authenticateToken, async (req: AuthedRequest, res: Response) => {
    try {
        const userId = req.user?.id;
        if (!userId) {
            return res.status(401).json({ message: 'User not authenticated' });
        }

        const { PrismaClient } = require('@prisma/client');
        const prisma = new PrismaClient();

        const sessions = await prisma.refreshToken.findMany({
            where: {
                userId,
                revokedAt: null,
                expiresAt: {
                    gt: new Date()
                }
            },
            select: {
                id: true,
                deviceFingerprint: true,
                issuedAt: true,
                lastUsedAt: true,
                expiresAt: true
            },
            orderBy: {
                lastUsedAt: 'desc'
            }
        });

        res.json({ sessions });
    } catch (error) {
        console.error('Get sessions error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Revoke specific session
router.post('/sessions/:sessionId', authenticateToken, async (req: AuthedRequest, res: Response) => {
    try {
        const userId = req.user?.id;
        const { sessionId } = req.params;

        if (!userId) {
            return res.status(401).json({ message: 'User not authenticated' });
        }

        const { PrismaClient } = require('@prisma/client');
        const prisma = new PrismaClient();

        const result = await prisma.refreshToken.updateMany({
            where: {
                id: sessionId,
                userId,
                revokedAt: null
            },
            data: { revokedAt: new Date() }
        });

        if (result.count === 0) {
            return res.status(404).json({ message: 'Session not found or already revoked' });
        }

        res.json({ message: 'Session revoked successfully' });
    } catch (error) {
        console.error('Revoke session error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

export default router;
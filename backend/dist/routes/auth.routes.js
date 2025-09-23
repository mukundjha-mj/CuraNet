"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const auth_controller_1 = __importDefault(require("../controllers/auth.controller"));
const authMiddleware_1 = require("../middlewares/authMiddleware");
const router = express_1.default.Router();
// Rate limiting for auth endpoints
const authRateLimit = (0, authMiddleware_1.rateLimitByIP)(10, 15 * 60 * 1000); // 10 requests per 15 minutes
const strictRateLimit = (0, authMiddleware_1.rateLimitByIP)(5, 60 * 1000); // 5 requests per minute
// Public routes (with rate limiting)
router.post('/register', authRateLimit, auth_controller_1.default.register);
router.post('/verify-email', authRateLimit, auth_controller_1.default.verifyEmail);
router.post('/login', authRateLimit, auth_controller_1.default.login);
router.post('/request-password-reset', strictRateLimit, auth_controller_1.default.requestPasswordReset);
router.post('/reset-password', authRateLimit, auth_controller_1.default.resetPassword);
// Protected routes (require authentication)
router.post('/refresh', auth_controller_1.default.refresh);
router.post('/logout', authMiddleware_1.authenticateToken, auth_controller_1.default.logout);
router.post('/profile', authMiddleware_1.authenticateToken, auth_controller_1.default.profile);
// Health check
router.post('/health', auth_controller_1.default.health);
// Additional utility routes for token management
router.post('/revoke-all-sessions', authMiddleware_1.authenticateToken, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const userId = (_a = req.user) === null || _a === void 0 ? void 0 : _a.id;
        if (!userId) {
            return res.status(401).json({ message: 'User not authenticated' });
        }
        const { PrismaClient } = require('@prisma/client');
        const prisma = new PrismaClient();
        // Revoke all refresh tokens for the user
        yield prisma.refreshToken.updateMany({
            where: { userId },
            data: { revokedAt: new Date() }
        });
        res.clearCookie('refreshToken');
        res.json({ message: 'All sessions revoked successfully' });
    }
    catch (error) {
        console.error('Revoke all sessions error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
}));
// Get active sessions
router.post('/sessions', authMiddleware_1.authenticateToken, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const userId = (_a = req.user) === null || _a === void 0 ? void 0 : _a.id;
        if (!userId) {
            return res.status(401).json({ message: 'User not authenticated' });
        }
        const { PrismaClient } = require('@prisma/client');
        const prisma = new PrismaClient();
        const sessions = yield prisma.refreshToken.findMany({
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
    }
    catch (error) {
        console.error('Get sessions error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
}));
// Revoke specific session
router.post('/sessions/:sessionId', authMiddleware_1.authenticateToken, (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const userId = (_a = req.user) === null || _a === void 0 ? void 0 : _a.id;
        const { sessionId } = req.params;
        if (!userId) {
            return res.status(401).json({ message: 'User not authenticated' });
        }
        const { PrismaClient } = require('@prisma/client');
        const prisma = new PrismaClient();
        const result = yield prisma.refreshToken.updateMany({
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
    }
    catch (error) {
        console.error('Revoke session error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
}));
exports.default = router;

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
exports.isAccountLocked = exports.clearFailedAttempts = exports.trackFailedLogin = exports.rateLimitByIP = exports.cleanupTokenBlacklist = exports.blacklistToken = exports.requireHealthProvider = exports.requireAdmin = exports.requirePharmacy = exports.requireDoctor = exports.requirePatient = exports.requireRole = exports.optionalAuth = exports.authenticateToken = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const client_1 = require("@prisma/client");
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
const prisma = new client_1.PrismaClient();
const getJwtSecret = () => {
    const secret = process.env.JWT_SECRET;
    if (!secret) {
        throw new Error('JWT_SECRET is not set in environment variables');
    }
    return secret;
};
// Token blacklist for logout (in production, use Redis for better performance)
const tokenBlacklist = new Set();
const authenticateToken = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const authHeader = req.headers.authorization;
        const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
        if (!token) {
            res.status(401).json({ message: 'Access token required' });
            return;
        }
        // Check if token is blacklisted
        if (tokenBlacklist.has(token)) {
            res.status(401).json({ message: 'Token has been revoked' });
            return;
        }
        // Verify JWT
        const decoded = jsonwebtoken_1.default.verify(token, getJwtSecret());
        // Additional validation - check if user still exists and is active
        const user = yield prisma.user.findUnique({
            where: { id: decoded.sub },
            select: {
                id: true,
                email: true,
                role: true,
                status: true
            }
        });
        if (!user) {
            res.status(401).json({ message: 'User not found' });
            return;
        }
        if (user.status !== 'active') {
            res.status(401).json({ message: 'Account not active' });
            return;
        }
        // Attach user info to request
        req.user = {
            id: user.id,
            email: user.email,
            role: user.role,
            status: user.status,
            tokenId: decoded.jti
        };
        next();
    }
    catch (error) {
        if (error.name === 'JsonWebTokenError') {
            res.status(401).json({ message: 'Invalid token' });
        }
        else if (error.name === 'TokenExpiredError') {
            res.status(401).json({ message: 'Token expired' });
        }
        else {
            console.error('Auth middleware error:', error);
            res.status(500).json({ message: 'Internal server error' });
        }
    }
});
exports.authenticateToken = authenticateToken;
// Optional token (for endpoints that work with or without auth)
const optionalAuth = (req, res, next) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const authHeader = req.headers.authorization;
        const token = authHeader && authHeader.split(' ')[1];
        if (!token) {
            next();
            return;
        }
        // Same logic as authenticateToken but don't fail if no token
        if (tokenBlacklist.has(token)) {
            next();
            return;
        }
        const decoded = jsonwebtoken_1.default.verify(token, getJwtSecret());
        const user = yield prisma.user.findUnique({
            where: { id: decoded.sub },
            select: {
                id: true,
                email: true,
                role: true,
                status: true
            }
        });
        if (user && user.status === 'active') {
            req.user = {
                id: user.id,
                email: user.email,
                role: user.role,
                status: user.status,
                tokenId: decoded.jti
            };
        }
        next();
    }
    catch (error) {
        // For optional auth, continue even if token validation fails
        next();
    }
});
exports.optionalAuth = optionalAuth;
// Role-based authorization middleware
const requireRole = (...roles) => {
    return (req, res, next) => {
        if (!req.user) {
            res.status(401).json({ message: 'Authentication required' });
            return;
        }
        if (!roles.includes(req.user.role)) {
            res.status(403).json({ message: 'Insufficient permissions' });
            return;
        }
        next();
    };
};
exports.requireRole = requireRole;
// Specific role middlewares for common cases
exports.requirePatient = (0, exports.requireRole)('patient');
exports.requireDoctor = (0, exports.requireRole)('doctor');
exports.requirePharmacy = (0, exports.requireRole)('pharmacy');
exports.requireAdmin = (0, exports.requireRole)('admin');
exports.requireHealthProvider = (0, exports.requireRole)('doctor', 'pharmacy');
// Add token to blacklist (for logout)
const blacklistToken = (token) => {
    tokenBlacklist.add(token);
};
exports.blacklistToken = blacklistToken;
// Clean up expired tokens from blacklist (call periodically)
const cleanupTokenBlacklist = () => {
    // In production, implement proper cleanup logic
    // For now, just clear the set periodically
    tokenBlacklist.clear();
};
exports.cleanupTokenBlacklist = cleanupTokenBlacklist;
// Rate limiting middleware (basic implementation)
const requestCounts = new Map();
const rateLimitByIP = (maxRequests, windowMs) => {
    return (req, res, next) => {
        const ip = req.ip || req.connection.remoteAddress || 'unknown';
        const now = Date.now();
        const windowStart = now - windowMs;
        let requestData = requestCounts.get(ip);
        if (!requestData || requestData.resetTime <= windowStart) {
            requestData = { count: 1, resetTime: now + windowMs };
            requestCounts.set(ip, requestData);
            next();
            return;
        }
        if (requestData.count >= maxRequests) {
            res.status(429).json({
                message: 'Too many requests',
                retryAfter: Math.ceil((requestData.resetTime - now) / 1000)
            });
            return;
        }
        requestData.count++;
        next();
    };
};
exports.rateLimitByIP = rateLimitByIP;
// Account lockout tracking (basic implementation)
const failedAttempts = new Map();
const trackFailedLogin = (email) => {
    const maxAttempts = 5;
    const lockoutDuration = 15 * 60 * 1000; // 15 minutes
    const now = Date.now();
    let attempts = failedAttempts.get(email);
    if (!attempts) {
        attempts = { count: 1, lockUntil: 0 };
        failedAttempts.set(email, attempts);
        return false; // Not locked
    }
    if (attempts.lockUntil > now) {
        return true; // Still locked
    }
    attempts.count++;
    if (attempts.count >= maxAttempts) {
        attempts.lockUntil = now + lockoutDuration;
        return true; // Now locked
    }
    return false; // Not locked yet
};
exports.trackFailedLogin = trackFailedLogin;
const clearFailedAttempts = (email) => {
    failedAttempts.delete(email);
};
exports.clearFailedAttempts = clearFailedAttempts;
const isAccountLocked = (email) => {
    const attempts = failedAttempts.get(email);
    if (!attempts)
        return false;
    return attempts.lockUntil > Date.now();
};
exports.isAccountLocked = isAccountLocked;
exports.default = {
    authenticateToken: exports.authenticateToken,
    optionalAuth: exports.optionalAuth,
    requireRole: exports.requireRole,
    requirePatient: exports.requirePatient,
    requireDoctor: exports.requireDoctor,
    requirePharmacy: exports.requirePharmacy,
    requireAdmin: exports.requireAdmin,
    requireHealthProvider: exports.requireHealthProvider,
    blacklistToken: exports.blacklistToken,
    cleanupTokenBlacklist: exports.cleanupTokenBlacklist,
    rateLimitByIP: exports.rateLimitByIP,
    trackFailedLogin: exports.trackFailedLogin,
    clearFailedAttempts: exports.clearFailedAttempts,
    isAccountLocked: exports.isAccountLocked
};

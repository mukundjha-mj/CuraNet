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
var __rest = (this && this.__rest) || function (s, e) {
    var t = {};
    for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p) && e.indexOf(p) < 0)
        t[p] = s[p];
    if (s != null && typeof Object.getOwnPropertySymbols === "function")
        for (var i = 0, p = Object.getOwnPropertySymbols(s); i < p.length; i++) {
            if (e.indexOf(p[i]) < 0 && Object.prototype.propertyIsEnumerable.call(s, p[i]))
                t[p[i]] = s[p[i]];
        }
    return t;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.health = exports.profile = exports.resetPassword = exports.requestPasswordReset = exports.logout = exports.refresh = exports.login = exports.verifyEmail = exports.register = void 0;
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const argon2_1 = __importDefault(require("argon2"));
const crypto_1 = __importDefault(require("crypto"));
const dotenv_1 = __importDefault(require("dotenv"));
const events_1 = require("events");
const client_1 = require("@prisma/client");
dotenv_1.default.config();
const prisma = new client_1.PrismaClient();
const authEventEmitter = new events_1.EventEmitter();
const getJwtSecret = () => {
    const secret = process.env.JWT_SECRET;
    if (!secret) {
        throw new Error('JWT_SECRET is not set in environment variables');
    }
    return secret;
};
const getJwtRefreshSecret = () => {
    const secret = process.env.JWT_REFRESH_SECRET;
    if (!secret) {
        throw new Error('JWT_REFRESH_SECRET is not set in environment variables');
    }
    return secret;
};
const getPepper = () => {
    const pepper = process.env.PASSWORD_PEPPER;
    if (!pepper) {
        throw new Error('PASSWORD_PEPPER is not set in environment variables');
    }
    return pepper;
};
// Generate secure random token
const generateSecureToken = () => {
    return crypto_1.default.randomBytes(32).toString('hex');
};
// Hash token for storage
const hashToken = (token) => {
    return crypto_1.default.createHash('sha256').update(token).digest('hex');
};
// Add pepper to password before hashing
const addPepper = (password) => {
    return password + getPepper();
};
const register = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { email, phone, password, role, name } = req.body;
        // Validate input
        if (!email || !password || !role) {
            res.status(400).json({ message: 'Email, password and role are required' });
            return;
        }
        // Normalize email
        const normalizedEmail = email.toLowerCase().trim();
        // Check for existing user
        const existingUser = yield prisma.user.findFirst({
            where: {
                OR: [
                    { email: normalizedEmail },
                    ...(phone ? [{ phone }] : [])
                ]
            }
        });
        if (existingUser) {
            res.status(400).json({ message: 'User with this email or phone already exists' });
            return;
        }
        // Enforce password policy (basic example)
        if (password.length < 8) {
            res.status(400).json({ message: 'Password must be at least 8 characters long' });
            return;
        }
        // Hash password with pepper and Argon2
        const pepperedPassword = addPepper(password);
        const passwordHash = yield argon2_1.default.hash(pepperedPassword, {
            type: argon2_1.default.argon2id,
            memoryCost: 2 ** 16, // 64 MB
            timeCost: 3,
            parallelism: 1,
        });
        // Generate verification token
        const verificationToken = generateSecureToken();
        const tokenHash = hashToken(verificationToken);
        const tokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
        // Create user with pending verification status
        const newUser = yield prisma.user.create({
            data: {
                email: normalizedEmail,
                phone,
                role,
                passwordHash,
                status: role === 'patient' ? 'pending_verification' : 'pending_approval',
                emailVerifications: {
                    create: {
                        tokenHash,
                        expiresAt: tokenExpiry
                    }
                }
            },
            select: {
                id: true,
                email: true,
                phone: true,
                role: true,
                status: true,
                createdAt: true
            }
        });
        // Emit UserCreated event for user-service to create profile
        authEventEmitter.emit('user-created', {
            userId: newUser.id,
            email: normalizedEmail,
            role,
            name
        });
        // Emit email verification event for notification service
        authEventEmitter.emit('send-verification-email', {
            email: normalizedEmail,
            token: verificationToken,
            userId: newUser.id
        });
        res.status(201).json({
            message: 'User registered successfully. Please check your email for verification.',
            user: newUser
        });
    }
    catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.register = register;
const verifyEmail = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { token } = req.body;
        if (!token) {
            res.status(400).json({ message: 'Verification token is required' });
            return;
        }
        const tokenHash = hashToken(token);
        // Find and validate verification token
        const verification = yield prisma.emailVerification.findFirst({
            where: {
                tokenHash,
                expiresAt: {
                    gt: new Date()
                },
                usedAt: null
            },
            include: {
                user: true
            }
        });
        if (!verification) {
            res.status(400).json({ message: 'Invalid or expired verification token' });
            return;
        }
        // Update user status and mark token as used
        yield prisma.$transaction((tx) => __awaiter(void 0, void 0, void 0, function* () {
            yield tx.user.update({
                where: { id: verification.userId },
                data: {
                    status: verification.user.role === 'patient' ? 'active' : 'pending_approval'
                }
            });
            yield tx.emailVerification.update({
                where: { id: verification.id },
                data: { usedAt: new Date() }
            });
        }));
        res.json({ message: 'Email verified successfully' });
    }
    catch (error) {
        console.error('Email verification error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.verifyEmail = verifyEmail;
const login = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { email, password, deviceFingerprint } = req.body;
        if (!email || !password) {
            res.status(400).json({ message: 'Email and password are required' });
            return;
        }
        const normalizedEmail = email.toLowerCase().trim();
        // Find user
        const user = yield prisma.user.findUnique({
            where: { email: normalizedEmail }
        });
        if (!user) {
            res.status(401).json({ message: 'Invalid email or password' });
            return;
        }
        // Check account status
        if (user.status !== 'active') {
            let message = 'Account not activated';
            if (user.status === 'pending_verification') {
                message = 'Please verify your email first';
            }
            else if (user.status === 'pending_approval') {
                message = 'Account pending approval';
            }
            else if (user.status === 'suspended') {
                message = 'Account suspended';
            }
            res.status(401).json({ message });
            return;
        }
        // Verify password
        const pepperedPassword = addPepper(password);
        const isValidPassword = yield argon2_1.default.verify(user.passwordHash, pepperedPassword);
        if (!isValidPassword) {
            res.status(401).json({ message: 'Invalid email or password' });
            return;
        }
        // Generate tokens
        const accessTokenPayload = {
            sub: user.id,
            email: user.email,
            role: user.role,
            status: user.status,
            jti: crypto_1.default.randomUUID()
        };
        const accessToken = jsonwebtoken_1.default.sign(accessTokenPayload, getJwtSecret(), {
            expiresIn: '15m',
            algorithm: 'HS256'
        });
        const refreshToken = generateSecureToken();
        const refreshTokenHash = hashToken(refreshToken);
        const deviceFingerprintToStore = deviceFingerprint || 'unknown';
        // Store refresh token
        yield prisma.refreshToken.create({
            data: {
                userId: user.id,
                tokenHash: refreshTokenHash,
                deviceFingerprint: deviceFingerprintToStore,
                expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
                lastUsedAt: new Date()
            }
        });
        // Set refresh token as HTTP-only cookie
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });
        // Emit login event for audit service
        authEventEmitter.emit('user-login', {
            userId: user.id,
            email: user.email,
            role: user.role,
            deviceFingerprint: deviceFingerprintToStore,
            timestamp: new Date(),
            ip: req.ip,
            userAgent: req.get('User-Agent')
        });
        const { passwordHash: _omit } = user, userResponse = __rest(user, ["passwordHash"]);
        res.json({
            message: 'Login successful',
            accessToken,
            user: userResponse
        });
    }
    catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.login = login;
const refresh = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const refreshToken = (_a = req.cookies) === null || _a === void 0 ? void 0 : _a.refreshToken;
        if (!refreshToken) {
            res.status(401).json({ message: 'Refresh token not provided' });
            return;
        }
        const tokenHash = hashToken(refreshToken);
        // Find valid refresh token
        const storedToken = yield prisma.refreshToken.findFirst({
            where: {
                tokenHash,
                expiresAt: {
                    gt: new Date()
                },
                revokedAt: null
            },
            include: {
                user: true
            }
        });
        if (!storedToken) {
            // Possible token reuse - revoke all tokens for security
            res.status(401).json({ message: 'Invalid refresh token' });
            return;
        }
        // Generate new tokens
        const newRefreshToken = generateSecureToken();
        const newRefreshTokenHash = hashToken(newRefreshToken);
        const accessTokenPayload = {
            sub: storedToken.user.id,
            email: storedToken.user.email,
            role: storedToken.user.role,
            status: storedToken.user.status,
            jti: crypto_1.default.randomUUID()
        };
        const accessToken = jsonwebtoken_1.default.sign(accessTokenPayload, getJwtSecret(), {
            expiresIn: '15m',
            algorithm: 'HS256'
        });
        // Rotate refresh token
        yield prisma.$transaction((tx) => __awaiter(void 0, void 0, void 0, function* () {
            // Revoke old token
            yield tx.refreshToken.update({
                where: { id: storedToken.id },
                data: { revokedAt: new Date() }
            });
            // Create new token
            yield tx.refreshToken.create({
                data: {
                    userId: storedToken.userId,
                    tokenHash: newRefreshTokenHash,
                    deviceFingerprint: storedToken.deviceFingerprint,
                    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
                    lastUsedAt: new Date()
                }
            });
        }));
        // Set new refresh token cookie
        res.cookie('refreshToken', newRefreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });
        res.json({ accessToken });
    }
    catch (error) {
        console.error('Refresh token error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.refresh = refresh;
const logout = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    var _a;
    try {
        const refreshToken = (_a = req.cookies) === null || _a === void 0 ? void 0 : _a.refreshToken;
        if (refreshToken) {
            const tokenHash = hashToken(refreshToken);
            // Revoke refresh token
            yield prisma.refreshToken.updateMany({
                where: { tokenHash },
                data: { revokedAt: new Date() }
            });
        }
        // Clear cookies
        res.clearCookie('refreshToken');
        // Emit logout event for audit
        if (req.user) {
            authEventEmitter.emit('user-logout', {
                userId: req.user.id,
                timestamp: new Date(),
                ip: req.ip
            });
        }
        res.json({ message: 'Logged out successfully' });
    }
    catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.logout = logout;
const requestPasswordReset = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { email } = req.body;
        if (!email) {
            res.status(400).json({ message: 'Email is required' });
            return;
        }
        const normalizedEmail = email.toLowerCase().trim();
        const user = yield prisma.user.findUnique({
            where: { email: normalizedEmail }
        });
        // Don't reveal if user exists or not for security
        if (user && user.status === 'active') {
            const resetToken = generateSecureToken();
            const tokenHash = hashToken(resetToken);
            const tokenExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
            yield prisma.passwordResetToken.create({
                data: {
                    userId: user.id,
                    tokenHash,
                    expiresAt: tokenExpiry
                }
            });
            // Emit password reset email event
            authEventEmitter.emit('send-password-reset-email', {
                email: normalizedEmail,
                token: resetToken,
                userId: user.id
            });
        }
        res.json({ message: 'If the email exists, a password reset link has been sent' });
    }
    catch (error) {
        console.error('Password reset request error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.requestPasswordReset = requestPasswordReset;
const resetPassword = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        const { token, newPassword } = req.body;
        if (!token || !newPassword) {
            res.status(400).json({ message: 'Token and new password are required' });
            return;
        }
        if (newPassword.length < 8) {
            res.status(400).json({ message: 'Password must be at least 8 characters long' });
            return;
        }
        const tokenHash = hashToken(token);
        // Find valid reset token
        const resetToken = yield prisma.passwordResetToken.findFirst({
            where: {
                tokenHash,
                expiresAt: {
                    gt: new Date()
                },
                usedAt: null
            }
        });
        if (!resetToken) {
            res.status(400).json({ message: 'Invalid or expired reset token' });
            return;
        }
        // Hash new password
        const pepperedPassword = addPepper(newPassword);
        const newPasswordHash = yield argon2_1.default.hash(pepperedPassword, {
            type: argon2_1.default.argon2id,
            memoryCost: 2 ** 16,
            timeCost: 3,
            parallelism: 1,
        });
        // Update password and revoke all refresh tokens
        yield prisma.$transaction((tx) => __awaiter(void 0, void 0, void 0, function* () {
            yield tx.user.update({
                where: { id: resetToken.userId },
                data: { passwordHash: newPasswordHash }
            });
            yield tx.passwordResetToken.update({
                where: { id: resetToken.id },
                data: { usedAt: new Date() }
            });
            // Revoke all refresh tokens for security
            yield tx.refreshToken.updateMany({
                where: { userId: resetToken.userId },
                data: { revokedAt: new Date() }
            });
        }));
        res.json({ message: 'Password reset successful' });
    }
    catch (error) {
        console.error('Password reset error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.resetPassword = resetPassword;
const profile = (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        if (!req.user) {
            res.status(401).json({ message: 'User not authenticated' });
            return;
        }
        const user = yield prisma.user.findUnique({
            where: { id: req.user.id },
            select: {
                id: true,
                email: true,
                phone: true,
                role: true,
                status: true,
                profileRef: true,
                createdAt: true,
                updatedAt: true
            }
        });
        if (!user) {
            res.status(404).json({ message: 'User not found' });
            return;
        }
        res.json({ user });
    }
    catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});
exports.profile = profile;
// Health check endpoint
const health = (_req, res) => __awaiter(void 0, void 0, void 0, function* () {
    try {
        yield prisma.$queryRaw `SELECT 1`;
        res.json({ status: 'healthy', service: 'auth-service' });
    }
    catch (error) {
        res.status(503).json({ status: 'unhealthy', service: 'auth-service' });
    }
});
exports.health = health;
exports.default = {
    register: exports.register,
    verifyEmail: exports.verifyEmail,
    login: exports.login,
    refresh: exports.refresh,
    logout: exports.logout,
    requestPasswordReset: exports.requestPasswordReset,
    resetPassword: exports.resetPassword,
    profile: exports.profile,
    health: exports.health
};

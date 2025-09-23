import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import argon2 from 'argon2';
import crypto from 'crypto';
import dotenv from 'dotenv';
import { EventEmitter } from 'events';
import { PrismaClient } from '@prisma/client';

dotenv.config();

const prisma = new PrismaClient();
const authEventEmitter = new EventEmitter();

// Helper types for requests with additional properties populated by middlewares
type AuthenticatedRequest = Request & { user?: any };
type CookieRequest = Request & { cookies?: Record<string, string> };

interface RegisterRequest {
    email: string;
    phone?: string;
    password: string;
    role: 'patient' | 'doctor' | 'pharmacy' | 'admin';
    name?: string;
}

interface LoginRequest {
    email: string;
    password: string;
    deviceFingerprint?: string;
}

const getJwtSecret = (): string => {
    const secret = process.env.JWT_SECRET;
    if (!secret) {
        throw new Error('JWT_SECRET is not set in environment variables');
    }
    return secret;
};

const getJwtRefreshSecret = (): string => {
    const secret = process.env.JWT_REFRESH_SECRET;
    if (!secret) {
        throw new Error('JWT_REFRESH_SECRET is not set in environment variables');
    }
    return secret;
};

const getPepper = (): string => {
    const pepper = process.env.PASSWORD_PEPPER;
    if (!pepper) {
        throw new Error('PASSWORD_PEPPER is not set in environment variables');
    }
    return pepper;
};

// Generate secure random token
const generateSecureToken = (): string => {
    return crypto.randomBytes(32).toString('hex');
};

// Hash token for storage
const hashToken = (token: string): string => {
    return crypto.createHash('sha256').update(token).digest('hex');
};

// Add pepper to password before hashing
const addPepper = (password: string): string => {
    return password + getPepper();
};

export const register = async (req: Request, res: Response): Promise<void> => {
    try {
        const { email, phone, password, role, name }: RegisterRequest = req.body;

        // Validate input
        if (!email || !password || !role) {
            res.status(400).json({ message: 'Email, password and role are required' });
            return;
        }

        // Normalize email
        const normalizedEmail = email.toLowerCase().trim();

        // Check for existing user
        const existingUser = await prisma.user.findFirst({
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
        const passwordHash = await argon2.hash(pepperedPassword, {
            type: argon2.argon2id,
            memoryCost: 2 ** 16, // 64 MB
            timeCost: 3,
            parallelism: 1,
        });

        // Generate verification token
        const verificationToken = generateSecureToken();
        const tokenHash = hashToken(verificationToken);
        const tokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

        // Create user with pending verification status
        const newUser = await prisma.user.create({
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

        // In development, log and optionally return the verification token for easy testing
        const isProduction = process.env.NODE_ENV === 'production';
        if (!isProduction) {
            console.info(`[DEV] Email verification token for ${normalizedEmail}: ${verificationToken}`);
        }

        res.status(201).json({
            message: 'User registered successfully. Please check your email for verification.',
            user: newUser,
            ...(isProduction ? {} : { devVerificationToken: verificationToken })
        });

    } catch (error: any) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

export const verifyEmail = async (req: Request, res: Response): Promise<void> => {
    try {
        const { token } = req.body;

        if (!token) {
            res.status(400).json({ message: 'Verification token is required' });
            return;
        }

        const tokenHash = hashToken(token);

        // Find and validate verification token
        const verification = await prisma.emailVerification.findFirst({
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
        await prisma.$transaction(async (tx) => {
            await tx.user.update({
                where: { id: verification.userId },
                data: {
                    status: verification.user.role === 'patient' ? 'active' : 'pending_approval'
                }
            });

            await tx.emailVerification.update({
                where: { id: verification.id },
                data: { usedAt: new Date() }
            });
        });

        res.json({ message: 'Email verified successfully' });

    } catch (error: any) {
        console.error('Email verification error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

export const login = async (req: Request, res: Response): Promise<void> => {
    try {
        const { email, password, deviceFingerprint }: LoginRequest = req.body;

        if (!email || !password) {
            res.status(400).json({ message: 'Email and password are required' });
            return;
        }

        const normalizedEmail = email.toLowerCase().trim();

        // Find user
        const user = await prisma.user.findUnique({
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
            } else if (user.status === 'pending_approval') {
                message = 'Account pending approval';
            } else if (user.status === 'suspended') {
                message = 'Account suspended';
            }
            res.status(401).json({ message });
            return;
        }

        // Verify password
        const pepperedPassword = addPepper(password);
        const isValidPassword = await argon2.verify(user.passwordHash, pepperedPassword);

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
            jti: crypto.randomUUID()
        };

        const accessToken = jwt.sign(accessTokenPayload, getJwtSecret(), {
            expiresIn: '15m',
            algorithm: 'HS256'
        });

        const refreshToken = generateSecureToken();
        const refreshTokenHash = hashToken(refreshToken);
        const deviceFingerprintToStore = deviceFingerprint || 'unknown';

        // Store refresh token
        await prisma.refreshToken.create({
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

        const { passwordHash: _omit, ...userResponse } = user;

        res.json({
            message: 'Login successful',
            accessToken,
            user: userResponse
        });

    } catch (error: any) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

export const refresh = async (req: CookieRequest, res: Response): Promise<void> => {
    try {
        const refreshToken = req.cookies?.refreshToken;

        if (!refreshToken) {
            res.status(401).json({ message: 'Refresh token not provided' });
            return;
        }

        const tokenHash = hashToken(refreshToken);

        // Find valid refresh token
        const storedToken = await prisma.refreshToken.findFirst({
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
            jti: crypto.randomUUID()
        };

        const accessToken = jwt.sign(accessTokenPayload, getJwtSecret(), {
            expiresIn: '15m',
            algorithm: 'HS256'
        });

        // Rotate refresh token
        await prisma.$transaction(async (tx) => {
            // Revoke old token
            await tx.refreshToken.update({
                where: { id: storedToken.id },
                data: { revokedAt: new Date() }
            });

            // Create new token
            await tx.refreshToken.create({
                data: {
                    userId: storedToken.userId,
                    tokenHash: newRefreshTokenHash,
                    deviceFingerprint: storedToken.deviceFingerprint,
                    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
                    lastUsedAt: new Date()
                }
            });
        });

        // Set new refresh token cookie
        res.cookie('refreshToken', newRefreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        res.json({ accessToken });

    } catch (error: any) {
        console.error('Refresh token error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

export const logout = async (req: CookieRequest & AuthenticatedRequest, res: Response): Promise<void> => {
    try {
        const refreshToken = req.cookies?.refreshToken;

        if (refreshToken) {
            const tokenHash = hashToken(refreshToken);
            
            // Revoke refresh token
            await prisma.refreshToken.updateMany({
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

    } catch (error: any) {
        console.error('Logout error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

export const requestPasswordReset = async (req: Request, res: Response): Promise<void> => {
    try {
        const { email } = req.body;

        if (!email) {
            res.status(400).json({ message: 'Email is required' });
            return;
        }

        const normalizedEmail = email.toLowerCase().trim();
        const user = await prisma.user.findUnique({
            where: { email: normalizedEmail }
        });

        // Don't reveal if user exists or not for security
        if (user && user.status === 'active') {
            const resetToken = generateSecureToken();
            const tokenHash = hashToken(resetToken);
            const tokenExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

            await prisma.passwordResetToken.create({
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

    } catch (error: any) {
        console.error('Password reset request error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

export const resetPassword = async (req: Request, res: Response): Promise<void> => {
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
        const resetToken = await prisma.passwordResetToken.findFirst({
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
        const newPasswordHash = await argon2.hash(pepperedPassword, {
            type: argon2.argon2id,
            memoryCost: 2 ** 16,
            timeCost: 3,
            parallelism: 1,
        });

        // Update password and revoke all refresh tokens
        await prisma.$transaction(async (tx) => {
            await tx.user.update({
                where: { id: resetToken.userId },
                data: { passwordHash: newPasswordHash }
            });

            await tx.passwordResetToken.update({
                where: { id: resetToken.id },
                data: { usedAt: new Date() }
            });

            // Revoke all refresh tokens for security
            await tx.refreshToken.updateMany({
                where: { userId: resetToken.userId },
                data: { revokedAt: new Date() }
            });
        });

        res.json({ message: 'Password reset successful' });

    } catch (error: any) {
        console.error('Password reset error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

export const profile = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
        if (!req.user) {
            res.status(401).json({ message: 'User not authenticated' });
            return;
        }

        const user = await prisma.user.findUnique({
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

    } catch (error: any) {
        console.error('Profile error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

// Health check endpoint
export const health = async (_req: Request, res: Response): Promise<void> => {
    try {
        await prisma.$queryRaw`SELECT 1`;
        res.json({ status: 'healthy', service: 'auth-service' });
    } catch (error) {
        res.status(503).json({ status: 'unhealthy', service: 'auth-service' });
    }
};

export default {
    register,
    verifyEmail,
    login,
    refresh,
    logout,
    requestPasswordReset,
    resetPassword,
    profile,
    health
};
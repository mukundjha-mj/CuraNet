import { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import argon2 from 'argon2';

const prisma = new PrismaClient();

type AuthedRequest = Request & { user?: { id: string; role: string } };

export const approveProvider = async (req: AuthedRequest, res: Response) => {
  try {
    const { id } = req.params as { id: string };
    if (!id) return res.status(400).json({ message: 'User id is required' });

    const user = await prisma.user.findUnique({ where: { id } });
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (user.role !== 'doctor' && user.role !== 'pharmacy') {
      return res.status(400).json({ message: 'Only providers (doctor/pharmacy) require approval' });
    }

    if (user.status === 'active') {
      return res.json({ message: 'User is already active', user: { id: user.id, status: user.status } });
    }

    const updated = await prisma.user.update({
      where: { id },
      data: { status: 'active' }
    });

    return res.json({ message: 'Provider approved', user: { id: updated.id, status: updated.status } });
  } catch (err) {
    console.error('approveProvider error', err);
    return res.status(500).json({ message: 'Internal server error' });
  }
};

export const listPendingProviders = async (_req: AuthedRequest, res: Response) => {
  try {
    const pending = await prisma.user.findMany({
      where: { status: 'pending_approval', OR: [{ role: 'doctor' }, { role: 'pharmacy' }] },
      select: { id: true, email: true, role: true, status: true, createdAt: true }
    });
    return res.json({ pending });
  } catch (err) {
    console.error('listPendingProviders error', err);
    return res.status(500).json({ message: 'Internal server error' });
  }
};

export default { approveProvider, listPendingProviders };

// DEV-ONLY bootstrap to create or promote an admin using a shared token
export const bootstrapAdmin = async (req: Request, res: Response) => {
  try {
    if (process.env.NODE_ENV === 'production') {
      return res.status(403).json({ message: 'Not allowed in production' });
    }

    const headerToken = (req.headers['x-bootstrap-token'] as string) || '';
    const bodyToken = (req.body?.token as string) || '';
    const provided = headerToken || bodyToken;
    const expected = process.env.ADMIN_BOOTSTRAP_TOKEN;
    if (!expected || !provided || provided !== expected) {
      return res.status(401).json({ message: 'Invalid bootstrap token' });
    }

    const { email, password, name, phone } = req.body as { email: string; password?: string; name?: string; phone?: string };
    if (!email) return res.status(400).json({ message: 'email is required' });
    const normalizedEmail = email.toLowerCase().trim();

    const existing = await prisma.user.findUnique({ where: { email: normalizedEmail } });

    // optional password handling
    async function hashPasswordIfProvided(pw?: string): Promise<string | undefined> {
      if (!pw) return undefined;
      const pepper = process.env.PASSWORD_PEPPER;
      if (!pepper) throw new Error('PASSWORD_PEPPER not configured');
      if (pw.length < 8) throw new Error('Password must be at least 8 characters long');
      const peppered = pw + pepper;
      return argon2.hash(peppered, { type: argon2.argon2id, memoryCost: 2 ** 16, timeCost: 3, parallelism: 1 });
    }

    if (existing) {
      const passwordHash = await hashPasswordIfProvided(password);
      const updated = await prisma.user.update({
        where: { id: existing.id },
        data: {
          role: 'admin',
          status: 'active',
          ...(passwordHash ? { passwordHash } : {}),
          ...(phone ? { phone } : {}),
          ...(name ? { profileRef: name } : {})
        },
        select: { id: true, email: true, role: true, status: true }
      });
      return res.json({ message: 'Admin promoted', user: updated });
    }

    if (!password) return res.status(400).json({ message: 'password is required to create a new admin' });
    const passwordHash = await hashPasswordIfProvided(password);
    const created = await prisma.user.create({
      data: {
        email: normalizedEmail,
        phone: phone || null,
        role: 'admin',
        status: 'active',
        passwordHash: passwordHash!,
        profileRef: name || null,
      },
      select: { id: true, email: true, role: true, status: true }
    });
    return res.status(201).json({ message: 'Admin created', user: created });
  } catch (err: any) {
    console.error('bootstrapAdmin error', err);
    return res.status(500).json({ message: err?.message || 'Internal server error' });
  }
};


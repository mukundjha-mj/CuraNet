import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();

export async function hasConsent(patientId: string, providerId: string): Promise<boolean> {
  const now = new Date();
  const prismaAny = prisma as any; // until prisma generate runs
  const consent = await prismaAny.consent?.findFirst?.({
    where: {
      patientId,
      providerId,
      status: 'active',
      OR: [{ expiresAt: null }, { expiresAt: { gt: now } }]
    }
  });
  return !!consent;
}

export default { hasConsent };

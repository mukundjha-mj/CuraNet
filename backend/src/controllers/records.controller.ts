import { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import { hasConsent } from '../services/consent.service';
import { emitAudit } from '../services/audit.service';

const prisma = new PrismaClient();
const prismaAny = prisma as any; // until prisma generate runs with new models

type AuthedRequest = Request & { user?: { id: string; role: string } };

// Encounters
export const createEncounter = async (req: AuthedRequest, res: Response) => {
  try {
    const actor = req.user!;
    const { patientId, type, reason, startTime, endTime, notes } = req.body;

    if (!patientId || !type || !startTime) {
      return res.status(400).json({ message: 'patientId, type, startTime are required' });
    }

    // Role check: only doctor can create
    if (actor.role !== 'doctor') {
      return res.status(403).json({ message: 'Only doctors can create encounters' });
    }

    // Consent check (doctor must have consent from patient)
    const consentOk = await hasConsent(patientId, actor.id);
    if (!consentOk) {
      return res.status(403).json({ message: 'Consent required for this patient' });
    }

  const enc = await prismaAny.encounter.create({
      data: {
        patientId,
        providerId: actor.id,
        type,
        reason,
        startTime: new Date(startTime),
        endTime: endTime ? new Date(endTime) : null,
        notes,
        createdById: actor.id,
        createdByRole: actor.role,
      }
    });

    await emitAudit({
      type: 'record.write',
      actorId: actor.id,
      actorRole: actor.role,
      patientId,
      resourceType: 'Encounter',
      resourceId: enc.id,
      timestamp: new Date().toISOString(),
      details: { action: 'create' }
    });

    res.status(201).json({ encounter: enc });
  } catch (err) {
    console.error('createEncounter error', err);
    res.status(500).json({ message: 'Internal server error' });
  }
};

export const getEncounter = async (req: AuthedRequest, res: Response) => {
  try {
    const actor = req.user!;
    const { id } = req.params as { id: string };
  const enc = await prismaAny.encounter.findUnique({ where: { id } });
    if (!enc) return res.status(404).json({ message: 'Encounter not found' });

    if (actor.role === 'patient') {
      if (enc.patientId !== actor.id) return res.status(403).json({ message: 'Forbidden' });
    } else {
      const consentOk = await hasConsent(enc.patientId, actor.id);
      if (!consentOk) return res.status(403).json({ message: 'Consent required' });
    }

    await emitAudit({
      type: 'record.read',
      actorId: actor.id,
      actorRole: actor.role,
      patientId: enc.patientId,
      resourceType: 'Encounter',
      resourceId: enc.id,
      timestamp: new Date().toISOString(),
    });

    res.json({ encounter: enc });
  } catch (err) {
    console.error('getEncounter error', err);
    res.status(500).json({ message: 'Internal server error' });
  }
};

export const listEncounters = async (req: AuthedRequest, res: Response) => {
  try {
    const actor = req.user!;
    const { patientId, limit = 20, cursor } = req.body as { patientId?: string; limit?: number; cursor?: string };

    // Determine patient context
    let pid = patientId;
    if (actor.role === 'patient') pid = actor.id;
    if (!pid) return res.status(400).json({ message: 'patientId is required' });

    if (actor.role !== 'patient') {
      const consentOk = await hasConsent(pid, actor.id);
      if (!consentOk) return res.status(403).json({ message: 'Consent required' });
    }

    const take = Math.min(Number(limit) || 20, 100);
  const encs = await prismaAny.encounter.findMany({
      where: { patientId: pid },
      orderBy: { startTime: 'desc' },
      take,
      ...(cursor ? { skip: 1, cursor: { id: cursor } } : {})
    });

    await emitAudit({
      type: 'record.read',
      actorId: actor.id,
      actorRole: actor.role,
      patientId: pid,
      resourceType: 'Encounter',
      timestamp: new Date().toISOString(),
      details: { listCount: encs.length }
    });

    res.json({ encounters: encs, nextCursor: encs.length === take ? encs[encs.length - 1].id : null });
  } catch (err) {
    console.error('listEncounters error', err);
    res.status(500).json({ message: 'Internal server error' });
  }
};

// Observations
export const createObservation = async (req: AuthedRequest, res: Response) => {
  try {
    const actor = req.user!;
    const { patientId, encounterId, code, value, unit } = req.body;
    if (!patientId || !code || typeof value === 'undefined') {
      return res.status(400).json({ message: 'patientId, code, value are required' });
    }
    if (actor.role !== 'doctor') {
      return res.status(403).json({ message: 'Only doctors can create observations' });
    }
    const consentOk = await hasConsent(patientId, actor.id);
    if (!consentOk) return res.status(403).json({ message: 'Consent required for this patient' });

  const obs = await prismaAny.observation.create({
      data: {
        patientId,
        providerId: actor.id,
        encounterId: encounterId || null,
        code,
        value,
        unit,
        createdById: actor.id,
        createdByRole: actor.role,
      }
    });

    await emitAudit({
      type: 'record.write',
      actorId: actor.id,
      actorRole: actor.role,
      patientId,
      resourceType: 'Observation',
      resourceId: obs.id,
      timestamp: new Date().toISOString(),
      details: { action: 'create' }
    });

    res.status(201).json({ observation: obs });
  } catch (err) {
    console.error('createObservation error', err);
    res.status(500).json({ message: 'Internal server error' });
  }
};

export const getObservation = async (req: AuthedRequest, res: Response) => {
  try {
    const actor = req.user!;
    const { id } = req.params as { id: string };
  const obs = await prismaAny.observation.findUnique({ where: { id } });
    if (!obs) return res.status(404).json({ message: 'Observation not found' });

    if (actor.role === 'patient') {
      if (obs.patientId !== actor.id) return res.status(403).json({ message: 'Forbidden' });
    } else {
      const consentOk = await hasConsent(obs.patientId, actor.id);
      if (!consentOk) return res.status(403).json({ message: 'Consent required' });
    }

    await emitAudit({
      type: 'record.read',
      actorId: actor.id,
      actorRole: actor.role,
      patientId: obs.patientId,
      resourceType: 'Observation',
      resourceId: obs.id,
      timestamp: new Date().toISOString(),
    });

    res.json({ observation: obs });
  } catch (err) {
    console.error('getObservation error', err);
    res.status(500).json({ message: 'Internal server error' });
  }
};

export const listObservations = async (req: AuthedRequest, res: Response) => {
  try {
    const actor = req.user!;
    const { patientId, limit = 20, cursor } = req.body as { patientId?: string; limit?: number; cursor?: string };

    let pid = patientId;
    if (actor.role === 'patient') pid = actor.id;
    if (!pid) return res.status(400).json({ message: 'patientId is required' });

    if (actor.role !== 'patient') {
      const consentOk = await hasConsent(pid, actor.id);
      if (!consentOk) return res.status(403).json({ message: 'Consent required' });
    }

    const take = Math.min(Number(limit) || 20, 100);
  const obss = await prismaAny.observation.findMany({
      where: { patientId: pid },
      orderBy: { recordedAt: 'desc' },
      take,
      ...(cursor ? { skip: 1, cursor: { id: cursor } } : {})
    });

    await emitAudit({
      type: 'record.read',
      actorId: actor.id,
      actorRole: actor.role,
      patientId: pid,
      resourceType: 'Observation',
      timestamp: new Date().toISOString(),
      details: { listCount: obss.length }
    });

    res.json({ observations: obss, nextCursor: obss.length === take ? obss[obss.length - 1].id : null });
  } catch (err) {
    console.error('listObservations error', err);
    res.status(500).json({ message: 'Internal server error' });
  }
};

export default {
  createEncounter,
  getEncounter,
  listEncounters,
  createObservation,
  getObservation,
  listObservations,
};

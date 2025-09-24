interface AuditEvent {
  type: 'record.read' | 'record.write';
  actorId: string;
  actorRole: string;
  patientId: string;
  resourceType: 'Encounter' | 'Observation';
  resourceId?: string;
  timestamp: string;
  details?: Record<string, any>;
}

export async function emitAudit(event: AuditEvent): Promise<void> {
  // TODO: replace with real HTTP call or message bus publish
  // e.g., await fetch(AUDIT_URL, { method: 'POST', body: JSON.stringify(event) })
  console.info('[AUDIT]', JSON.stringify(event));
}

export default { emitAudit };

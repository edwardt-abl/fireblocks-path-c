import crypto from 'node:crypto';
import type { Database } from 'better-sqlite3';

export type AuditEventType =
  | 'envelope.received'
  | 'envelope.replay_rejected'
  | 'envelope.signature_failed'
  | 'intent.created'
  | 'intent.confirmed'
  | 'intent.expired'
  | 'intent.submitted'
  | 'intent.pending_authorization'
  | 'intent.completed'
  | 'intent.rejected'
  | 'intent.cancelled'
  | 'intent.cancel_failed'
  | 'intent.unknown_state'
  | 'rate.allowed'
  | 'rate.tripped_killswitch'
  | 'rate.rejected'
  | 'killswitch.activated'
  | 'killswitch.deactivated'
  | 'sla.cancellation_attempted'
  | 'sla.cancellation_succeeded'
  | 'sla.cancellation_failed'
  | 'intent.rejected_parse';

export interface AuditEvent {
  eventType: AuditEventType;
  actor: string;
  intentId?: string;
  metadata: Record<string, unknown>;
}

export function appendAuditEvent(db: Database, event: AuditEvent): void {
  const now = Math.floor(Date.now() / 1000);
  const last = db
    .prepare(`SELECT curr_hash FROM audit ORDER BY seq DESC LIMIT 1`)
    .get() as { curr_hash: string } | undefined;
  const prevHash = last?.curr_hash ?? '0'.repeat(64);

  const payload = JSON.stringify({
    eventType: event.eventType,
    actor: event.actor,
    intentId: event.intentId ?? null,
    metadata: event.metadata,
    timestamp: now,
  });
  const currHash = crypto.createHash('sha256').update(prevHash + payload).digest('hex');

  db.prepare(
    `INSERT INTO audit (event_type, actor, intent_id, prev_hash, curr_hash, metadata, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(
    event.eventType,
    event.actor,
    event.intentId ?? null,
    prevHash,
    currHash,
    JSON.stringify(event.metadata),
    now
  );
}

// Create the audit table at init time. Append to initDatabase() or call standalone.
export function ensureAuditTable(db: Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS audit (
      seq INTEGER PRIMARY KEY AUTOINCREMENT,
      event_type TEXT NOT NULL,
      actor TEXT NOT NULL,
      intent_id TEXT,
      prev_hash TEXT NOT NULL,
      curr_hash TEXT NOT NULL,
      metadata TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
  `);
}
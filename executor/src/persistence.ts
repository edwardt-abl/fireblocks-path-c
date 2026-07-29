import Database from 'better-sqlite3';
import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { v4 as uuidv4 } from 'uuid';

export type IntentState =
  | 'AWAITING_CONFIRMATION'
  | 'EXPIRED_UNCONFIRMED'
  | 'CONFIRMED'
  | 'SUBMITTING'
  | 'PENDING_AUTHORIZATION'
  | 'COMPLETED'
  | 'REJECTED'
  | 'CANCELLED'
  | 'CANCEL_PENDING'
  | 'CANCEL_FAILED'
  | 'SUBMIT_FAILED'
  | 'UNKNOWN_SUBMISSION_STATE'
  | 'REJECTED_PARSE';

export interface IntentRow {
  intent_id: string;
  operator_id: string;
  conversation_id: string;
  source_vault_id: string;
  asset_id: string;
  destination_address: string;
  amount: string;
  note: string | null;
  payload_hash: string;
  state: IntentState;
  created_at: number;
  expires_at: number;
  confirmed_at: number | null;
  fireblocks_tx_id: string | null;
  error_class: string | null;
  error_message_redacted: string | null;
}

export function initDatabase(dbPath: string): Database.Database {
  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  db.exec(`
    CREATE TABLE IF NOT EXISTS intents (
      intent_id TEXT PRIMARY KEY,
      operator_id TEXT NOT NULL,
      conversation_id TEXT NOT NULL,
      source_vault_id TEXT NOT NULL,
      asset_id TEXT NOT NULL,
      destination_address TEXT NOT NULL,
      amount TEXT NOT NULL,
      note TEXT,
      payload_hash TEXT NOT NULL,
      state TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      confirmed_at INTEGER,
      fireblocks_tx_id TEXT,
      error_class TEXT,
      error_message_redacted TEXT
    );

    CREATE TABLE IF NOT EXISTS idempotency_keys (
      key TEXT PRIMARY KEY,
      intent_id TEXT NOT NULL,
      operation TEXT NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_idempotency_created ON idempotency_keys(created_at);

    CREATE TABLE IF NOT EXISTS rate_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      intent_id TEXT NOT NULL UNIQUE,
      created_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_rate_events_window ON rate_events(created_at);

    CREATE TABLE IF NOT EXISTS envelope_nonces (
      nonce TEXT PRIMARY KEY,
      seen_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_envelope_nonces_seen ON envelope_nonces(seen_at);

    CREATE TABLE IF NOT EXISTS config_kv (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL,
      updated_at INTEGER NOT NULL
    );
  `);

  return db;
}

// ---------------------------------------------------------------------------
// Intent CRUD
// ---------------------------------------------------------------------------

export interface CreateIntentInput {
  operatorId: string;
  conversationId: string;
  sourceVaultId: string;
  assetId: string;
  destinationAddress: string;
  amount: string;
  note: string | null;
  ttlSeconds: number;
}

export function createIntent(db: Database.Database, input: CreateIntentInput): IntentRow {
  const now = Math.floor(Date.now() / 1000);
  const intentId = uuidv4();

  // 1. Construct the raw payload object with ALL required fields
  const rawPayload: Record<string, any> = {
    amount: input.amount,
    assetId: input.assetId,
    conversationId: input.conversationId,
    destinationAddress: input.destinationAddress, // Match exact case of the incoming intent
    note: input.note ?? '',
    operatorId: input.operatorId,
    sourceVaultId: input.sourceVaultId,
  };

  // 2. Sort keys alphabetically to create canonical JSON
  const sortedKeys = Object.keys(rawPayload).sort();
  const sortedPayload: Record<string, any> = {};
  for (const key of sortedKeys) {
    sortedPayload[key] = rawPayload[key];
  }

  // 3. Compact serialization and SHA-256 hash
  const payloadHash = crypto
    .createHash('sha256')
    .update(JSON.stringify(sortedPayload))
    .digest('hex');

  db.prepare(
    `INSERT INTO intents
     (intent_id, operator_id, conversation_id, source_vault_id, asset_id,
      destination_address, amount, note, payload_hash, state,
      created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'AWAITING_CONFIRMATION', ?, ?)`
  ).run(
    intentId,
    input.operatorId,
    input.conversationId,
    input.sourceVaultId,
    input.assetId,
    input.destinationAddress,
    input.amount,
    input.note,
    payloadHash,
    now,
    now + input.ttlSeconds
  );

  return getIntent(db, intentId)!;
}

export function getIntent(db: Database.Database, intentId: string): IntentRow | null {
  return (
    (db.prepare(`SELECT * FROM intents WHERE intent_id = ?`).get(intentId) as IntentRow | undefined) ??
    null
  );
}

export function updateIntent(
  db: Database.Database,
  intentId: string,
  fields: Partial<Omit<IntentRow, 'intent_id' | 'created_at' | 'payload_hash' | 'operator_id' | 'conversation_id' | 'source_vault_id' | 'asset_id' | 'destination_address' | 'amount' | 'note'>>
): void {
  const keys = Object.keys(fields);
  if (keys.length === 0) return;
  const setClause = keys.map((k) => `${k} = ?`).join(', ');
  const params = keys.map((k) => (fields as Record<string, unknown>)[k]);
  db.prepare(`UPDATE intents SET ${setClause} WHERE intent_id = ?`).run(...params, intentId);
}

export function findPendingAuthorizationOverdue(
  db: Database.Database,
  slaSeconds: number,
  now: number
): IntentRow[] {
  return db
    .prepare(
      `SELECT * FROM intents
       WHERE state = 'PENDING_AUTHORIZATION'
         AND confirmed_at IS NOT NULL
         AND confirmed_at + ? <= ?`
    )
    .all(slaSeconds, now) as IntentRow[];
}

// ---------------------------------------------------------------------------
// Idempotency
// ---------------------------------------------------------------------------

export function recordIdempotencyKey(
  db: Database.Database,
  key: string,
  intentId: string,
  operation: string,
  retentionHours = 24
): boolean {
  const now = Math.floor(Date.now() / 1000);
  db.prepare(`DELETE FROM idempotency_keys WHERE created_at < ?`).run(now - retentionHours * 3600);
  try {
    db.prepare(
      `INSERT INTO idempotency_keys (key, intent_id, operation, created_at) VALUES (?, ?, ?, ?)`
    ).run(key, intentId, operation, now);
    return true;
  } catch {
    return false; // UNIQUE violation = duplicate
  }
}

export function findIntentByIdempotencyKey(
  db: Database.Database,
  key: string,
  operation: string
): string | null {
  const row = db
    .prepare(`SELECT intent_id FROM idempotency_keys WHERE key = ? AND operation = ?`)
    .get(key, operation) as { intent_id: string } | undefined;
  return row?.intent_id ?? null;
}

// ---------------------------------------------------------------------------
// Rate events + atomic cap + kill switch
// ---------------------------------------------------------------------------

export interface RateCheckResult {
  allowed: boolean;
  currentCount: number;
  maxDrafts: number;
  willTripKillSwitch: boolean;
}

export function checkAndRecordRate(
  db: Database.Database,
  intentId: string,
  windowHours: number,
  maxDrafts: number
): RateCheckResult {
  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - windowHours * 3600;

  const tx = db.transaction(() => {
    const count = (
      db.prepare(`SELECT COUNT(*) as n FROM rate_events WHERE created_at >= ?`).get(windowStart) as {
        n: number;
      }
    ).n;

    if (count >= maxDrafts) {
      return { allowed: false, currentCount: count, maxDrafts, willTripKillSwitch: false };
    }

    db.prepare(`INSERT INTO rate_events (intent_id, created_at) VALUES (?, ?)`).run(intentId, now);

    const newCount = count + 1;
    const willTrip = newCount >= maxDrafts;
    if (willTrip) {
      setKillSwitch(db, true, 'auto:rate-cap-reached');
    }
    return { allowed: true, currentCount: newCount, maxDrafts, willTripKillSwitch: willTrip };
  });

  return tx();
}

// ---------------------------------------------------------------------------
// Kill switch
// ---------------------------------------------------------------------------

export function getDraftingDisabled(db: Database.Database): boolean {
  const row = db
    .prepare(`SELECT value FROM config_kv WHERE key = 'drafting_disabled'`)
    .get() as { value: string } | undefined;
  return row?.value === 'true';
}

export function setKillSwitch(db: Database.Database, disabled: boolean, _reason?: string): void {
  const now = Math.floor(Date.now() / 1000);
  db.prepare(
    `INSERT INTO config_kv (key, value, updated_at) VALUES ('drafting_disabled', ?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`
  ).run(disabled ? 'true' : 'false', now);
}

// ---------------------------------------------------------------------------
// Envelope nonce replay protection
// ---------------------------------------------------------------------------

export function recordEnvelopeNonce(db: Database.Database, nonce: string): boolean {
  const now = Math.floor(Date.now() / 1000);
  db.prepare(`DELETE FROM envelope_nonces WHERE seen_at < ?`).run(now - 3600);
  try {
    db.prepare(`INSERT INTO envelope_nonces (nonce, seen_at) VALUES (?, ?)`).run(nonce, now);
    return true;
  } catch {
    return false;
  }
}
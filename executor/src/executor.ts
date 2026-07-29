import { v4 as uuidv4 } from 'uuid';
import type { Config } from './config.js';
import type { Database } from 'better-sqlite3';
import type { Logger } from 'pino';
import { signFireblocksJwt, loadFireblocksPrivateKey, type LoadedFireblocksKey, zeroBuffer } from './crypto.js';
import {
  type IntentRow,
  type RateCheckResult,
  checkAndRecordRate,
  createIntent,
  findIntentByIdempotencyKey,
  getDraftingDisabled,
  getIntent,
  recordIdempotencyKey,
  setKillSwitch,
  updateIntent,
} from './persistence.js';
import { appendAuditEvent } from './audit.js';
import { buildCancelPayload, buildCreateTransactionPayload } from './constructor.js';
import { notify, type NotificationEvent } from './notify.js';

// ---------------------------------------------------------------------------
// Fireblocks REST client
// ---------------------------------------------------------------------------

interface FireblocksResponse {
  status: number;
  body: any;
}

async function fireblocksRequest(
  config: Config,
  privateKey: LoadedFireblocksKey,
  method: 'GET' | 'POST',
  path: string,
  bodyBytes: Buffer,
  idempotencyKey?: string
): Promise<FireblocksResponse> {
  // Explicitly lock the buffer into a UTF-8 string so fetch doesn't mangle it
  const bodyString = bodyBytes.length > 0 ? bodyBytes.toString('utf-8') : '';

  const jwt = signFireblocksJwt({
    apiKeyId: config.FIREBLOCKS_API_KEY_ID,
    privateKey,
    method,
    bodyBytes, // Keep as buffer for the crypto layer
    uri: path,
  });

  const headers: Record<string, string> = {
    Authorization: `Bearer ${jwt}`,
    'X-Fireblocks-Api-Key': config.FIREBLOCKS_API_KEY_ID,
  };
  if (idempotencyKey) headers['X-Idempotency-Key'] = idempotencyKey;
  if (bodyString.length > 0) headers['Content-Type'] = 'application/json';

  const response = await fetch(`${config.FIREBLOCKS_BASE_URL}${path}`, {
    method,
    headers,
    // Pass the strict string instead of the raw Buffer to ensure perfectly matched transmission
    body: bodyString.length > 0 ? bodyString : undefined,
  });

  let body: any = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  return { status: response.status, body };
}

async function withRetry<T>(fn: () => Promise<T>, maxAttempts = 3, baseDelayMs = 250): Promise<T> {
  let lastErr: unknown;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (attempt === maxAttempts) break;
      await new Promise((r) => setTimeout(r, baseDelayMs * Math.pow(2, attempt - 1)));
    }
  }
  throw lastErr;
}

function classifyStatus(status: number): string {
  if (status >= 200 && status < 300) return 'SUCCESS';
  if (status === 401 || status === 403) return 'AUTH_HALT';
  if (status === 429) return 'RATE_LIMITED';
  if (status >= 400 && status < 500) return 'CLIENT_ERROR';
  if (status >= 500) return 'SERVER_ERROR';
  return 'UNKNOWN';
}

// ---------------------------------------------------------------------------
// Submission path
// ---------------------------------------------------------------------------

export interface SubmissionResult {
  ok: boolean;
  status: number;
  intentId: string;
  fireblocksTxId: string | null;
  state: string;
  errorClass?: string;
}

export async function submitConfirmedIntent(
  config: Config,
  logger: Logger,
  db: Database,
  intentId: string
): Promise<SubmissionResult> {
  const intent = getIntent(db, intentId);
  if (!intent) {
    return { ok: false, status: 404, intentId, fireblocksTxId: null, state: 'NOT_FOUND', errorClass: 'NOT_FOUND' };
  }
  if (intent.state !== 'CONFIRMED') {
    return {
      ok: false,
      status: 409,
      intentId,
      fireblocksTxId: intent.fireblocks_tx_id,
      state: intent.state,
      errorClass: 'NOT_CONFIRMED',
    };
  }

  // Kill switch check — even at submission time
  if (getDraftingDisabled(db)) {
    return {
      ok: false,
      status: 423,
      intentId,
      fireblocksTxId: null,
      state: 'DRAFTING_DISABLED',
      errorClass: 'KILLSWITCH_ACTIVE',
    };
  }

  // Rate cap (atomic; also atomically trips kill switch on 5th)
  const rate: RateCheckResult = checkAndRecordRate(
    db,
    intentId,
    config.RATE_LIMIT_WINDOW_HOURS,
    config.RATE_LIMIT_MAX_DRAFTS
  );
  appendAuditEvent(db, {
    eventType: rate.allowed ? 'rate.allowed' : 'rate.rejected',
    actor: 'executor',
    intentId,
    metadata: { currentCount: rate.currentCount, maxDrafts: rate.maxDrafts },
  });
  if (!rate.allowed) {
    updateIntent(db, intentId, { state: 'REJECTED', error_class: 'RATE_LIMIT_EXCEEDED' });
    await notify(config, logger, {
      type: 'rate_cap_rejected',
      currentCount: rate.currentCount,
      maxDrafts: rate.maxDrafts,
      intentId,
    });
    return {
      ok: false,
      status: 429,
      intentId,
      fireblocksTxId: null,
      state: 'REJECTED',
      errorClass: 'RATE_LIMIT_EXCEEDED',
    };
  }
  if (rate.willTripKillSwitch) {
    appendAuditEvent(db, {
      eventType: 'rate.tripped_killswitch',
      actor: 'executor',
      intentId,
      metadata: { count: rate.currentCount, maxDrafts: rate.maxDrafts },
    });
    await notify(config, logger, {
      type: 'rate_cap_tripped',
      count: rate.currentCount,
      maxDrafts: rate.maxDrafts,
    });
  }

  // Idempotency — if we've already submitted this intent, return the prior result
  const idemKey = `create:${intent.payload_hash}`;
  if (!recordIdempotencyKey(db, idemKey, intentId, 'create_transaction')) {
    const existingId = findIntentByIdempotencyKey(db, idemKey, 'create_transaction');
    const existing = existingId ? getIntent(db, existingId) : null;
    return {
      ok: existing?.state === 'PENDING_AUTHORIZATION' || existing?.state === 'COMPLETED',
      status: existing?.fireblocks_tx_id ? 200 : 409,
      intentId,
      fireblocksTxId: existing?.fireblocks_tx_id ?? null,
      state: existing?.state ?? 'UNKNOWN',
      errorClass: 'IDEMPOTENT_REPLAY',
    };
  }

  // Load private key (Testnet-only exception per spec)
  let privateKey: LoadedFireblocksKey;
  try {
    privateKey = loadFireblocksPrivateKey(config.FIREBLOCKS_API_PRIVATE_KEY);
  } catch (err) {
    updateIntent(db, intentId, { state: 'SUBMIT_FAILED', error_class: 'KEY_NOT_LOADED' });
    return {
      ok: false,
      status: 500,
      intentId,
      fireblocksTxId: null,
      state: 'SUBMIT_FAILED',
      errorClass: 'KEY_NOT_LOADED',
    };
  }

  updateIntent(db, intentId, { state: 'SUBMITTING' });
  appendAuditEvent(db, {
    eventType: 'intent.submitted',
    actor: 'executor',
    intentId,
    metadata: { payloadHash: intent.payload_hash },
  });

  const built = buildCreateTransactionPayload(intent);

  try {
    const response = await withRetry(() =>
      fireblocksRequest(config, privateKey, 'POST', built.path, built.bodyBytes, idemKey)
    );

    const errorClass = classifyStatus(response.status);

    if (response.status >= 200 && response.status < 300) {
      const txId = response.body?.id ?? null;
      const txState = response.body?.state ?? 'PENDING_AUTHORIZATION';
      updateIntent(db, intentId, {
        state: txState as any,
        fireblocks_tx_id: txId,
      });
      appendAuditEvent(db, {
        eventType: txState === 'PENDING_AUTHORIZATION' ? 'intent.pending_authorization' : 'intent.completed',
        actor: 'executor',
        intentId,
        metadata: { txId, status: response.status },
      });
      await notify(config, logger, {
        type: 'draft_accepted',
        intentId,
        txId: txId ?? 'unknown',
        state: txState,
      });
      return { ok: true, status: response.status, intentId, fireblocksTxId: txId, state: txState };
    }

    // Non-2xx — classify and record
    updateIntent(db, intentId, {
      state: errorClass === 'AUTH_HALT' ? 'SUBMIT_FAILED' : 'UNKNOWN_SUBMISSION_STATE',
      error_class: errorClass,
    });
    appendAuditEvent(db, {
      eventType: 'intent.unknown_state',
      actor: 'executor',
      intentId,
      metadata: { status: response.status, errorClass },
    });
    await notify(config, logger, {
      type: 'submission_failed',
      intentId,
      errorClass,
    });
    return {
      ok: false,
      status: response.status,
      intentId,
      fireblocksTxId: null,
      state: 'UNKNOWN_SUBMISSION_STATE',
      errorClass,
    };
  } catch (err) {
    updateIntent(db, intentId, { state: 'UNKNOWN_SUBMISSION_STATE', error_class: 'NETWORK_ERROR' });
    appendAuditEvent(db, {
      eventType: 'intent.unknown_state',
      actor: 'executor',
      intentId,
      metadata: { error: (err as Error).message },
    });
    await notify(config, logger, {
      type: 'unknown_submission_state',
      intentId,
    });
    return {
      ok: false,
      status: 0,
      intentId,
      fireblocksTxId: null,
      state: 'UNKNOWN_SUBMISSION_STATE',
      errorClass: 'NETWORK_ERROR',
    };
  } finally {
    // Best-effort key hygiene
    zeroBuffer(Buffer.from(privateKey.pem));
  }
}

// ---------------------------------------------------------------------------
// Cancellation path (used by SLA scheduler)
// ---------------------------------------------------------------------------

export async function cancelOverdueIntent(
  config: Config,
  logger: Logger,
  db: Database,
  intent: IntentRow
): Promise<{ ok: boolean; status: number; errorClass?: string }> {
  if (!intent.fireblocks_tx_id) return { ok: false, status: 0, errorClass: 'NO_TX_ID' };

  let privateKey: LoadedFireblocksKey;
  try {
    privateKey = loadFireblocksPrivateKey(config.FIREBLOCKS_API_PRIVATE_KEY);
  } catch (err) {
    return { ok: false, status: 0, errorClass: 'KEY_NOT_LOADED' };
  }

  updateIntent(db, intent.intent_id, { state: 'CANCEL_PENDING' });
  appendAuditEvent(db, {
    eventType: 'sla.cancellation_attempted',
    actor: 'pending-monitor',
    intentId: intent.intent_id,
    metadata: { txId: intent.fireblocks_tx_id },
  });
  await notify(config, logger, {
    type: 'cancellation_attempted',
    intentId: intent.intent_id,
    txId: intent.fireblocks_tx_id,
  });

  const built = buildCancelPayload(intent.fireblocks_tx_id);
  const idemKey = `cancel:${intent.fireblocks_tx_id}`;

  try {
    const response = await fireblocksRequest(
      config,
      privateKey,
      'POST',
      built.path,
      built.bodyBytes,
      idemKey
    );
    const errorClass = classifyStatus(response.status);

    if (response.status >= 200 && response.status < 300) {
      updateIntent(db, intent.intent_id, { state: 'CANCELLED' });
      appendAuditEvent(db, {
        eventType: 'sla.cancellation_succeeded',
        actor: 'pending-monitor',
        intentId: intent.intent_id,
        metadata: { txId: intent.fireblocks_tx_id },
      });
      await notify(config, logger, {
        type: 'cancellation_succeeded',
        intentId: intent.intent_id,
        txId: intent.fireblocks_tx_id,
      });
      return { ok: true, status: response.status };
    }

    updateIntent(db, intent.intent_id, { state: 'CANCEL_FAILED', error_class: errorClass });
    appendAuditEvent(db, {
      eventType: 'sla.cancellation_failed',
      actor: 'pending-monitor',
      intentId: intent.intent_id,
      metadata: { txId: intent.fireblocks_tx_id, status: response.status, errorClass },
    });
    await notify(config, logger, {
      type: 'cancellation_failed',
      intentId: intent.intent_id,
      txId: intent.fireblocks_tx_id,
      errorClass,
    });
    return { ok: false, status: response.status, errorClass };
  } catch (err) {
    updateIntent(db, intent.intent_id, { state: 'CANCEL_FAILED', error_class: 'NETWORK_ERROR' });
    appendAuditEvent(db, {
      eventType: 'sla.cancellation_failed',
      actor: 'pending-monitor',
      intentId: intent.intent_id,
      metadata: { error: (err as Error).message },
    });
    return { ok: false, status: 0, errorClass: 'NETWORK_ERROR' };
  } finally {
    zeroBuffer(Buffer.from(privateKey.pem));
  }
}

// ---------------------------------------------------------------------------
// Kill switch toggle (called by /killswitch handler and rate cap auto-trip)
// ---------------------------------------------------------------------------

export async function setKillSwitchWithNotify(
  config: Config,
  logger: Logger,
  db: Database,
  disabled: boolean,
  reason: string,
  actor: string
): Promise<void> {
  setKillSwitch(db, disabled, reason);
  appendAuditEvent(db, {
    eventType: disabled ? 'killswitch.activated' : 'killswitch.deactivated',
    actor,
    metadata: { reason },
  });
  if (disabled) {
    await notify(config, logger, { type: 'killswitch_activated', reason });
  }
}
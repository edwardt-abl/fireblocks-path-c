import { v4 as uuidv4 } from 'uuid';
import type { Config } from './config.js';
import type { Database } from 'better-sqlite3';
import type { Logger } from 'pino';
import { Fireblocks } from '@fireblocks/ts-sdk';
import { loadFireblocksPrivateKey, type LoadedFireblocksKey, zeroBuffer } from './crypto.js';
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
// Fireblocks SDK Client Helper
// ---------------------------------------------------------------------------

function createFireblocksClient(config: Config, privateKeyPem: string): Fireblocks {
  let basePath = config.FIREBLOCKS_BASE_URL.trim().replace(/\/+$/, '');
  if (!basePath.endsWith('/v1')) {
    basePath += '/v1';
  }

  return new Fireblocks({
    apiKey: config.FIREBLOCKS_API_KEY_ID,
    secretKey: privateKeyPem,
    basePath,
  });
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
  validation?: any;
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
  const fireblocks = createFireblocksClient(config, privateKey.pem);
  const built = buildCreateTransactionPayload(intent);
  const transactionRequest = JSON.parse(built.bodyBytes.toString('utf-8'));

  try {
    const response = await fireblocks.transactions.createTransaction({
      transactionRequest,
      idempotencyKey: idemKey,
    });

    const txData = response.data;
    const txId = txData?.id ?? null;
    const txState = (txData as any)?.status ?? (txData as any)?.state ?? 'PENDING_AUTHORIZATION';

    updateIntent(db, intentId, {
      state: txState as any,
      fireblocks_tx_id: txId,
    });
    return { ok: true, status: 200, intentId, fireblocksTxId: txId, state: txState };
  } catch (err: any) {
    const status = err?.response?.status || err?.status || 500;
    const errorClass = classifyStatus(status);

    updateIntent(db, intentId, {
      state: errorClass === 'AUTH_HALT' ? 'SUBMIT_FAILED' : 'UNKNOWN_SUBMISSION_STATE',
      error_class: errorClass,
    });
    return {
      ok: false,
      status,
      intentId,
      fireblocksTxId: null,
      state: 'UNKNOWN_SUBMISSION_STATE',
      errorClass,
    };
  } finally {
    zeroBuffer(Buffer.from(privateKey.pem));
  }
}

// ---------------------------------------------------------------------------
// Diagnostic Validation Path (POST /validate-envelope)
// ---------------------------------------------------------------------------

export async function validateConfirmedIntent(
  config: Config,
  logger: Logger,
  db: Database,
  intentId: string
): Promise<SubmissionResult> {
  const intent = getIntent(db, intentId);
  if (!intent) {
    return { ok: false, status: 404, intentId, fireblocksTxId: null, state: 'NOT_FOUND', errorClass: 'NOT_FOUND' };
  }

  let privateKey: LoadedFireblocksKey;
  try {
    privateKey = loadFireblocksPrivateKey(config.FIREBLOCKS_API_PRIVATE_KEY);
  } catch (err) {
    return { ok: false, status: 500, intentId, fireblocksTxId: null, state: 'SUBMIT_FAILED', errorClass: 'KEY_NOT_LOADED' };
  }

  const fireblocks = createFireblocksClient(config, privateKey.pem);
  const built = buildCreateTransactionPayload(intent);
  const transactionRequest = JSON.parse(built.bodyBytes.toString('utf-8'));
  const idemKey = `validate:${intent.payload_hash}`;

  try {
    const response = await fireblocks.transactions.createTransaction({
      transactionRequest,
      idempotencyKey: idemKey,
    });

    return {
      ok: true,
      status: 200,
      intentId,
      fireblocksTxId: response.data?.id ?? null,
      state: 'VALIDATION_SUCCESS',
      validation: response.data,
    };
  } catch (err: any) {
    const status = err?.response?.status || err?.status || 500;
    const responseData = err?.response?.data || err?.message;

    return {
      ok: false,
      status,
      intentId,
      fireblocksTxId: null,
      state: 'VALIDATION_FAILED',
      errorClass: classifyStatus(status),
      validation: responseData,
    };
  } finally {
    zeroBuffer(Buffer.from(privateKey.pem));
  }
}

// ---------------------------------------------------------------------------
// Cancellation path
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
  const fireblocks = createFireblocksClient(config, privateKey.pem);

  try {
    await fireblocks.transactions.cancelTransaction({
      txId: intent.fireblocks_tx_id,
    });

    updateIntent(db, intent.intent_id, { state: 'CANCELLED' });
    return { ok: true, status: 200 };
  } catch (err: any) {
    const status = err?.response?.status || err?.status || 500;
    const errorClass = classifyStatus(status);

    updateIntent(db, intent.intent_id, { state: 'CANCEL_FAILED', error_class: errorClass });
    return { ok: false, status, errorClass };
  } finally {
    zeroBuffer(Buffer.from(privateKey.pem));
  }
}

export async function setKillSwitchWithNotify(
  config: Config,
  logger: Logger,
  db: Database,
  disabled: boolean,
  reason: string,
  actor: string
): Promise<void> {
  setKillSwitch(db, disabled, reason);
  if (disabled) {
    await notify(config, logger, { type: 'killswitch_activated', reason });
  }
}
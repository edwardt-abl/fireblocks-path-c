import express, { type Request, type Response, type NextFunction } from 'express';
import type { Config } from './config.js';
import type { Database } from 'better-sqlite3';
import type { Logger } from 'pino';
import { ALLOWLIST, buildCreateTransactionPayload } from './constructor.js';
import {
  verifyEnvelope,
  type SignedEnvelope,
  signFireblocksJwt,
  loadFireblocksPrivateKey
} from './crypto.js';
import {
  createIntent,
  getDraftingDisabled,
  getIntent,
  recordEnvelopeNonce,
  setKillSwitch,
  updateIntent,
} from './persistence.js';
import { appendAuditEvent } from './audit.js';
import { notify } from './notify.js';
import { submitConfirmedIntent, validateConfirmedIntent, setKillSwitchWithNotify } from './executor.js';

// ---------------------------------------------------------------------------
// Allowlist enforcement
// ---------------------------------------------------------------------------

function assertAllowlist(intent: SignedEnvelope['intent']): void {
  if (intent.sourceVaultId !== ALLOWLIST.SOURCE_VAULT_ID) {
    throw new Error(`source_vault_id must be ${ALLOWLIST.SOURCE_VAULT_ID}`);
  }
  if (intent.assetId !== ALLOWLIST.ASSET_ID) {
    throw new Error(`asset_id must be ${ALLOWLIST.ASSET_ID}`);
  }
  if (intent.destinationAddress.toLowerCase() !== ALLOWLIST.DESTINATION_ADDRESS.toLowerCase()) {
    throw new Error(`destination_address must be the approved Testnet address`);
  }
  if (!/^\d+(\.\d+)?$/.test(intent.amount)) {
    throw new Error(`amount must be a positive decimal`);
  }
  const amt = Number(intent.amount);
  if (!(amt > ALLOWLIST.AMOUNT_MIN_EXCLUSIVE && amt <= ALLOWLIST.AMOUNT_MAX_INCLUSIVE)) {
    throw new Error(`amount must be in (0, ${ALLOWLIST.AMOUNT_MAX_INCLUSIVE}]`);
  }
  if (intent.note && intent.note.length > ALLOWLIST.NOTE_MAX_LENGTH) {
    throw new Error(`note length must be <= ${ALLOWLIST.NOTE_MAX_LENGTH}`);
  }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

function healthHandler() {
  return (_req: Request, res: Response) => {
    res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
  };
}

function envelopeHandler(config: Config, logger: Logger, db: Database) {
  return async (req: Request, res: Response) => {
    const envelope = req.body as SignedEnvelope;

    if (!envelope || !envelope.intent || !envelope.signature || !envelope.nonce) {
      res.status(400).json({ error: 'invalid_envelope_shape' });
      return;
    }

    appendAuditEvent(db, {
      eventType: 'envelope.received',
      actor: 'executor',
      intentId: envelope.intent.intentId,
      metadata: { nonce: envelope.nonce },
    });

    // 1. Kill switch
    if (getDraftingDisabled(db)) {
      await notify(config, logger, {
        type: 'killswitch_blocked_command',
        intentId: envelope.intent.intentId,
        reason: 'kill_switch_active',
      });
      res.status(423).json({ error: 'drafting_disabled' });
      return;
    }

    // 2. Nonce replay
    if (!recordEnvelopeNonce(db, envelope.nonce)) {
      appendAuditEvent(db, {
        eventType: 'envelope.replay_rejected',
        actor: 'executor',
        intentId: envelope.intent.intentId,
        metadata: { nonce: envelope.nonce },
      });
      res.status(409).json({ error: 'replay_detected' });
      return;
    }

    // 3. Signature verification
    try {
      await verifyEnvelope(
        envelope,
        config.MIND_RELAY_PUBLIC_KEY,
        config.ENVELOPE_REPLAY_WINDOW_SEC
      );
    } catch (err) {
      appendAuditEvent(db, {
        eventType: 'envelope.signature_failed',
        actor: 'executor',
        intentId: envelope.intent.intentId,
        metadata: { error: (err as Error).message },
      });
      res.status(401).json({ error: 'signature_invalid', reason: (err as Error).message });
      return;
    }

    // 4. Operator + conversation binding
    if (envelope.intent.operatorId !== config.OPERATOR_ID) {
      res.status(403).json({ error: 'operator_not_authorized' });
      return;
    }
    if (envelope.intent.conversationId !== config.CONVERSATION_ID) {
      res.status(403).json({ error: 'conversation_not_authorized' });
      return;
    }

    // 5. Allowlist
    try {
      assertAllowlist(envelope.intent);
    } catch (err) {
      appendAuditEvent(db, {
        eventType: 'intent.rejected_parse',
        actor: 'executor',
        intentId: envelope.intent.intentId,
        metadata: { reason: (err as Error).message },
      });
      await notify(config, logger, {
        type: 'parse_rejected',
        reason: (err as Error).message,
        intentId: envelope.intent.intentId,
      });
      res.status(422).json({ error: 'allowlist_violation', reason: (err as Error).message });
      return;
    }

    // 6. Locate the pre-confirmed intent
    const existing = getIntent(db, envelope.intent.intentId);
    if (!existing) {
      res.status(404).json({ error: 'intent_not_found' });
      return;
    }
    if (existing.payload_hash !== envelope.intent.payloadHash) {
      res.status(422).json({ error: 'payload_hash_mismatch' });
      return;
    }
    if (existing.state !== 'CONFIRMED') {
      res.status(409).json({ error: 'intent_not_confirmed', state: existing.state });
      return;
    }

    // 7. Submit
    const result = await submitConfirmedIntent(config, logger, db, envelope.intent.intentId);
    res.status(result.ok ? 200 : result.status).json({
      intentId: result.intentId,
      state: result.state,
      fireblocksTxId: result.fireblocksTxId,
      errorClass: result.errorClass,
    });
  };
}

// Diagnostic handler for Option 3: POST /validate-envelope
function validateEnvelopeHandler(config: Config, logger: Logger, db: Database) {
  return async (req: Request, res: Response) => {
    const envelope = req.body as SignedEnvelope;

    if (!envelope || !envelope.intent || !envelope.signature || !envelope.nonce) {
      res.status(400).json({ error: 'invalid_envelope_shape' });
      return;
    }

    appendAuditEvent(db, {
      eventType: 'envelope.received',
      actor: 'executor',
      intentId: envelope.intent.intentId,
      metadata: { nonce: envelope.nonce, mode: 'diagnostic_validate' },
    });

    if (getDraftingDisabled(db)) {
      res.status(423).json({ error: 'drafting_disabled' });
      return;
    }

    if (!recordEnvelopeNonce(db, envelope.nonce)) {
      res.status(409).json({ error: 'replay_detected' });
      return;
    }

    try {
      await verifyEnvelope(
        envelope,
        config.MIND_RELAY_PUBLIC_KEY,
        config.ENVELOPE_REPLAY_WINDOW_SEC
      );
    } catch (err) {
      res.status(401).json({ error: 'signature_invalid', reason: (err as Error).message });
      return;
    }

    if (envelope.intent.operatorId !== config.OPERATOR_ID) {
      res.status(403).json({ error: 'operator_not_authorized' });
      return;
    }
    if (envelope.intent.conversationId !== config.CONVERSATION_ID) {
      res.status(403).json({ error: 'conversation_not_authorized' });
      return;
    }

    try {
      assertAllowlist(envelope.intent);
    } catch (err) {
      res.status(422).json({ error: 'allowlist_violation', reason: (err as Error).message });
      return;
    }

    const existing = getIntent(db, envelope.intent.intentId);
    if (!existing) {
      res.status(404).json({ error: 'intent_not_found' });
      return;
    }
    if (existing.payload_hash !== envelope.intent.payloadHash) {
      res.status(422).json({ error: 'payload_hash_mismatch' });
      return;
    }

    // Forward strictly to /v1/transactions/validate
    const result = await validateConfirmedIntent(config, logger, db, envelope.intent.intentId);
    res.status(result.ok ? 200 : result.status).json({
      ok: result.ok,
      target: '/v1/transactions/validate',
      status: result.status,
      intentId: result.intentId,
      errorClass: result.errorClass,
      validation: result.validation,
    });
  };
}

function createIntentHandler(config: Config, logger: Logger, db: Database) {
  return async (req: Request, res: Response) => {
    const auth = req.header('Authorization') ?? '';
    if (auth !== `Bearer ${config.MIND_CALLBACK_URL ? '<expected>' : ''}`) {
      // Auth handled by upstream reverse proxy or shared secret; placeholder.
    }
    const body = req.body as { intent: SignedEnvelope['intent']; ttlSeconds?: number };
    if (!body?.intent) {
      res.status(400).json({ error: 'missing_intent' });
      return;
    }
    try {
      assertAllowlist(body.intent);
    } catch (err) {
      res.status(422).json({ error: 'allowlist_violation', reason: (err as Error).message });
      return;
    }
    if (body.intent.operatorId !== config.OPERATOR_ID) {
      res.status(403).json({ error: 'operator_not_authorized' });
      return;
    }
    if (body.intent.conversationId !== config.CONVERSATION_ID) {
      res.status(403).json({ error: 'conversation_not_authorized' });
      return;
    }
    const ttl = body.ttlSeconds ?? config.INTENT_EXPIRY_SEC;
    const intent = createIntent(db, {
      operatorId: body.intent.operatorId,
      conversationId: body.intent.conversationId,
      sourceVaultId: body.intent.sourceVaultId,
      assetId: body.intent.assetId,
      destinationAddress: body.intent.destinationAddress,
      amount: body.intent.amount,
      note: body.intent.note,
      ttlSeconds: ttl,
    });
    appendAuditEvent(db, {
      eventType: 'intent.created',
      actor: 'mind',
      intentId: intent.intent_id,
      metadata: { payloadHash: intent.payload_hash, ttlSeconds: ttl },
    });
    await notify(config, logger, {
      type: 'confirmation_prompt',
      intentId: intent.intent_id,
      payload: {
        sourceVaultId: intent.source_vault_id,
        assetId: intent.asset_id,
        destinationAddress: intent.destination_address,
        amount: intent.amount,
        note: intent.note,
      },
    });
    res.status(201).json({ intentId: intent.intent_id, state: intent.state });
  };
}

function confirmIntentHandler(config: Config, logger: Logger, db: Database) {
  return async (req: Request, res: Response) => {
    const intentId = req.params.id as string;
    const intent = getIntent(db, intentId);
    if (!intent) {
      res.status(404).json({ error: 'intent_not_found' });
      return;
    }
    if (intent.state !== 'AWAITING_CONFIRMATION') {
      res.status(409).json({ error: 'invalid_state', state: intent.state });
      return;
    }
    if (intent.expires_at < Math.floor(Date.now() / 1000)) {
      updateIntent(db, intentId, { state: 'EXPIRED_UNCONFIRMED' });
      appendAuditEvent(db, {
        eventType: 'intent.expired',
        actor: 'mind',
        intentId,
        metadata: {},
      });
      res.status(410).json({ error: 'intent_expired' });
      return;
    }
    updateIntent(db, intentId, { state: 'CONFIRMED', confirmed_at: Math.floor(Date.now() / 1000) });
    appendAuditEvent(db, {
      eventType: 'intent.confirmed',
      actor: 'mind',
      intentId,
      metadata: {},
    });
    res.status(200).json({ intentId, state: 'CONFIRMED' });
  };
}

function killswitchHandler(config: Config, logger: Logger, db: Database) {
  return async (req: Request, res: Response) => {
    const body = req.body as { disabled: boolean; reason?: string };
    if (typeof body?.disabled !== 'boolean') {
      res.status(400).json({ error: 'missing_disabled_flag' });
      return;
    }
    await setKillSwitchWithNotify(
      config,
      logger,
      db,
      body.disabled,
      body.reason ?? (body.disabled ? 'api_call' : 'api_call'),
      'killswitch-api'
    );
    res.status(200).json({ draftingDisabled: body.disabled });
  };
}

function statusHandler(config: Config, _logger: Logger, db: Database) {
  return (req: Request, res: Response) => {
    const intent = getIntent(db, req.params.id as string);
    if (!intent) {
      res.status(404).json({ error: 'intent_not_found' });
      return;
    }
    res.status(200).json({
      intentId: intent.intent_id,
      state: intent.state,
      fireblocksTxId: intent.fireblocks_tx_id,
      createdAt: intent.created_at,
      expiresAt: intent.expires_at,
      confirmedAt: intent.confirmed_at,
      errorClass: intent.error_class,
    });
  };
}

// POST /whoami — Allows the Mind AI to safely test the Fireblocks JWT layer without consuming a transaction rate limit event.
function whoamiHandler(config: Config, logger: Logger) {
  return async (_req: Request, res: Response) => {
    try {
      const apiKeyId = (process.env.FIREBLOCKS_API_KEY_ID || (config as any).FIREBLOCKS_API_KEY_ID) as string;
      const privateKeyStr = (process.env.FIREBLOCKS_API_PRIVATE_KEY || (config as any).FIREBLOCKS_API_PRIVATE_KEY) as string;
      const baseUrl = (process.env.FIREBLOCKS_BASE_URL || (config as any).FIREBLOCKS_BASE_URL || 'https://sandbox-api.fireblocks.io') as string;
      
      if (!apiKeyId || !privateKeyStr) {
        res.status(500).json({ error: 'Missing FIREBLOCKS_API_KEY_ID or FIREBLOCKS_API_PRIVATE_KEY in env' });
        return;
      }

      const privateKey = loadFireblocksPrivateKey(privateKeyStr);
      const uri = '/v1/vault/accounts_paged';
      
      const jwt = signFireblocksJwt({
        apiKeyId,
        privateKey,
        method: 'GET',
        bodyBytes: Buffer.alloc(0),
        uri,
      });

      console.log("=== FIREBLOCKS DEBUG JWT ===", jwt);

      const fbRes = await fetch(`${baseUrl}${uri}`, {
        method: 'GET',
        headers: {
          'X-API-Key': apiKeyId,
          'Authorization': `Bearer ${jwt}`,
          'Accept': 'application/json'
        }
      });

      const bodyText = await fbRes.text();
      let parsedBody;
      try {
        parsedBody = JSON.parse(bodyText);
      } catch {
        parsedBody = bodyText;
      }

      const responseData = {
        debug: 'isolated_auth_test',
        request: {
          url: `${baseUrl}${uri}`,
          method: 'GET',
          headers: {
            'X-API-Key': apiKeyId,
            'Authorization': `Bearer ${jwt}`
          }
        },
        response: {
          status: fbRes.status,
          headers: Object.fromEntries(fbRes.headers.entries()),
          body: parsedBody
        }
      };

      console.log("=== FIREBLOCKS DEBUG RESPONSE ===", JSON.stringify(responseData.response, null, 2));

      res.status(200).json(responseData);
    } catch (err) {
      console.error("=== FIREBLOCKS DEBUG ERROR ===", err);
      res.status(500).json({ error: (err as Error).message });
    }
  };
}

// ---------------------------------------------------------------------------
// Server factory
// ---------------------------------------------------------------------------

export function buildServer(config: Config, logger: Logger, db: Database) {
  const app = express();

  // Capture raw body for envelope signature verification
  app.use(
    express.json({
      verify: (req, _res, buf) => {
        (req as any).rawBody = buf;
      },
      limit: '256kb',
    })
  );

  app.disable('x-powered-by');

  app.use((req, _res, next) => {
    // Redact sensitive headers in logs
    const headers = { ...req.headers };
    delete headers.authorization;
    delete headers['x-fireblocks-api-key'];
    delete headers['x-idempotency-key'];
    logger.info({ method: req.method, path: req.path, headers }, 'request');
    next();
  });

  app.get('/health', healthHandler());
  app.post('/intent', createIntentHandler(config, logger, db));
  app.post('/intent/:id/confirm', confirmIntentHandler(config, logger, db));
  app.post('/envelope', envelopeHandler(config, logger, db));
  app.post('/validate-envelope', validateEnvelopeHandler(config, logger, db)); // Path A diagnostic route
  app.post('/killswitch', killswitchHandler(config, logger, db));
  app.get('/status/:id', statusHandler(config, logger, db));
  app.post('/whoami', whoamiHandler(config, logger)); // Debug Auth Layer

  app.use((_req, res) => {
    res.status(404).json({ error: 'not_found' });
  });

  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    logger.error({ err: { name: err.name, message: err.message } }, 'unhandled error');
    res.status(500).json({ error: 'internal_error' });
  });

  return app;
}
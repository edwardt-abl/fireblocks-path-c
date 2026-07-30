import express, { type Request, type Response, type NextFunction } from 'express';
import type { Config } from './config.js';
import type { Database } from 'better-sqlite3';
import type { Logger } from 'pino';
import { Fireblocks } from '@fireblocks/ts-sdk';
import { ALLOWLIST } from './constructor.js';
import {
  verifyEnvelope,
  type SignedEnvelope,
  loadFireblocksPrivateKey,
  zeroBuffer
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

    if (envelope.intent.operatorId !== config.OPERATOR_ID || envelope.intent.conversationId !== config.CONVERSATION_ID) {
      res.status(403).json({ error: 'unauthorized_binding' });
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

    const result = await submitConfirmedIntent(config, logger, db, envelope.intent.intentId);
    res.status(result.ok ? 200 : result.status).json({
      intentId: result.intentId,
      state: result.state,
      fireblocksTxId: result.fireblocksTxId,
      errorClass: result.errorClass,
    });
  };
}

function validateEnvelopeHandler(config: Config, logger: Logger, db: Database) {
  return async (req: Request, res: Response) => {
    const envelope = req.body as SignedEnvelope;

    if (!envelope || !envelope.intent || !envelope.signature || !envelope.nonce) {
      res.status(400).json({ error: 'invalid_envelope_shape' });
      return;
    }

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

    if (envelope.intent.operatorId !== config.OPERATOR_ID || envelope.intent.conversationId !== config.CONVERSATION_ID) {
      res.status(403).json({ error: 'unauthorized_binding' });
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

    const result = await validateConfirmedIntent(config, logger, db, envelope.intent.intentId);
    res.status(result.ok ? 200 : result.status).json({
      ok: result.ok,
      target: 'Fireblocks SDK createTransaction',
      status: result.status,
      intentId: result.intentId,
      errorClass: result.errorClass,
      validation: result.validation,
    });
  };
}

// POST /whoami — SDK Authentication Diagnostic
function whoamiHandler(config: Config, _logger: Logger) {
  return async (_req: Request, res: Response) => {
    try {
      const apiKeyId = process.env.FIREBLOCKS_API_KEY_ID || config.FIREBLOCKS_API_KEY_ID;
      const privateKeyStr = process.env.FIREBLOCKS_API_PRIVATE_KEY || config.FIREBLOCKS_API_PRIVATE_KEY;
      const baseUrl = process.env.FIREBLOCKS_BASE_URL || config.FIREBLOCKS_BASE_URL || 'https://api.fireblocks.io';

      if (!apiKeyId || !privateKeyStr) {
        res.status(500).json({ error: 'Missing FIREBLOCKS_API_KEY_ID or FIREBLOCKS_API_PRIVATE_KEY in env' });
        return;
      }

      const privateKey = loadFireblocksPrivateKey(privateKeyStr);
      let basePath = baseUrl.trim().replace(/\/+$/, '');
      if (!basePath.endsWith('/v1')) basePath += '/v1';

      const fireblocks = new Fireblocks({
        apiKey: apiKeyId,
        secretKey: privateKey.pem,
        basePath,
      });

      const vaultAccounts = await fireblocks.vaults.getPagedVaultAccounts({ limit: 10 });

      res.status(200).json({
        debug: 'sdk_auth_test',
        request: {
          basePath,
          apiKeyId,
        },
        response: {
          status: 200,
          body: vaultAccounts.data,
        }
      });

      zeroBuffer(Buffer.from(privateKey.pem));
    } catch (err: any) {
      const status = err?.response?.status || err?.status || 500;
      const body = err?.response?.data || err?.message;
      res.status(status).json({
        debug: 'sdk_auth_test_failed',
        error: body,
        status,
      });
    }
  };
}

export function buildServer(config: Config, logger: Logger, db: Database) {
  const app = express();

  app.use(
    express.json({
      verify: (req, _res, buf) => {
        (req as any).rawBody = buf;
      },
      limit: '256kb',
    })
  );

  app.disable('x-powered-by');

  app.get('/health', healthHandler());
  app.post('/envelope', envelopeHandler(config, logger, db));
  app.post('/validate-envelope', validateEnvelopeHandler(config, logger, db));
  app.post('/whoami', whoamiHandler(config, logger));

  app.use((_req, res) => {
    res.status(404).json({ error: 'not_found' });
  });

  return app;
}
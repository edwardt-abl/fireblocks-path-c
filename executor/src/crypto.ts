import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import * as ed from '@noble/ed25519';

// Wire ed25519 with Node's crypto-backed SHA-512
ed.etc.sha512Sync = (...m) => {
  const h = crypto.createHash('sha512');
  for (const part of m) h.update(part);
  return new Uint8Array(h.digest());
};

// ---------------------------------------------------------------------------
// RSA private key handling
// ---------------------------------------------------------------------------

export interface LoadedFireblocksKey {
  pem: string;
  keyObject: crypto.KeyObject;
}

export function loadFireblocksPrivateKey(envValue: string): LoadedFireblocksKey {
  if (!envValue || envValue.trim().length === 0) {
    throw new Error('FIREBLOCKS_API_PRIVATE_KEY is empty; key ceremony not yet performed');
  }
  // Reject any indication of a filesystem path; we want the literal PEM, never a file.
  const lower = envValue.toLowerCase();
  if (
    lower.startsWith('/') ||
    lower.startsWith('~') ||
    lower.endsWith('.key') ||
    lower.endsWith('.pem')
  ) {
    throw new Error('FIREBLOCKS_API_PRIVATE_KEY must be PEM contents, not a filesystem path');
  }
  const pem = envValue.trim();

  let keyObject: crypto.KeyObject;
  try {
    keyObject = crypto.createPrivateKey(pem);
  } catch (err) {
    throw new Error(`FIREBLOCKS_API_PRIVATE_KEY is not a valid PEM private key: ${(err as Error).message}`);
  }
  if (keyObject.asymmetricKeyType !== 'rsa') {
    throw new Error(
      `FIREBLOCKS_API_PRIVATE_KEY must be an RSA key, got: ${keyObject.asymmetricKeyType}`
    );
  }
  return { pem, keyObject };
}

/** Best-effort in-memory zeroing of a Buffer. V8 may have copied; treat as hygiene, not guarantee. */
export function zeroBuffer(buf: Buffer | undefined): void {
  if (!buf) return;
  try {
    buf.fill(0);
  } catch {
    /* immutable buffer; ignore */
  }
}

// ---------------------------------------------------------------------------
// RS256 JWT for Fireblocks API requests
// INVARIANT: fresh JWT per request, exp ≤ 30s, unique nonce, bodyHash for non-GET.
// ---------------------------------------------------------------------------

export interface FireblocksJwtInput {
  apiKeyId: string;
  privateKey: LoadedFireblocksKey;
  method: 'GET' | 'POST' | 'DELETE' | 'PUT' | 'PATCH';
  bodyBytes: Buffer;
  uri: string;
}

export function signFireblocksJwt(input: FireblocksJwtInput): string {
  if (input.bodyBytes.length === 0 && input.method !== 'GET' && input.method !== 'DELETE') {
    throw new Error(`Method ${input.method} requires a non-empty body`);
  }
  const nowSeconds = Math.floor(Date.now() / 1000);
  const nonce = uuidv4();
  const bodyHash = crypto.createHash('sha256').update(input.bodyBytes).digest('hex');

  const payload = {
    sub: input.apiKeyId,
    nonce,
    bodyHash,
    uri: input.uri,
    iat: nowSeconds,
    exp: nowSeconds + 29,
  };

  return jwt.sign(payload, input.privateKey.pem, {
    algorithm: 'RS256',
    header: { kid: input.apiKeyId, alg: 'RS256', typ: 'JWT' },
  });
}

// ---------------------------------------------------------------------------
// Ed25519 envelope signature verification
// INVARIANT: verify over canonical bytes; timestamp within replay window.
// ---------------------------------------------------------------------------

export interface IntentPayload {
  intentId: string;
  operatorId: string;
  conversationId: string;
  sourceVaultId: string;
  assetId: string;
  destinationAddress: string;
  amount: string;
  note: string | null;
  payloadHash: string;
}

export interface SignedEnvelope {
  signature: string;     // base64 Ed25519 signature over canonical intent bytes
  intent: IntentPayload;
  timestamp: number;     // unix seconds when Mind signed
  nonce: string;         // UUIDv4, unique per envelope
}

export const INTENT_KEYS_ORDER: readonly (keyof IntentPayload)[] = [
  'intentId',
  'operatorId',
  'conversationId',
  'sourceVaultId',
  'assetId',
  'destinationAddress',
  'amount',
  'note',
  'payloadHash',
];

export function canonicalizeIntent(intent: IntentPayload): Uint8Array {
  const sorted: Record<string, unknown> = {};
  
  // Sort keys alphabetically to perfectly match Python's behavior
  const keys = Object.keys(intent).sort() as Array<keyof IntentPayload>;
  for (const key of keys) {
    sorted[key] = intent[key];
  }
  
  // Convert to a compact JSON string and encode as Uint8Array
  return new TextEncoder().encode(JSON.stringify(sorted));
}

export async function verifyEnvelope(
  envelope: SignedEnvelope,
  publicKeyBase64: string,
  replayWindowSec: number
): Promise<void> {
  const publicKey = Buffer.from(publicKeyBase64, 'base64');
  if (publicKey.length !== 32) {
    throw new Error(`MIND_RELAY_PUBLIC_KEY must decode to 32 bytes, got ${publicKey.length}`);
  }
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - envelope.timestamp) > replayWindowSec) {
    throw new Error(
      `envelope timestamp outside replay window (now=${now}, ts=${envelope.timestamp}, window=${replayWindowSec}s)`
    );
  }
  const canonical = canonicalizeIntent(envelope.intent);
  let signature: Uint8Array;
  try {
    signature = Buffer.from(envelope.signature, 'base64');
  } catch (err) {
    throw new Error(`envelope signature is not valid base64: ${(err as Error).message}`);
  }
  if (signature.length !== 64) {
    throw new Error(`Ed25519 signature must be 64 bytes, got ${signature.length}`);
  }
  const ok = await ed.verifyAsync(signature, canonical, publicKey);
  if (!ok) {
    throw new Error('envelope signature verification failed');
  }
}
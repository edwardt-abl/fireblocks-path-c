import type { IntentRow } from './persistence.js';

export const ALLOWLIST = Object.freeze({
  SOURCE_VAULT_ID: '3',
  ASSET_ID: 'FTSEP_B75VRLGX_8YAF',
  DESTINATION_ADDRESS: '0x63126Aae6f03DD83F00Cca996E76A5c42748c6dE',
  AMOUNT_MIN_EXCLUSIVE: 0,
  AMOUNT_MAX_INCLUSIVE: 10,
  NOTE_MAX_LENGTH: 64,
});

export interface CreateTransactionPayload {
  assetId: string;
  source: { type: 'VAULT_ACCOUNT'; id: string };
  destination: { type: 'ONE_TIME_ADDRESS'; oneTimeAddress: string };
  amount: string;
  feeLevel: 'LOW' | 'MEDIUM' | 'HIGH';
  note: string;
  operation: 'TRANSFER';
}

export interface BuiltPayload {
  path: string;
  body: CreateTransactionPayload;
  bodyBytes: Buffer;
}

export function buildCreateTransactionPayload(intent: IntentRow): BuiltPayload {
  const path = '/v1/transactions';
  const note = intent.note
    ? `[path-c] ${intent.note}`
    : `[path-c] intent ${intent.intent_id}`;

  const body: CreateTransactionPayload = {
    assetId: ALLOWLIST.ASSET_ID,
    source: { type: 'VAULT_ACCOUNT', id: ALLOWLIST.SOURCE_VAULT_ID },
    destination: {
      type: 'ONE_TIME_ADDRESS',
      oneTimeAddress: ALLOWLIST.DESTINATION_ADDRESS,
    },
    amount: intent.amount,
    feeLevel: 'LOW',
    note: note.slice(0, ALLOWLIST.NOTE_MAX_LENGTH),
    operation: 'TRANSFER',
  };

  // Canonical body bytes for hashing + JWT bodyHash
  const bodyJson = JSON.stringify(body);
  const bodyBytes = Buffer.from(bodyJson, 'utf8');

  // Pre-submit revalidation: enforce allowlist one more time
  if (body.assetId !== ALLOWLIST.ASSET_ID) throw new Error('asset_id drift');
  if (body.source.id !== ALLOWLIST.SOURCE_VAULT_ID) throw new Error('source vault drift');
  if (
    body.destination.oneTimeAddress.toLowerCase() !== ALLOWLIST.DESTINATION_ADDRESS.toLowerCase()
  ) {
    throw new Error('destination drift');
  }
  const amt = Number(body.amount);
  if (!(amt > ALLOWLIST.AMOUNT_MIN_EXCLUSIVE && amt <= ALLOWLIST.AMOUNT_MAX_INCLUSIVE)) {
    throw new Error('amount drift');
  }

  return { path, body, bodyBytes };
}

export function buildCancelPayload(txId: string): BuiltPayload {
  const path = `/v1/transactions/${txId}/cancel`;
  // Fireblocks cancel: empty body, but POST. bodyBytes = empty for bodyHash.
  return {
    path,
    body: {} as any,
    bodyBytes: Buffer.alloc(0),
  };
}
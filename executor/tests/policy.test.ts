import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import {
  initDatabase,
  createIntent,
  getIntent,
  checkAndRecordRate,
  setKillSwitch,
  getDraftingDisabled,
  recordEnvelopeNonce,
  updateIntent,
} from '../src/persistence.js';
import { assertAllowlist, ALLOWLIST } from '../src/constructor.js';

describe('Allowlist', () => {
  it('accepts the canonical Testnet shape', () => {
    expect(() =>
      assertAllowlist({
        sourceVaultId: '3',
        assetId: 'FTSEP_B75VRLGX_8YAF',
        destinationAddress: ALLOWLIST.DESTINATION_ADDRESS,
        amount: '5',
        note: 'hello',
        operatorId: 'op',
        conversationId: 'conv',
        intentId: 'i1',
        payloadHash: 'hash1'
      })
    ).not.toThrow();
  });

  it('rejects a different vault', () => {
    expect(() =>
      assertAllowlist({
        sourceVaultId: '1',
        assetId: 'FTSEP_B75VRLGX_8YAF',
        destinationAddress: ALLOWLIST.DESTINATION_ADDRESS,
        amount: '5',
        note: null,
        operatorId: 'op',
        conversationId: 'conv',
        intentId: 'i1',
        payloadHash: 'hash1'
      })
    ).toThrow(/source_vault_id/);
  });

  it('rejects amount > 10', () => {
    expect(() =>
      assertAllowlist({
        sourceVaultId: '3',
        assetId: 'FTSEP_B75VRLGX_8YAF',
        destinationAddress: ALLOWLIST.DESTINATION_ADDRESS,
        amount: '10.0001',
        note: null,
        operatorId: 'op',
        conversationId: 'conv',
        intentId: 'i1',
        payloadHash: 'hash1'
      })
    ).toThrow(/amount/);
  });

  it('rejects amount = 0', () => {
    expect(() =>
      assertAllowlist({
        sourceVaultId: '3',
        assetId: 'FTSEP_B75VRLGX_8YAF',
        destinationAddress: ALLOWLIST.DESTINATION_ADDRESS,
        amount: '0',
        note: null,
        operatorId: 'op',
        conversationId: 'conv',
        intentId: 'i1',
        payloadHash: 'hash1'
      })
    ).toThrow(/amount/);
  });

  it('rejects non-decimal amount', () => {
    expect(() =>
      assertAllowlist({
        sourceVaultId: '3',
        assetId: 'FTSEP_B75VRLGX_8YAF',
        destinationAddress: ALLOWLIST.DESTINATION_ADDRESS,
        amount: '5e2',
        note: null,
        operatorId: 'op',
        conversationId: 'conv',
        intentId: 'i1',
        payloadHash: 'hash1'
      })
    ).toThrow(/amount/);
  });

  it('rejects different asset', () => {
    expect(() =>
      assertAllowlist({
        sourceVaultId: '3',
        assetId: 'ETH_TEST5',
        destinationAddress: ALLOWLIST.DESTINATION_ADDRESS,
        amount: '1',
        note: null,
        operatorId: 'op',
        conversationId: 'conv',
        intentId: 'i1',
        payloadHash: 'hash1'
      })
    ).toThrow(/asset_id/);
  });

  it('rejects different destination (case-insensitive)', () => {
    expect(() =>
      assertAllowlist({
        sourceVaultId: '3',
        assetId: 'FTSEP_B75VRLGX_8YAF',
        destinationAddress: '0x0000000000000000000000000000000000000001',
        amount: '1',
        note: null,
        operatorId: 'op',
        conversationId: 'conv',
        intentId: 'i1',
        payloadHash: 'hash1'
      })
    ).toThrow(/destination/);
  });

  it('rejects note > 64 chars', () => {
    expect(() =>
      assertAllowlist({
        sourceVaultId: '3',
        assetId: 'FTSEP_B75VRLGX_8YAF',
        destinationAddress: ALLOWLIST.DESTINATION_ADDRESS,
        amount: '1',
        note: 'x'.repeat(65),
        operatorId: 'op',
        conversationId: 'conv',
        intentId: 'i1',
        payloadHash: 'hash1'
      })
    ).toThrow(/note/);
  });
});

describe('Rate cap', () => {
  let db: Database.Database;

  beforeEach(() => {
    db = initDatabase(':memory:');
  });

  it('allows drafts 1..5 and atomically trips the kill switch on the 5th', () => {
    for (let i = 1; i <= 5; i++) {
      const intent = createIntent(db, {
        operatorId: 'op',
        conversationId: 'conv',
        sourceVaultId: '3',
        assetId: 'FTSEP_B75VRLGX_8YAF',
        destinationAddress: ALLOWLIST.DESTINATION_ADDRESS,
        amount: '1',
        note: null,
        ttlSeconds: 900,
      });
      const r = checkAndRecordRate(db, intent.intent_id, 24, 5);
      expect(r.allowed).toBe(true);
      expect(r.currentCount).toBe(i);
      if (i === 5) expect(r.willTripKillSwitch).toBe(true);
      else expect(r.willTripKillSwitch).toBe(false);
    }
    expect(getDraftingDisabled(db)).toBe(true);
  });

  it('rejects the 6th draft', () => {
    for (let i = 0; i < 5; i++) {
      const intent = createIntent(db, {
        operatorId: 'op',
        conversationId: 'conv',
        sourceVaultId: '3',
        assetId: 'FTSEP_B75VRLGX_8YAF',
        destinationAddress: ALLOWLIST.DESTINATION_ADDRESS,
        amount: '1',
        note: null,
        ttlSeconds: 900,
      });
      checkAndRecordRate(db, intent.intent_id, 24, 5);
    }
    const sixth = createIntent(db, {
      operatorId: 'op',
      conversationId: 'conv',
      sourceVaultId: '3',
      assetId: 'FTSEP_B75VRLGX_8YAF',
      destinationAddress: ALLOWLIST.DESTINATION_ADDRESS,
      amount: '1',
      note: null,
      ttlSeconds: 900,
    });
    const r = checkAndRecordRate(db, sixth.intent_id, 24, 5);
    expect(r.allowed).toBe(false);
    expect(r.currentCount).toBe(5);
  });
});

describe('Kill switch', () => {
  let db: Database.Database;

  beforeEach(() => {
    db = initDatabase(':memory:');
  });

  it('defaults to enabled', () => {
    expect(getDraftingDisabled(db)).toBe(false);
  });

  it('can be activated and deactivated', () => {
    setKillSwitch(db, true);
    expect(getDraftingDisabled(db)).toBe(true);
    setKillSwitch(db, false);
    expect(getDraftingDisabled(db)).toBe(false);
  });
});

describe('Envelope nonce replay protection', () => {
  let db: Database.Database;

  beforeEach(() => {
    db = initDatabase(':memory:');
  });

  it('accepts a fresh nonce', () => {
    expect(recordEnvelopeNonce(db, 'n1')).toBe(true);
  });

  it('rejects a replayed nonce', () => {
    expect(recordEnvelopeNonce(db, 'n1')).toBe(true);
    expect(recordEnvelopeNonce(db, 'n1')).toBe(false);
  });
});
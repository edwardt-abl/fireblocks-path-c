import { describe, it, expect } from 'vitest';
import { canonicalizeIntent } from '../src/crypto.js'; // Adjust if in a different file like crypto.js

describe('Canonicalization matching Python Signer', () => {
  it('should serialize the intent with alphabetically sorted keys and compact separators', () => {
    // Bypass type checking here to simulate an incoming raw JSON payload
    const intent: any = {
      intentId: 'i1',
      operatorId: 'op',
      conversationId: 'conv',
      sourceVaultId: '3',
      assetId: 'FTSEP_B75VRLGX_8YAF',
      destinationAddress: '0x123',
      amount: '5',
      note: 'hello',
      payloadHash: 'hash1'
    };

    // Run the function
    const resultBytes = canonicalizeIntent(intent);
    
    // Decode the Uint8Array back to a string so we can easily compare it
    const resultString = new TextDecoder().decode(resultBytes);
    
    // This is the exact string the AI reported the Python signer produces
    const expected = '{"amount":"5","assetId":"FTSEP_B75VRLGX_8YAF","conversationId":"conv","destinationAddress":"0x123","intentId":"i1","note":"hello","operatorId":"op","payloadHash":"hash1","sourceVaultId":"3"}';

    expect(resultString).toBe(expected);
  });
});
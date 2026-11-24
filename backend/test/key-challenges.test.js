const assert = require('node:assert/strict');
const { createHash, webcrypto } = require('node:crypto');
const { test } = require('node:test');
const { issueKeyChallenge, verifyKeyChallenge } = require('../src/keys/key-challenges');

const userId = '17';
const keyId = 'test-key';
const now = Date.parse('2026-11-23T00:00:00Z');

async function registrationFor(purpose, publicKey) {
  const spki = Buffer.from(await webcrypto.subtle.exportKey('spki', publicKey));
  return {
    userId, keyId, purpose,
    publicKey: spki.toString('base64url'),
    publicKeyFingerprint: createHash('sha256').update(spki).digest('base64url'),
  };
}

// Alphabetical keys match the record canonicalized by the browser's enrollment module.
function proofRecord(challenge) {
  return JSON.stringify({
    expiresAt: challenge.expiresAt,
    keyId: challenge.keyId,
    keyPurpose: challenge.purpose,
    nonce: challenge.nonce,
    purpose: 'key-proof/v1',
    userId: challenge.userId,
  });
}

test('SIGN registration verifies a browser signature bound to the challenged account and key', async () => {
  const pair = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const input = await registrationFor('SIGN', pair.publicKey);
  const issued = issueKeyChallenge(input, now);
  assert.equal(issued.responseHash, null);
  assert.equal(issued.challenge.expiresAt, '2026-11-23T00:05:00.000Z');
  const signed = await webcrypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, Buffer.from(proofRecord(issued.challenge)),
  );
  const proof = { ...issued, publicKey: input.publicKey, response: Buffer.from(signed).toString('base64url') };
  assert.equal(verifyKeyChallenge(proof, now), true);
  assert.equal(verifyKeyChallenge(proof, now + 5 * 60 * 1000), false);
  assert.equal(verifyKeyChallenge({ ...proof, challenge: { ...issued.challenge, userId: '18' } }, now), false);
  assert.equal(verifyKeyChallenge({ ...proof, response: proof.response + '=' }, now), false);
  assert.throws(() => issueKeyChallenge({ ...input, publicKeyFingerprint: 'wrong' }, now), /fingerprint/);
  assert.throws(() => issueKeyChallenge({ ...input, purpose: 'ENC' }, now), /profile/);
});

test('ENC registration verifies the browser response to an RSA-OAEP challenge', async () => {
  const pair = await webcrypto.subtle.generateKey({
    name: 'RSA-OAEP', modulusLength: 3072, publicExponent: Uint8Array.of(1, 0, 1), hash: 'SHA-256',
  }, true, ['encrypt', 'decrypt']);
  const input = await registrationFor('ENC', pair.publicKey);
  const issued = issueKeyChallenge(input, now);
  const label = createHash('sha256').update(proofRecord(issued.challenge)).digest();
  const ciphertext = Buffer.from(issued.challenge.ciphertext, 'base64url');
  assert.equal(ciphertext.length, 384);
  const bytes = await webcrypto.subtle.decrypt({ name: 'RSA-OAEP', label }, pair.privateKey, ciphertext);
  const proof = { ...issued, publicKey: input.publicKey, response: Buffer.from(bytes).toString('base64url') };
  assert.equal(verifyKeyChallenge(proof, now), true);
  assert.equal(verifyKeyChallenge(proof, now + 5 * 60 * 1000), false);
  assert.equal(verifyKeyChallenge({ ...proof, response: Buffer.alloc(32).toString('base64url') }, now), false);
  assert.equal(verifyKeyChallenge({ ...proof, responseHash: null }, now), false);
});

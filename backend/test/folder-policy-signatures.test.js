const assert = require('node:assert/strict');
const { webcrypto } = require('node:crypto');
const { test } = require('node:test');
const canonicalize = require('canonicalize');
const { createFolderPolicyVerifiers } = require('../src/folders/folder-policy-signatures');

test('folder policy accepts browser signatures bound to the owner and the exact policy', async () => {
  const { subtle } = webcrypto;
  const algorithm = { name: 'ECDSA', namedCurve: 'P-256' };
  const signAlgorithm = { name: 'ECDSA', hash: 'SHA-256' };
  const { publicKey, privateKey } = await subtle.generateKey(algorithm, true, ['sign', 'verify']);
  const ownerJwk = await subtle.exportKey('jwk', publicKey);
  async function sign(payload) {
    return Buffer.from(await subtle.sign(signAlgorithm, privateKey, Buffer.from(canonicalize(payload)))).toString('base64url');
  }

  let active = true;
  let eligible = true;
  const { verifyInitialFolderPolicy, verifyFolderPolicy } = createFolderPolicyVerifiers({
    lookupActiveSigningKey: async (_connection, userId) => active && userId === '7' ? ownerJwk : null,
    canReceiveFolderKeys: async () => eligible,
  });
  const folder = { folderId: 'folder-a', name: 'Test', patientRef: 'p1', treatmentReference: 'e1' };
  const payload = {
    purpose: 'INITIAL_FOLDER_POLICY', folder, ownerId: '7', policyVersion: 1,
    members: [{ userId: '7', role: 'OWNER' }],
  };
  const input = { folder, ownerId: '7', policyVersion: 1, signedPolicy: { payload, signature: await sign(payload) } };
  assert.equal(await verifyInitialFolderPolicy(input), true);
  assert.equal(await verifyInitialFolderPolicy({ ...input, folder: { ...folder, name: 'Changed' } }), false);

  const context = { ownerId: '7', folderId: 'folder-a', action: 'ADD_MEMBER', target: { userId: '8', role: 'VIEWER' } };
  const ownerSignature = await sign({ purpose: 'FOLDER_MEMBERSHIP_CHANGE', context });
  const change = { ownerId: '7', context, ownerSignature };
  assert.equal(await verifyFolderPolicy(change), true);
  assert.equal(await verifyFolderPolicy({ ...change, context: { ...context, folderId: 'folder-b' } }), false);
  eligible = false;
  assert.equal(await verifyFolderPolicy(change), false);
  eligible = true;
  active = false;
  assert.equal(await verifyFolderPolicy(change), false);
});

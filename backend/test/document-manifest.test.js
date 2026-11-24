const assert = require('node:assert/strict');
const { randomBytes, randomUUID } = require('node:crypto');
const { test } = require('node:test');
const { verifyDocumentUpload } = require('../src/documents/document-manifest');
const { createSignedUpload, createSigner, createUploadContextFixture, sha256Hex } = require('./helpers/document-fixtures');

async function validUpload() {
  const signer = await createSigner();
  const context = createUploadContextFixture();
  const upload = await createSignedUpload(context, signer);
  const input = {
    context,
    manifest: upload.manifest,
    signature: upload.signature,
    envelopes: upload.envelopes,
    signerPublicJwk: signer.publicKeyJwk,
    ciphertext: { sha256: sha256Hex(upload.ciphertext), size: upload.ciphertext.length },
  };
  return { context, input };
}

test('upload evidence that matches the issued context is accepted', async () => {
  const { context, input } = await validUpload();
  const result = verifyDocumentUpload(input);
  assert.equal(result.code, undefined);
  assert.equal(result.nonce.length, 12);
  assert.deepEqual(
    result.envelopes.map(({ userId, membershipId, keyId, wrappedDek }) => [userId, membershipId, keyId, wrappedDek.length]),
    context.recipients.map(({ userId, membershipId, keyId }) => [userId, membershipId, keyId, 384]),
  );
  const reordered = verifyDocumentUpload({ ...input, envelopes: [...input.envelopes].reverse() });
  assert.equal(reordered.code, undefined);
});

test('manifest fields bound to the context or profile cannot change', async () => {
  const { input } = await validUpload();
  const { manifest } = input;
  const bound = {
    purpose: 'OTHER', contextId: randomUUID(), folderId: randomUUID(), documentId: randomUUID(),
    versionId: randomUUID(), revisionId: randomUUID(), versionNumber: 2, baseVersionId: randomUUID(),
    policyVersion: 4, actorUserId: '9', signerKeyId: randomUUID(),
  };
  for (const [field, value] of Object.entries(bound)) {
    assert.equal(verifyDocumentUpload({ ...input, manifest: { ...manifest, [field]: value } }).code, 'MANIFEST_MISMATCH', field);
  }
  const { authorRecordSha256, ...missingField } = manifest;
  assert.ok(authorRecordSha256);
  const variants = [
    missingField,
    { ...manifest, extra: true },
    { ...manifest, aead: { alg: 'AES-128-GCM', nonce: manifest.aead.nonce } },
    { ...manifest, aead: { alg: 'AES-256-GCM', nonce: randomBytes(11).toString('base64url') } },
    { ...manifest, aead: { ...manifest.aead, nonce: manifest.aead.nonce + '=' } },
    { ...manifest, ciphertextSha256: 'A'.repeat(64) },
    { ...manifest, authorRecordSha256: 42 },
    { ...manifest, ciphertextSize: 15 },
    { ...manifest, recipients: [...manifest.recipients].reverse() },
    { ...manifest, recipients: manifest.recipients.slice(1) },
    { ...manifest, recipients: [manifest.recipients[0], { ...manifest.recipients[1], keyId: randomUUID() }] },
  ];
  for (const variant of variants) {
    assert.equal(verifyDocumentUpload({ ...input, manifest: variant }).code, 'MANIFEST_MISMATCH');
  }
  assert.equal(verifyDocumentUpload({ ...input, ciphertext: { ...input.ciphertext, size: input.ciphertext.size + 1 } }).code, 'CIPHERTEXT_HASH_MISMATCH');
  assert.equal(verifyDocumentUpload({ ...input, ciphertext: { ...input.ciphertext, sha256: sha256Hex('other') } }).code, 'CIPHERTEXT_HASH_MISMATCH');
});

test('the signature must come from the signer key over the exact manifest', async () => {
  const { input } = await validUpload();
  const other = await createSigner();
  assert.equal(verifyDocumentUpload({ ...input, signerPublicJwk: other.publicKeyJwk }).code, 'INVALID_SIGNATURE');
  assert.equal(verifyDocumentUpload({ ...input, signerPublicJwk: { ...input.signerPublicJwk, d: 'secret' } }).code, 'INVALID_SIGNATURE');
  const changed = { ...input.manifest, authorRecordSha256: sha256Hex('other') };
  assert.equal(verifyDocumentUpload({ ...input, manifest: changed }).code, 'INVALID_SIGNATURE');
  const standardBase64 = Buffer.from(input.signature, 'base64url').toString('base64');
  for (const signature of [input.signature + 'A', input.signature.slice(1), standardBase64, 42]) {
    assert.equal(verifyDocumentUpload({ ...input, signature }).code, 'INVALID_SIGNATURE');
  }
});

test('every current recipient gets exactly one well-formed envelope', async () => {
  const { input } = await validUpload();
  const [first, second] = input.envelopes;
  const variants = [
    [first],
    [first, second, { ...second, userId: '11' }],
    [first, { ...first }],
    [first, { ...second, keyId: randomUUID() }],
    [first, { ...second, wrappedDek: randomBytes(384).toString('base64url') }],
    [first, { ...second, wrappedDek: randomBytes(383).toString('base64url') }],
    [first, { ...second, wrappedDek: randomBytes(385).toString('base64url') }],
    [first, { ...second, extra: 1 }],
    'not-an-array',
  ];
  for (const envelopes of variants) {
    assert.equal(verifyDocumentUpload({ ...input, envelopes }).code, 'RECIPIENTS_MISMATCH');
  }
});

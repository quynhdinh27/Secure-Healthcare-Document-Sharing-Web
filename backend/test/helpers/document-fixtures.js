// Shared fixtures for document tests: a browser-style ECDSA signer and a
// signed upload that matches an issued upload context.
const { createHash, randomBytes, randomUUID, webcrypto } = require('node:crypto');
const canonicalize = require('canonicalize');

const { subtle } = webcrypto;

function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}

async function createSigner() {
  const { publicKey, privateKey } = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const { kty, crv, x, y } = await subtle.exportKey('jwk', publicKey);
  return {
    publicKeyJwk: { kty, crv, x, y },
    async sign(payload) {
      const signature = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, Buffer.from(canonicalize(payload)));
      return Buffer.from(signature).toString('base64url');
    },
  };
}

function createUploadContextFixture(overrides = {}) {
  return {
    contextId: randomUUID(),
    purpose: 'NEW_DOCUMENT',
    folderId: randomUUID(),
    userId: '7',
    documentId: randomUUID(),
    versionId: randomUUID(),
    revisionId: randomUUID(),
    versionNumber: 1,
    baseVersionId: null,
    policyVersion: 3,
    signerKeyId: randomUUID(),
    recipients: [
      { userId: '7', membershipId: '70', keyId: randomUUID(), fingerprint: 'a'.repeat(64) },
      { userId: '9', membershipId: '90', keyId: randomUUID(), fingerprint: 'b'.repeat(64) },
    ],
    ...overrides,
  };
}

async function createSignedUpload(context, signer, ciphertext = randomBytes(64)) {
  const envelopes = context.recipients.map(({ userId, keyId }) => ({
    userId, keyId, wrappedDek: randomBytes(384).toString('base64url'),
  }));
  const manifest = {
    purpose: 'DOCUMENT_VERSION_UPLOAD',
    contextId: context.contextId,
    folderId: context.folderId,
    documentId: context.documentId,
    versionId: context.versionId,
    revisionId: context.revisionId,
    versionNumber: context.versionNumber,
    baseVersionId: context.baseVersionId,
    policyVersion: context.policyVersion,
    actorUserId: context.userId,
    signerKeyId: context.signerKeyId,
    aead: { alg: 'AES-256-GCM', nonce: randomBytes(12).toString('base64url') },
    ciphertextSha256: sha256Hex(ciphertext),
    ciphertextSize: ciphertext.length,
    authorRecordSha256: sha256Hex('author-record'),
    recipients: envelopes.map(({ userId, keyId, wrappedDek }) => ({
      userId, keyId, wrappedDekSha256: sha256Hex(Buffer.from(wrappedDek, 'base64url')),
    })),
  };
  return { ciphertext, manifest, envelopes, signature: await signer.sign(manifest) };
}

module.exports = { createSignedUpload, createSigner, createUploadContextFixture, sha256Hex };

// Plays the browser for documents: AES-256-GCM encryption, RSA-OAEP DEK envelopes,
// ECDSA-signed CryptoManifest (spec 7.4), and the reverse path for downloads.
const assert = require('node:assert/strict');
const { createHash, webcrypto } = require('node:crypto');
const canonicalize = require('canonicalize');
const { signPayload } = require('./dev-accounts.cjs');

const { subtle } = webcrypto;
const RSA_OAEP = { name: 'RSA-OAEP', hash: 'SHA-256' };

function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}

function aadFor({ folderId, documentId, versionId, revisionId }) {
  return Buffer.from(canonicalize({ purpose: 'DOCUMENT_VERSION_UPLOAD', folderId, documentId, versionId, revisionId }));
}

function oaepLabelFor({ folderId, documentId, versionId, revisionId }, recipientKeyId) {
  return Buffer.from(canonicalize({ purpose: 'DEK_ENVELOPE', folderId, documentId, versionId, revisionId, recipientKeyId }));
}

async function prepareUpload({ context, author, plaintext, documentName, category, mimeType, sourceManifest }) {
  const dek = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const nonce = webcrypto.getRandomValues(new Uint8Array(12));
  const ciphertext = Buffer.from(await subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aadFor(context), tagLength: 128 }, dek, plaintext,
  ));
  const rawDek = await subtle.exportKey('raw', dek);
  const envelopes = [];
  for (const recipient of context.recipients) {
    const publicKey = await subtle.importKey('jwk', recipient.publicKeyJwk, RSA_OAEP, false, ['encrypt']);
    const wrapped = await subtle.encrypt({ name: 'RSA-OAEP', label: oaepLabelFor(context, recipient.keyId) }, publicKey, rawDek);
    envelopes.push({ userId: recipient.userId, keyId: recipient.keyId, wrappedDek: Buffer.from(wrapped).toString('base64url') });
  }
  // In the real client the AuthorRecord travels inside the encrypted container.
  const authorRecord = {
    documentId: context.documentId, versionId: context.versionId, baseVersionId: context.baseVersionId,
    authorUserId: author.userId, authorKeyId: author.keys.signing.keyId,
    policyVersion: context.policyVersion, plaintextSha256: sha256Hex(plaintext),
  };
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
    actorUserId: author.userId,
    signerKeyId: context.signerKeyId,
    aead: { alg: 'AES-256-GCM', nonce: Buffer.from(nonce).toString('base64url') },
    ciphertextSha256: sha256Hex(ciphertext),
    ciphertextSize: ciphertext.length,
    authorRecordSha256: sha256Hex(canonicalize(authorRecord)),
    recipients: envelopes.map(({ userId, keyId, wrappedDek }) => ({
      userId, keyId, wrappedDekSha256: sha256Hex(Buffer.from(wrappedDek, 'base64url')),
    })),
  };
  if (sourceManifest) {
    Object.assign(manifest, {
      purpose: 'DOCUMENT_ROTATION_RESULT',
      generation: context.generation,
      sourceRevisionId: sourceManifest.revisionId,
      sourceManifestSha256: sha256Hex(canonicalize(sourceManifest)),
      authorRecordSha256: sourceManifest.authorRecordSha256,
    });
  }
  const signature = await signPayload(author.keys.signing.privateJwk, manifest);
  const form = new FormData();
  form.append('metadata', JSON.stringify({ contextId: context.contextId, documentName, category, mimeType, manifest, signature, envelopes }));
  form.append('ciphertext', new Blob([ciphertext]), 'ciphertext.bin');
  return { form, ciphertext, manifest };
}

async function downloadAndDecrypt({ call, user, versionId }) {
  const evidence = await call(`/versions/${versionId}/manifest`, user.userId, 200);
  const { data } = await call(`/versions/${versionId}/content?revisionId=${evidence.revisionId}`, user.userId, 200, { raw: true });
  return verifyAndDecrypt(evidence, data, user);
}

async function verifyAndDecrypt(evidence, data, user) {
  const signerKey = await subtle.importKey('jwk', evidence.signer.publicKeyJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const validSignature = await subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' }, signerKey,
    Buffer.from(evidence.signature, 'base64url'), Buffer.from(canonicalize(evidence.manifest)),
  );
  assert.equal(validSignature, true, 'manifest signature verifies');
  const privateKey = await subtle.importKey('jwk', user.keys.encryption.privateJwk, RSA_OAEP, false, ['decrypt']);
  const rawDek = await subtle.decrypt(
    { name: 'RSA-OAEP', label: oaepLabelFor(evidence.manifest, evidence.envelope.keyId) },
    privateKey, Buffer.from(evidence.envelope.wrappedDek, 'base64url'),
  );
  const dek = await subtle.importKey('raw', rawDek, 'AES-GCM', false, ['decrypt']);
  assert.equal(sha256Hex(data), evidence.manifest.ciphertextSha256, 'ciphertext hash matches the manifest');
  return Buffer.from(await subtle.decrypt({
    name: 'AES-GCM', iv: Buffer.from(evidence.manifest.aead.nonce, 'base64url'),
    additionalData: aadFor(evidence.manifest), tagLength: 128,
  }, dek, data));
}

module.exports = { downloadAndDecrypt, prepareUpload, sha256Hex, verifyAndDecrypt };

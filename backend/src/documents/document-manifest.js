const { createHash, createPublicKey, verify } = require('node:crypto');
const canonicalize = require('canonicalize');

// Pure checks of the signed CryptoManifest and DEK envelopes against an issued
// upload context (spec section 7.3-7.4). No database access.
const MANIFEST_PURPOSE = 'DOCUMENT_VERSION_UPLOAD';
const WRAPPED_DEK_BYTES = 384;
const NONCE_BYTES = 12;
const GCM_TAG_BYTES = 16;
const manifestKeys = [
  'purpose', 'contextId', 'folderId', 'documentId', 'versionId', 'revisionId', 'versionNumber',
  'baseVersionId', 'policyVersion', 'actorUserId', 'signerKeyId', 'aead', 'ciphertextSha256',
  'ciphertextSize', 'authorRecordSha256', 'recipients',
];

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(value, keys) {
  return isPlainObject(value) && Object.keys(value).length === keys.length
    && keys.every((key) => Object.hasOwn(value, key));
}

function isSha256Hex(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function decodeBase64url(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const bytes = Buffer.from(value, 'base64url');
  return bytes.toString('base64url') === value ? bytes : null;
}

function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}

function contextBoundFields(context) {
  return {
    purpose: MANIFEST_PURPOSE,
    contextId: context.contextId,
    folderId: context.folderId,
    documentId: context.documentId,
    versionId: context.versionId,
    revisionId: context.revisionId,
    versionNumber: Number(context.versionNumber),
    baseVersionId: context.baseVersionId ?? null,
    policyVersion: Number(context.policyVersion),
    actorUserId: context.userId,
    signerKeyId: context.signerKeyId,
  };
}

function checkManifest(context, manifest) {
  const mismatch = { code: 'MANIFEST_MISMATCH' };
  if (!hasExactKeys(manifest, manifestKeys)) return mismatch;
  const bound = contextBoundFields(context);
  if (Object.entries(bound).some(([key, value]) => manifest[key] !== value)) return mismatch;
  if (!hasExactKeys(manifest.aead, ['alg', 'nonce']) || manifest.aead.alg !== 'AES-256-GCM') return mismatch;
  const nonce = decodeBase64url(manifest.aead.nonce);
  if (!nonce || nonce.length !== NONCE_BYTES) return mismatch;
  if (!isSha256Hex(manifest.ciphertextSha256) || !isSha256Hex(manifest.authorRecordSha256)) return mismatch;
  if (!Number.isSafeInteger(manifest.ciphertextSize) || manifest.ciphertextSize < GCM_TAG_BYTES) return mismatch;
  const { recipients } = context;
  if (!Array.isArray(manifest.recipients) || manifest.recipients.length !== recipients.length) return mismatch;
  const recipientsMatch = manifest.recipients.every((entry, index) => (
    hasExactKeys(entry, ['userId', 'keyId', 'wrappedDekSha256'])
    && entry.userId === recipients[index].userId
    && entry.keyId === recipients[index].keyId
    && isSha256Hex(entry.wrappedDekSha256)
  ));
  return recipientsMatch ? { nonce } : mismatch;
}

// Same profile as src/folders/folder-policy-signatures.js (not exported there).
function verifyManifestSignature(publicJwk, manifest, signature) {
  if (publicJwk?.kty !== 'EC' || publicJwk.crv !== 'P-256' || publicJwk.d !== undefined
      || typeof signature !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(signature)) {
    return false;
  }
  const bytes = Buffer.from(signature, 'base64url');
  if (bytes.length !== 64 || bytes.toString('base64url') !== signature) return false;
  try {
    const key = createPublicKey({ key: publicJwk, format: 'jwk' });
    return verify('sha256', Buffer.from(canonicalize(manifest), 'utf8'), { key, dsaEncoding: 'ieee-p1363' }, bytes);
  } catch {
    return false;
  }
}

function checkEnvelopes(context, manifest, envelopes) {
  const mismatch = { code: 'RECIPIENTS_MISMATCH' };
  if (!Array.isArray(envelopes) || envelopes.length !== context.recipients.length) return mismatch;
  const byUser = new Map();
  for (const envelope of envelopes) {
    if (!hasExactKeys(envelope, ['userId', 'keyId', 'wrappedDek']) || typeof envelope.userId !== 'string'
        || byUser.has(envelope.userId)) {
      return mismatch;
    }
    byUser.set(envelope.userId, envelope);
  }
  const accepted = [];
  for (const [index, recipient] of context.recipients.entries()) {
    const envelope = byUser.get(recipient.userId);
    const wrappedDek = decodeBase64url(envelope?.wrappedDek);
    if (!envelope || envelope.keyId !== recipient.keyId || !wrappedDek
        || wrappedDek.length !== WRAPPED_DEK_BYTES
        || sha256Hex(wrappedDek) !== manifest.recipients[index].wrappedDekSha256) {
      return mismatch;
    }
    accepted.push({ userId: recipient.userId, membershipId: recipient.membershipId, keyId: recipient.keyId, wrappedDek });
  }
  return { envelopes: accepted };
}

function verifyDocumentUpload({ context, manifest, signature, envelopes, signerPublicJwk, ciphertext }) {
  const checked = checkManifest(context, manifest);
  if (checked.code) return checked;
  if (manifest.ciphertextSha256 !== ciphertext?.sha256 || manifest.ciphertextSize !== ciphertext?.size) {
    return { code: 'CIPHERTEXT_HASH_MISMATCH' };
  }
  if (!verifyManifestSignature(signerPublicJwk, manifest, signature)) return { code: 'INVALID_SIGNATURE' };
  const accepted = checkEnvelopes(context, manifest, envelopes);
  if (accepted.code) return accepted;
  return { nonce: checked.nonce, envelopes: accepted.envelopes };
}

module.exports = { MANIFEST_PURPOSE, WRAPPED_DEK_BYTES, verifyDocumentUpload };

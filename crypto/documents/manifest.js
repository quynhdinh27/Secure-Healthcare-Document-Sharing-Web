import { base64url, canonicalBytes, fromBase64url, requiredStrings } from '../encoding.js'
import { encryptAesGcm, generateDek } from '../primitives/aes-gcm.js'
import { importSigningKey, signRecord, verifyRecord } from '../primitives/ecdsa.js'
import { hashBytes } from '../primitives/sha256.js'
import { createEnvelopes, suiteId } from './envelope.js'

export const uploadPurpose = 'document-upload/v1'
export const updatePurpose = 'document-version/v1'
export const rotationPurpose = 'rotation-item/v1'
const documentIds = ['folderId', 'documentId', 'versionId']
const revisionIds = [...documentIds, 'cryptoRevisionId', 'keySessionId']
const contextFields = [...revisionIds, 'policyHash', 'keyRegistryRevision']

function select(record, fields) {
  return Object.fromEntries(fields.map(field => [field, record[field]]))
}

export function documentAad(record) {
  return canonicalBytes({
    purpose: 'document-content/v1', suiteId, ...select(record, revisionIds),
    authorRecordHash: record.authorRecordHash
  })
}

export async function sealContainer({ container, authorRecordHash, context, signer, operation }) {
  requiredStrings(context, contextFields)
  requiredStrings(signer, ['userId', 'keyId'])
  const record = {
    ...operation, ...select(context, contextFields), suiteId, authorRecordHash,
    actorUserId: signer.userId, actorSigningKeyId: signer.keyId
  }
  const dek = await generateDek()
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const aad = documentAad(record)
  const ciphertext = await encryptAesGcm(dek, nonce, aad, container)
  const { envelopes, recipientCommitments } = await createEnvelopes(dek, record, context.recipients)
  const signedManifest = await signRecord({
    ...record, nonce: base64url(nonce), aad: base64url(aad),
    ciphertextHash: await hashBytes(ciphertext), recipientCommitments
  }, signer.privateKey)
  return { ciphertext, envelopes, signedManifest }
}

export function assertSameFields(actual, expected, fields, message) {
  for (const field of fields) {
    if (actual[field] !== expected[field]) throw new Error(message + ': ' + field)
  }
}

export async function verifyBoundSignature(signed, userId, keyId, trust, usage) {
  requiredStrings({ userId, keyId }, ['userId', 'keyId'])
  const spki = await trust.resolveSigningKey({ userId, keyId, usage })
  await verifyRecord(signed, await importSigningKey('spki', fromBase64url(spki)))
}

export async function verifyManifest(signed, expected, trust, policyProof) {
  const { record } = signed
  requiredStrings(record, [...contextFields, 'authorRecordHash', 'ciphertextHash', 'nonce', 'aad'])
  requiredStrings(expected, contextFields)
  assertSameFields(record, expected, contextFields, 'Unexpected crypto context')
  if (record.suiteId !== suiteId || record.purpose !== expected.purpose ||
      ![uploadPurpose, updatePurpose, rotationPurpose].includes(record.purpose)) {
    throw new Error('Unexpected manifest suite or purpose')
  }
  if (record.purpose === rotationPurpose) {
    requiredStrings(record, ['rotationId', 'itemId', 'generation', 'sourceCryptoRevisionId', 'sourceCryptoManifestHash'])
    requiredStrings(expected, ['rotationId', 'itemId', 'generation'])
    assertSameFields(record, expected, ['rotationId', 'itemId', 'generation'], 'Unexpected rotation context')
  } else {
    requiredStrings(record, ['contextId'])
    if (record.purpose === updatePurpose) requiredStrings(record, ['baseVersionId'])
    if (record.purpose === uploadPurpose && record.baseVersionId !== null) throw new Error('Unexpected base version')
  }
  await verifyBoundSignature(signed, record.actorUserId, record.actorSigningKeyId, trust, record.purpose)
  if (await trust.verifyPolicyProof({ record: structuredClone(record), policyProof }) !== true) throw new Error('Invalid policy proof')
  if (record.aad !== base64url(documentAad(record))) throw new Error('Invalid manifest AAD')
  return record
}

export async function verifyOriginalManifest(original, revision, trust, originalPolicyProof) {
  const { record } = original
  assertSameFields(record, revision, [...documentIds, 'authorRecordHash'], 'Original manifest mismatch')
  if (![uploadPurpose, updatePurpose].includes(record.purpose) || record.suiteId !== suiteId) {
    throw new Error('Expected original upload/version manifest')
  }
  await verifyBoundSignature(original, record.actorUserId, record.actorSigningKeyId, trust, record.purpose)
  if (await trust.verifyPolicyProof({ record: structuredClone(record), policyProof: originalPolicyProof }) !== true) {
    throw new Error('Invalid original policy proof')
  }
  return record
}

import { base64url, canonicalBytes, fromBase64url, requiredStrings } from '../encoding.js'
import { importEncryptionKey, unwrapDek, wrapDek } from '../primitives/rsa-oaep.js'
import { hashRecord, sha256 } from '../primitives/sha256.js'

export const suiteId = 'AES-256-GCM+RSA-OAEP-3072-SHA256+ECDSA-P256-SHA256/v1'

function label(scope, recipientEncryptionKeyId) {
  const { folderId, versionId, cryptoRevisionId, keySessionId } = scope
  return sha256(canonicalBytes({
    purpose: 'dek-envelope/v1', folderId, versionId, cryptoRevisionId, keySessionId, recipientEncryptionKeyId
  }))
}

export async function createEnvelopes(dek, scope, recipients) {
  if (!Array.isArray(recipients) || !recipients.length) throw new Error('Recipients required')
  const memberships = new Set()
  const envelopes = []
  const recipientCommitments = []
  for (const recipient of [...recipients].sort((a, b) =>
    a.membershipId < b.membershipId ? -1 : Number(a.membershipId > b.membershipId)
  )) {
    requiredStrings(recipient, ['membershipId', 'recipientEncryptionKeyId', 'publicKey'])
    const { membershipId, recipientEncryptionKeyId, publicKey } = recipient
    if (memberships.has(membershipId)) throw new Error('Duplicate recipient')
    memberships.add(membershipId)
    const key = await importEncryptionKey('spki', fromBase64url(publicKey))
    const wrapped = await wrapDek(dek, key, await label(scope, recipientEncryptionKeyId))
    const envelope = {
      cryptoRevisionId: scope.cryptoRevisionId, membershipId, recipientEncryptionKeyId,
      suiteId, wrappedDek: base64url(wrapped)
    }
    envelopes.push(envelope)
    recipientCommitments.push({ membershipId, recipientEncryptionKeyId, envelopeHash: await hashRecord(envelope) })
  }
  return { envelopes, recipientCommitments }
}

export async function unwrapOwnEnvelope(scope, envelope, recipient) {
  const { membershipId, recipientEncryptionKeyId, privateKey } = recipient
  requiredStrings(recipient, ['membershipId', 'recipientEncryptionKeyId'])
  if (envelope.membershipId !== membershipId || envelope.recipientEncryptionKeyId !== recipientEncryptionKeyId ||
      envelope.cryptoRevisionId !== scope.cryptoRevisionId || envelope.suiteId !== suiteId) {
    throw new Error('Envelope does not match recipient or revision')
  }
  const commitments = scope.recipientCommitments.filter(item => item.membershipId === membershipId)
  if (commitments.length !== 1 || commitments[0].recipientEncryptionKeyId !== recipientEncryptionKeyId ||
      commitments[0].envelopeHash !== await hashRecord(envelope)) {
    throw new Error('Envelope commitment mismatch')
  }
  const wrapped = fromBase64url(envelope.wrappedDek)
  if (wrapped.length !== 384) throw new Error('Invalid wrapped DEK length')
  return unwrapDek(wrapped, privateKey, await label(scope, recipientEncryptionKeyId))
}

import { fromBase64url, requiredStrings } from '../encoding.js'
import { importSigningKey, signRecord, verifyRecord } from '../primitives/ecdsa.js'

export function signFolderPolicy({ context, signer }) {
  requiredStrings(context, ['folderId', 'contextId', 'action', 'nonce', 'expiresAt'])
  requiredStrings(signer, ['userId', 'keyId'])
  if (!(Date.parse(context.expiresAt) > Date.now())) throw new Error('Policy context expired')
  return signRecord({
    purpose: 'folder-policy/v1', context, actorUserId: signer.userId, actorSigningKeyId: signer.keyId
  }, signer.privateKey)
}

export function signInitialFolderPolicy({ folderId, policy, signer }) {
  requiredStrings({ folderId }, ['folderId'])
  requiredStrings(signer, ['userId', 'keyId'])
  return signRecord({
    purpose: 'initial-folder-policy/v1', folderId, policy,
    actorUserId: signer.userId, actorSigningKeyId: signer.keyId
  }, signer.privateKey)
}

export async function verifyFolderPolicy({ signedPolicy, trustedOwner }) {
  requiredStrings(trustedOwner, ['userId', 'keyId', 'publicKey', 'folderId'])
  const { record } = signedPolicy
  const folderId = record.purpose === 'initial-folder-policy/v1' ? record.folderId : record.context?.folderId
  if (folderId !== trustedOwner.folderId || record.actorUserId !== trustedOwner.userId ||
      record.actorSigningKeyId !== trustedOwner.keyId ||
      !['folder-policy/v1', 'initial-folder-policy/v1'].includes(record.purpose)) {
    throw new Error('Policy signer or scope mismatch')
  }
  await verifyRecord(signedPolicy, await importSigningKey('spki', fromBase64url(trustedOwner.publicKey)))
}

import { requiredStrings } from '../encoding.js'
import { openVerifiedContainer } from '../documents/download.js'
import { rotationPurpose } from '../documents/manifest.js'
import { signRecord } from '../primitives/ecdsa.js'

export async function prepareRotationCommit({ job: rotationJob, items, signer, recipient, trust }) {
  const job = structuredClone(rotationJob)
  requiredStrings(job, ['rotationId', 'generation', 'folderId', 'keySessionId', 'policyHash', 'keyRegistryRevision'])
  requiredStrings(signer, ['userId', 'keyId'])
  if (!Array.isArray(job.itemIds) || !Array.isArray(items) || items.length !== job.itemIds.length ||
      new Set(job.itemIds).size !== job.itemIds.length ||
      job.itemIds.some(id => typeof id !== 'string' || !id)) {
    throw new Error('Incomplete rotation item set')
  }

  const staged = new Map(items.map(item => [item.expected.itemId, item]))
  const results = []
  for (const itemId of [...job.itemIds].sort()) {
    const item = staged.get(itemId)
    if (!item) throw new Error('Missing staged rotation item')
    const { rotationId, generation, folderId, keySessionId, policyHash, keyRegistryRevision } = job
    const expected = {
      ...item.expected, purpose: rotationPurpose, rotationId, generation,
      folderId, keySessionId, policyHash, keyRegistryRevision
    }
    requiredStrings(item.expected, ['sourceCryptoRevisionId', 'sourceCryptoManifestHash', 'authorRecordHash'])
    const opened = await openVerifiedContainer({ bundle: item.bundle, expected, recipient, trust })
    try {
      for (const field of ['sourceCryptoRevisionId', 'sourceCryptoManifestHash', 'authorRecordHash']) {
        if (opened.manifest[field] !== item.expected[field]) throw new Error('Staged source mismatch: ' + field)
      }
      results.push({ itemId, cryptoRevisionId: opened.manifest.cryptoRevisionId, manifestHash: opened.manifestHash })
    } finally {
      opened.container.fill(0)
    }
  }
  const { rotationId, generation, folderId, keySessionId, policyHash, keyRegistryRevision } = job
  return signRecord({
    purpose: 'rotation-commit/v1', rotationId, generation, folderId, keySessionId, policyHash,
    keyRegistryRevision, actorUserId: signer.userId, actorSigningKeyId: signer.keyId, results
  }, signer.privateKey)
}

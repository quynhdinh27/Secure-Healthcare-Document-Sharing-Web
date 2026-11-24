import { requiredStrings } from '../encoding.js'
import { openVerifiedContainer } from '../documents/download.js'
import { assertSameFields, rotationPurpose, sealContainer } from '../documents/manifest.js'

export async function prepareRotationItem({ source, expectedSource, target: rotationTarget, recipient, signer, trust }) {
  const target = structuredClone(rotationTarget)
  requiredStrings(target, ['rotationId', 'generation', 'itemId', 'cryptoRevisionId'])
  const opened = await openVerifiedContainer({ bundle: source, expected: expectedSource, recipient, trust })
  try {
    const { manifest, container } = opened
    assertSameFields(manifest, target, ['folderId', 'documentId', 'versionId'], 'Rotation changed business version')
    if (manifest.cryptoRevisionId === target.cryptoRevisionId || manifest.keySessionId === target.keySessionId) {
      throw new Error('Rotation requires a fresh revision and key session')
    }
    const operation = {
      purpose: rotationPurpose, rotationId: target.rotationId, itemId: target.itemId, generation: target.generation,
      sourceCryptoRevisionId: manifest.cryptoRevisionId, sourceCryptoManifestHash: opened.manifestHash
    }
    return await sealContainer({ container, authorRecordHash: manifest.authorRecordHash, context: target, signer, operation })
  } finally {
    opened.container.fill(0)
  }
}

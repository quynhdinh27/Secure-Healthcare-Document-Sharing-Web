import { bytes, fromBase64url } from '../encoding.js'
import { decryptAesGcm } from '../primitives/aes-gcm.js'
import { hashBytes, hashRecord } from '../primitives/sha256.js'
import { unpackContainer } from './author-record.js'
import { unwrapOwnEnvelope } from './envelope.js'
import {
  documentAad, rotationPurpose, verifyBoundSignature, verifyManifest, verifyOriginalManifest
} from './manifest.js'

export async function openVerifiedContainer({ bundle, expected, recipient, trust }) {
  const { ciphertext: receivedCiphertext, ...evidence } = bundle
  const { signedManifest, policyProof, envelope, originalManifest, originalPolicyProof } = structuredClone(evidence)
  const ciphertext = bytes(receivedCiphertext).slice()
  const ownKey = { ...recipient }
  const manifest = await verifyManifest(signedManifest, expected, trust, policyProof)
  const original = manifest.purpose === rotationPurpose
    ? await verifyOriginalManifest(originalManifest, manifest, trust, originalPolicyProof)
    : manifest
  if (await hashBytes(ciphertext) !== manifest.ciphertextHash) throw new Error('Ciphertext hash mismatch')
  const key = await unwrapOwnEnvelope(manifest, envelope, ownKey)
  const container = new Uint8Array(await decryptAesGcm(
    key, fromBase64url(manifest.nonce), documentAad(manifest), ciphertext
  ))
  try {
    const { file, metadata, authorRecord } = unpackContainer(container)
    if (await hashRecord(authorRecord) !== original.authorRecordHash) throw new Error('Author record hash mismatch')
    const author = authorRecord.record
    if (author.purpose !== 'author-record/v1' || author.documentId !== original.documentId ||
        author.versionId !== original.versionId || author.authorUserId !== original.actorUserId ||
        author.authorSigningKeyId !== original.actorSigningKeyId || author.baseVersionId !== original.baseVersionId ||
        author.creationPolicyHash !== original.policyHash) {
      throw new Error('Author record binding mismatch')
    }
    await verifyBoundSignature(authorRecord, author.authorUserId, author.authorSigningKeyId, trust, 'author-record/v1')
    if (await hashBytes(file) !== author.contentHash || await hashRecord(metadata) !== author.metadataHash) {
      throw new Error('Document content or metadata hash mismatch')
    }
    return { container, file, metadata, author, manifest, manifestHash: await hashRecord(signedManifest) }
  } catch (error) {
    container.fill(0)
    throw error
  }
}

export async function openDocument(options) {
  const opened = await openVerifiedContainer(options)
  try {
    return {
      file: opened.file.slice(), metadata: opened.metadata,
      authorUserId: opened.author.authorUserId, versionId: opened.author.versionId
    }
  } finally {
    opened.container.fill(0)
  }
}

import { bytes, canonicalBytes, text } from '../encoding.js'
import { signRecord } from '../primitives/ecdsa.js'
import { hashBytes, hashRecord } from '../primitives/sha256.js'

export async function createAuthorRecord(file, metadata, target, signer) {
  return signRecord({
    purpose: 'author-record/v1', documentId: target.documentId, versionId: target.versionId,
    authorUserId: signer.userId, authorSigningKeyId: signer.keyId,
    baseVersionId: target.baseVersionId, creationPolicyHash: target.policyHash,
    contentHash: await hashBytes(file), metadataHash: await hashRecord(metadata)
  }, signer.privateKey)
}

export function packContainer(file, metadata, authorRecord) {
  const header = canonicalBytes({ format: 'medshare-document/v1', metadata, authorRecord })
  if (header.length > 1048576) throw new RangeError('Document metadata exceeds 1 MiB')
  const output = new Uint8Array(4 + header.length + file.byteLength)
  new DataView(output.buffer).setUint32(0, header.length)
  output.set(header, 4)
  output.set(file, 4 + header.length)
  return output
}

export function unpackContainer(container) {
  const data = bytes(container)
  if (data.length < 4) throw new Error('Invalid encrypted container')
  const headerLength = new DataView(data.buffer, data.byteOffset, data.byteLength).getUint32(0)
  if (headerLength < 2 || headerLength > 1048576 || headerLength > data.length - 4) {
    throw new Error('Invalid container header length')
  }
  const { format, metadata, authorRecord } = JSON.parse(text(data.subarray(4, 4 + headerLength)))
  if (format !== 'medshare-document/v1') throw new Error('Unsupported container format')
  return { file: data.subarray(4 + headerLength), metadata, authorRecord }
}

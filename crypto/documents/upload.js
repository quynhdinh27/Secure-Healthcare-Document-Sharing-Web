import { bytes, requiredStrings } from '../encoding.js'
import { hashRecord } from '../primitives/sha256.js'
import { createAuthorRecord, packContainer } from './author-record.js'
import { sealContainer, updatePurpose, uploadPurpose } from './manifest.js'

export async function prepareUpload({ file, metadata = {}, context: uploadContext, signer }) {
  const context = structuredClone(uploadContext)
  const stableMetadata = structuredClone(metadata)
  requiredStrings(context, ['contextId', 'expiresAt'])
  requiredStrings(signer, ['userId', 'keyId'])
  if (!(Date.parse(context.expiresAt) > Date.now())) throw new Error('Upload context expired')
  if (!['NEW_DOCUMENT', 'NEW_VERSION'].includes(context.purpose)) throw new Error('Invalid upload purpose')
  const isUpdate = context.purpose === 'NEW_VERSION'
  if (isUpdate) requiredStrings(context, ['baseVersionId'])
  const baseVersionId = isUpdate ? context.baseVersionId : null
  const purpose = isUpdate ? updatePurpose : uploadPurpose
  const data = file instanceof Blob ? new Uint8Array(await file.arrayBuffer()) : bytes(file).slice()
  let container
  try {
    const authorRecord = await createAuthorRecord(data, stableMetadata, { ...context, baseVersionId }, signer)
    container = packContainer(data, stableMetadata, authorRecord)
    const payload = await sealContainer({
      container, authorRecordHash: await hashRecord(authorRecord), context, signer,
      operation: { purpose, contextId: context.contextId, baseVersionId }
    })
    return { contextId: context.contextId, ...payload }
  } finally {
    container?.fill(0)
    data.fill(0)
  }
}

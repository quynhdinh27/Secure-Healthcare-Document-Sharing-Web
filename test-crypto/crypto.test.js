import assert from 'node:assert/strict'
import { deriveArgon2id } from '../src/crypto/argon2.js'
import { before, test } from 'node:test'
import {
  beginKeyEnrollment, answerKeyChallenge, finalizeLocalKey, restorePrivateKey, prepareUpload,
  openDocument, prepareRotationItem, prepareRotationCommit, signFolderPolicy, verifyFolderPolicy
} from '../src/crypto/index.js'
import { base64url, canonicalBytes, fromBase64url, utf8 } from '../src/crypto/encoding.js'
import { hashRecord, sha256 } from '../src/crypto/primitives/sha256.js'
import { signRecord, verifyRecord } from '../src/crypto/primitives/ecdsa.js'

let ownerSign, ownerEnc, viewerEnc, signer, owner, viewer, context, trust
let upload, source, expectedSource
const file = utf8('Test record, no patient data')
const metadata = { fileName: 'sample.txt', mimeType: 'text/plain' }
const expiresAt = '2099-01-01T00:00:00Z'

before(async () => {
  const enrollments = await Promise.all([
    beginKeyEnrollment({ userId: 'owner', purpose: 'SIGN' }),
    beginKeyEnrollment({ userId: 'owner', purpose: 'ENC' }),
    beginKeyEnrollment({ userId: 'viewer', purpose: 'ENC' })
  ])
  ownerSign = enrollments[0]
  ownerEnc = enrollments[1]
  viewerEnc = enrollments[2]
  signer = { userId: 'owner', keyId: 'owner-sign', privateKey: ownerSign.pair.privateKey }
  owner = { membershipId: 'owner-member', recipientEncryptionKeyId: 'owner-enc', privateKey: ownerEnc.pair.privateKey }
  viewer = { membershipId: 'viewer-member', recipientEncryptionKeyId: 'viewer-enc', privateKey: viewerEnc.pair.privateKey }
  context = {
    purpose: 'NEW_DOCUMENT', contextId: 'context-1', expiresAt,
    folderId: 'folder-1', documentId: 'doc-1', versionId: 'version-1',
    cryptoRevisionId: 'revision-1', keySessionId: 'session-1', policyHash: 'policy-1',
    keyRegistryRevision: 'registry-1', recipients: [
      { membershipId: viewer.membershipId, recipientEncryptionKeyId: viewer.recipientEncryptionKeyId, publicKey: viewerEnc.registration.publicKey },
      { membershipId: owner.membershipId, recipientEncryptionKeyId: owner.recipientEncryptionKeyId, publicKey: ownerEnc.registration.publicKey }
    ]
  }
  trust = {
    resolveSigningKey({ userId, keyId }) {
      assert.equal(userId, 'owner')
      assert.equal(keyId, 'owner-sign')
      return ownerSign.registration.publicKey
    },
    verifyPolicyProof({ record, policyProof }) {
      return policyProof === record.policyHash
    }
  }
  upload = await prepareUpload({ file, metadata, context, signer })
  source = { ...upload, envelope: upload.envelopes[0], policyProof: 'policy-1' }
  expectedSource = { ...context, purpose: 'document-upload/v1' }
})

test('Owner upload opens for Viewer, with a private plaintext hash', async () => {
  assert.equal(Object.hasOwn(upload.signedManifest.record, 'contentHash'), false)
  const bundle = { ...source, envelope: upload.envelopes[1] }
  const opened = await openDocument({ bundle, expected: expectedSource, recipient: viewer, trust })
  assert.deepEqual(opened, { file, metadata, authorUserId: 'owner', versionId: 'version-1' })
})

test('A new business version uses its own DEK and retains its base version ID', async () => {
  const updateContext = {
    ...context, purpose: 'NEW_VERSION', contextId: 'context-2', versionId: 'version-2',
    cryptoRevisionId: 'revision-2', baseVersionId: 'version-1'
  }
  const result = await prepareUpload({ file, metadata, context: updateContext, signer })
  const bundle = { ...result, envelope: result.envelopes[0], policyProof: 'policy-1' }
  const expected = { ...updateContext, purpose: 'document-version/v1' }
  assert.equal(result.signedManifest.record.baseVersionId, 'version-1')
  const opened = await openDocument({ bundle, expected, recipient: owner, trust })
  assert.equal(opened.versionId, 'version-2')
  await assert.rejects(openDocument({
    bundle: { ...bundle, envelope: source.envelope }, expected, recipient: owner, trust
  }), /recipient or revision/)
})

test('Rejects wrong policy, manifest, expected revision and recipient envelope', async () => {
  const read = (bundle, expected = expectedSource) => openDocument({ bundle, expected, recipient: owner, trust })
  const { signedManifest } = source
  const modified = { ...signedManifest, record: { ...signedManifest.record, authorRecordHash: 'wrong' } }
  await assert.rejects(read({ ...source, signedManifest: modified }), /Invalid signature/)
  await assert.rejects(read({ ...source, policyProof: null }), /Invalid policy proof/)
  await assert.rejects(read(source, { ...expectedSource, cryptoRevisionId: 'other' }), /Unexpected crypto context/)
  await assert.rejects(read({ ...source, envelope: upload.envelopes[1] }), /recipient or revision/)
  const envelope = { ...source.envelope, wrappedDek: upload.envelopes[1].wrappedDek }
  await assert.rejects(read({ ...source, envelope }), /commitment/)
})

test('Rejects modified ciphertext even when the outer hash was signed again', async () => {
  const ciphertext = new Uint8Array(source.ciphertext.slice(0))
  ciphertext[0] ^= 1
  const options = { expected: expectedSource, recipient: owner, trust }
  await assert.rejects(openDocument({ ...options, bundle: { ...source, ciphertext } }), /Ciphertext hash mismatch/)
  const ciphertextHash = base64url(await sha256(ciphertext))
  const signedManifest = await signRecord({ ...source.signedManifest.record, ciphertextHash }, signer.privateKey)
  await assert.rejects(openDocument({ ...options, bundle: { ...source, ciphertext, signedManifest } }), { name: 'OperationError' })
})

test('Prepare/commit rotation keeps the author, excludes the revoked member and rejects stale staging', async () => {
  const target = {
    ...context, rotationId: 'rotation-1', itemId: 'item-1', generation: '1', keySessionId: 'session-2',
    cryptoRevisionId: 'rekeyed-1', policyHash: 'policy-2', recipients: context.recipients.slice(1)
  }
  const result = await prepareRotationItem({ source, expectedSource, target, recipient: owner, signer, trust })
  assert.deepEqual(result.envelopes.map(envelope => envelope.membershipId), [owner.membershipId])
  assert.equal(result.signedManifest.record.authorRecordHash, source.signedManifest.record.authorRecordHash)
  const bundle = {
    ...result, envelope: result.envelopes[0], policyProof: 'policy-2',
    originalManifest: source.signedManifest, originalPolicyProof: 'policy-1'
  }
  const expected = {
    ...target, purpose: 'rotation-item/v1', sourceCryptoRevisionId: context.cryptoRevisionId,
    sourceCryptoManifestHash: await hashRecord(source.signedManifest),
    authorRecordHash: source.signedManifest.record.authorRecordHash
  }
  const opened = await openDocument({ bundle, expected, recipient: owner, trust })
  assert.deepEqual(opened, { file, metadata, versionId: 'version-1', authorUserId: 'owner' })
  await assert.rejects(openDocument({
    bundle: { ...bundle, envelope: upload.envelopes[1] }, expected, recipient: viewer, trust
  }), /recipient or revision/)
  const options = { job: { ...target, itemIds: ['item-1'] }, items: [{ bundle, expected }], signer, recipient: owner, trust }
  const commit = await prepareRotationCommit(options)
  assert.equal(commit.record.results.length, 1)
  assert.equal(commit.record.results[0].manifestHash, await hashRecord(result.signedManifest))
  await verifyRecord(commit, ownerSign.pair.publicKey)
  await assert.rejects(prepareRotationCommit({ ...options, items: [] }), /Incomplete/)
  await assert.rejects(prepareRotationCommit({
    ...options, job: { ...options.job, generation: '2' }
  }), /Unexpected rotation context/)
})

test('Enrollment challenge, backup and recovery use real Argon2id', async () => {
  const challenge = { userId: 'owner', keyId: 'owner-enc', purpose: 'ENC', nonce: 'nonce-1', expiresAt }
  const record = { ...challenge, purpose: 'key-proof/v1', keyPurpose: 'ENC' }
  const label = await sha256(canonicalBytes(record))
  const secret = crypto.getRandomValues(new Uint8Array(32))
  challenge.ciphertext = base64url(await crypto.subtle.encrypt({ name: 'RSA-OAEP', label }, ownerEnc.pair.publicKey, secret))
  const proof = await answerKeyChallenge(ownerEnc, { keyId: 'owner-enc', challenge })
  assert.deepEqual(fromBase64url(proof), secret)
  const passphrase = 'example recovery passphrase'
  const result = await finalizeLocalKey(ownerEnc, { keyId: 'owner-enc', passphrase, deriveArgon2id })
  assert.equal(result.privateKey.extractable, false)
  const recovery = { ...result, passphrase, deriveArgon2id, publicKey: ownerEnc.registration.publicKey }
  const restored = await restorePrivateKey(recovery)
  assert.equal(restored.extractable, false)
  const opened = await openDocument({
    bundle: source, expected: expectedSource, trust, recipient: { ...owner, privateKey: restored }
  })
  assert.deepEqual(opened.file, file)
  await assert.rejects(restorePrivateKey({ ...recovery, passphrase: 'wrong' }), { name: 'OperationError' })
  await assert.rejects(restorePrivateKey({
    ...recovery, backup: { ...result.backup, kdf: { ...result.backup.kdf, memoryKiB: 2 ** 29 } }
  }), /profile or key binding mismatch/)
})

test('Signing enrollment and membership policy signatures bind distinct purposes', async () => {
  const challenge = { userId: 'owner', keyId: 'owner-sign', purpose: 'SIGN', nonce: 'nonce-1', expiresAt }
  const signature = await answerKeyChallenge(ownerSign, { keyId: 'owner-sign', challenge })
  await verifyRecord({
    record: { ...challenge, purpose: 'key-proof/v1', keyPurpose: 'SIGN' }, signature
  }, ownerSign.pair.publicKey)
  const signed = await signFolderPolicy({
    context: { folderId: 'folder-1', contextId: 'policy-context-2', action: 'REVOKE', nonce: 'nonce-1', expiresAt, target: 'viewer-member' },
    signer
  })
  assert.equal(signed.record.purpose, 'folder-policy/v1')
  const trustedOwner = { userId: 'owner', keyId: 'owner-sign', folderId: 'folder-1', publicKey: ownerSign.registration.publicKey }
  await verifyFolderPolicy({ signedPolicy: signed, trustedOwner })
  await assert.rejects(verifyFolderPolicy({
    signedPolicy: signed, trustedOwner: { ...trustedOwner, folderId: 'other-folder' }
  }), /Policy signer or scope mismatch/)
})

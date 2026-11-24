import { base64url, canonicalBytes, fromBase64url, requiredStrings } from '../encoding.js'
import { decryptChallenge, generateEncryptionPair, importEncryptionKey } from '../primitives/rsa-oaep.js'
import { generateSigningPair, importSigningKey, signRecord, verifyRecord } from '../primitives/ecdsa.js'
import { hashBytes, sha256 } from '../primitives/sha256.js'
import { decryptBackup, encryptBackup } from './backup.js'

function keyProfile(purpose) {
  if (purpose === 'ENC') return { generate: generateEncryptionPair, import: importEncryptionKey }
  if (purpose === 'SIGN') return { generate: generateSigningPair, import: importSigningKey }
  throw new TypeError('Unknown key purpose')
}

export async function beginKeyEnrollment({ userId, purpose }) {
  requiredStrings({ userId }, ['userId'])
  const pair = await keyProfile(purpose).generate()
  const spki = await crypto.subtle.exportKey('spki', pair.publicKey)
  return { registration: { userId, purpose, publicKey: base64url(spki), publicKeyFingerprint: await hashBytes(spki) }, pair }
}

function challengeRecord(challenge, { userId, keyId, purpose }) {
  requiredStrings(challenge, ['userId', 'keyId', 'nonce', 'expiresAt'])
  const expiresAt = Date.parse(challenge.expiresAt)
  if (challenge.userId !== userId || challenge.keyId !== keyId || challenge.purpose !== purpose ||
      !Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
    throw new Error('Invalid or expired key challenge')
  }
  return { purpose: 'key-proof/v1', keyPurpose: purpose, userId, keyId, nonce: challenge.nonce, expiresAt: challenge.expiresAt }
}

export async function answerKeyChallenge(enrollment, { keyId, challenge }) {
  const { registration, pair } = enrollment
  const record = challengeRecord(challenge, { ...registration, keyId })
  if (registration.purpose === 'SIGN') return (await signRecord(record, pair.privateKey)).signature
  const label = await sha256(canonicalBytes(record))
  const wrapped = fromBase64url(challenge.ciphertext)
  if (wrapped.length !== 384) throw new Error('Invalid RSA challenge length')
  const response = new Uint8Array(await decryptChallenge(pair.privateKey, wrapped, label))
  try {
    if (response.length !== 32) throw new Error('Invalid challenge length')
    return base64url(response)
  } finally {
    response.fill(0)
  }
}

export async function finalizeLocalKey(enrollment, { keyId, passphrase, deriveArgon2id }) {
  const { registration, pair } = enrollment
  const { userId, purpose, publicKeyFingerprint } = registration
  const binding = { userId, keyId, purpose, publicKeyFingerprint }
  const raw = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey))
  try {
    const backup = await encryptBackup(raw, { binding, passphrase, deriveArgon2id })
    const privateKey = await keyProfile(purpose).import('pkcs8', raw, true)
    return { binding, privateKey, backup }
  } finally {
    raw.fill(0)
  }
}

export async function restorePrivateKey({ backup, binding, publicKey, passphrase, deriveArgon2id }) {
  const profile = keyProfile(binding.purpose)
  const spki = fromBase64url(publicKey)
  if (await hashBytes(spki) !== binding.publicKeyFingerprint) throw new Error('Public key fingerprint mismatch')
  const registeredKey = await profile.import('spki', spki)
  const raw = await decryptBackup(backup, { binding, passphrase, deriveArgon2id })
  try {
    const privateKey = await profile.import('pkcs8', raw, true)
    if (binding.purpose === 'SIGN') {
      const check = { purpose: 'local-key-recovery/v1', nonce: base64url(crypto.getRandomValues(new Uint8Array(32))) }
      await verifyRecord(await signRecord(check, privateKey), registeredKey)
    } else {
      const check = crypto.getRandomValues(new Uint8Array(32))
      const label = canonicalBytes({ purpose: 'local-key-recovery/v1' })
      const encrypted = await crypto.subtle.encrypt({ name: 'RSA-OAEP', label }, registeredKey, check)
      const result = await decryptChallenge(privateKey, encrypted, label)
      if (base64url(result) !== base64url(check)) throw new Error('Private key does not match registered public key')
    }
    return privateKey
  } finally {
    raw.fill(0)
  }
}

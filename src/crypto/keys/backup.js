import { base64url, bytes, canonicalBytes, fromBase64url, requiredStrings, utf8 } from '../encoding.js'
import { decryptAesGcm, encryptAesGcm, importAesKey } from '../primitives/aes-gcm.js'

export const backupProfile = Object.freeze({ algorithm: 'Argon2id', memoryKiB: 65536, iterations: 3, parallelism: 4, length: 32, version: 19 })

function backupHeader(binding, salt, nonce) {
  requiredStrings(binding, ['userId', 'keyId', 'purpose', 'publicKeyFingerprint'])
  return {
    format: 'medshare-private-key-backup/v1', userId: binding.userId, keyId: binding.keyId,
    purpose: binding.purpose, publicKeyFingerprint: binding.publicKeyFingerprint,
    kdf: backupProfile, salt, nonce
  }
}

async function backupKey(passphrase, salt, deriveArgon2id) {
  if (typeof passphrase !== 'string' || !passphrase) throw new TypeError('Recovery passphrase required')
  if (typeof deriveArgon2id !== 'function') throw new TypeError('Argon2id provider required')
  const password = utf8(passphrase)
  let raw
  try {
    raw = bytes(await deriveArgon2id(password, salt, backupProfile))
    return await importAesKey(raw)
  } finally {
    password.fill(0)
    raw?.fill(0)
  }
}

export async function encryptBackup(pkcs8, { binding, passphrase, deriveArgon2id }) {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const header = backupHeader(binding, base64url(salt), base64url(nonce))
  const key = await backupKey(passphrase, salt, deriveArgon2id)
  const ciphertext = await encryptAesGcm(key, nonce, canonicalBytes(header), pkcs8)
  return { ...header, ciphertext: base64url(ciphertext) }
}

export async function decryptBackup(backup, { binding, passphrase, deriveArgon2id }) {
  const { ciphertext, ...header } = backup
  const expected = backupHeader(binding, header.salt, header.nonce)
  if (base64url(canonicalBytes(header)) !== base64url(canonicalBytes(expected))) {
    throw new Error('Backup profile or key binding mismatch')
  }
  const salt = fromBase64url(header.salt)
  const nonce = fromBase64url(header.nonce)
  if (salt.length !== 16 || nonce.length !== 12) throw new Error('Invalid backup salt or nonce')
  const key = await backupKey(passphrase, salt, deriveArgon2id)
  return new Uint8Array(await decryptAesGcm(key, nonce, canonicalBytes(header), fromBase64url(ciphertext)))
}

const algorithm = { name: 'AES-GCM', length: 256 }
export const generateDek = () => crypto.subtle.generateKey(algorithm, true, ['encrypt', 'decrypt'])

export function importAesKey(raw) {
  if (raw.byteLength !== 32) throw new TypeError('Expected a 32-byte AES key')
  return crypto.subtle.importKey('raw', raw, algorithm, false, ['encrypt', 'decrypt'])
}

export function encryptAesGcm(key, nonce, aad, plaintext) {
  return crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, key, plaintext)
}

export function decryptAesGcm(key, nonce, aad, ciphertext) {
  if (nonce.byteLength !== 12) throw new TypeError('Invalid GCM nonce')
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, key, ciphertext)
}

const rsa = { name: 'RSA-OAEP', hash: 'SHA-256' }

export function generateEncryptionPair() {
  return crypto.subtle.generateKey({
    ...rsa, modulusLength: 3072, publicExponent: Uint8Array.of(1, 0, 1)
  }, true, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'])
}

export async function importEncryptionKey(format, data, privateKey = false) {
  const key = await crypto.subtle.importKey(
    format, data, rsa, false, privateKey ? ['decrypt', 'unwrapKey'] : ['encrypt', 'wrapKey']
  )
  if (key.algorithm.modulusLength !== 3072 || key.algorithm.publicExponent.join(',') !== '1,0,1') {
    throw new TypeError('Invalid RSA key profile')
  }
  return key
}

export function wrapDek(dek, publicKey, label) {
  return crypto.subtle.wrapKey('raw', dek, publicKey, { name: 'RSA-OAEP', label })
}

export async function unwrapDek(wrapped, privateKey, label) {
  const key = await crypto.subtle.unwrapKey(
    'raw', wrapped, privateKey, { name: 'RSA-OAEP', label },
    'AES-GCM', false, ['decrypt']
  )
  if (key.algorithm.length !== 256) throw new TypeError('Invalid DEK length')
  return key
}

export const decryptChallenge = (key, ciphertext, label) =>
  crypto.subtle.decrypt({ name: 'RSA-OAEP', label }, key, ciphertext)

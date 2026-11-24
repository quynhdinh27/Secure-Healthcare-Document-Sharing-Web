import { base64url, canonicalBytes, fromBase64url } from '../encoding.js'

const curve = { name: 'ECDSA', namedCurve: 'P-256' }
const signatureAlgorithm = { name: 'ECDSA', hash: 'SHA-256' }

export const generateSigningPair = () => crypto.subtle.generateKey(curve, true, ['sign', 'verify'])

export function importSigningKey(format, data, privateKey = false) {
  return crypto.subtle.importKey(format, data, curve, false, [privateKey ? 'sign' : 'verify'])
}

export async function signRecord(record, key) {
  const stableRecord = JSON.parse(new TextDecoder().decode(canonicalBytes(record)))
  const signature = await crypto.subtle.sign(signatureAlgorithm, key, canonicalBytes(stableRecord))
  return { record: stableRecord, signature: base64url(signature) }
}

export async function verifyRecord(signed, key) {
  const signature = fromBase64url(signed.signature)
  if (signature.length !== 64 ||
      !await crypto.subtle.verify(signatureAlgorithm, key, signature, canonicalBytes(signed.record))) {
    throw new Error('Invalid signature')
  }
}

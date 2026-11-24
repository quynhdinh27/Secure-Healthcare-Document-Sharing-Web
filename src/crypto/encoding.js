const encoder = new TextEncoder()
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })

export const utf8 = value => encoder.encode(value)
export const text = value => decoder.decode(value)

export function bytes(value) {
  if (value instanceof ArrayBuffer) return new Uint8Array(value)
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
  }
  throw new TypeError('Expected binary data')
}

export function base64url(value) {
  const data = bytes(value)
  let binary = ''
  for (let offset = 0; offset < data.length; offset += 8192) {
    binary += String.fromCharCode(...data.subarray(offset, offset + 8192))
  }
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
}

export function fromBase64url(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new TypeError('Expected unpadded base64url')
  }
  const result = Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0))
  if (base64url(result) !== value) throw new TypeError('Noncanonical base64url')
  return result
}

function jsonString(value) {
  if (/[\uD800-\uDFFF]/u.test(value)) throw new TypeError('Invalid Unicode in signed JSON')
  return JSON.stringify(value)
}

function canonicalize(value) {
  if (typeof value === 'string') return jsonString(value)
  if (value === null || typeof value === 'boolean' || Number.isFinite(value)) {
    return JSON.stringify(value)
  }
  if (Array.isArray(value)) return '[' + Array.from(value, canonicalize).join(',') + ']'
  if (value && [Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    return '{' + Object.keys(value).sort().map(key =>
      jsonString(key) + ':' + canonicalize(value[key])
    ).join(',') + '}'
  }
  throw new TypeError('Expected a JSON value')
}

export const canonicalBytes = value => utf8(canonicalize(value))

export function requiredStrings(value, fields) {
  for (const field of fields) {
    if (typeof value?.[field] !== 'string' || !value[field]) throw new TypeError('Invalid ' + field)
  }
}

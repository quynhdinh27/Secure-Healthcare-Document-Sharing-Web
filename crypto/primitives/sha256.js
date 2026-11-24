import { base64url, canonicalBytes } from '../encoding.js'

export const sha256 = data => crypto.subtle.digest('SHA-256', data)
export const hashBytes = async data => base64url(await sha256(data))
export const hashRecord = record => hashBytes(canonicalBytes(record))

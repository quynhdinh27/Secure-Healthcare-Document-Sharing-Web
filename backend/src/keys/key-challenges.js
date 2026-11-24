const {
  constants, createHash, createPublicKey, publicEncrypt, randomBytes, timingSafeEqual, verify,
} = require('node:crypto');
const canonicalize = require('canonicalize');

const challengeLifetimeMs = 5 * 60 * 1000;

function decodeBase64url(value, maxLength) {
  if (typeof value !== 'string' || value.length > maxLength || !/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const bytes = Buffer.from(value, 'base64url');
  return bytes.toString('base64url') === value ? bytes : null;
}

function hash(bytes) {
  return createHash('sha256').update(bytes).digest();
}

function importPublicKey(purpose, encoded) {
  const spki = decodeBase64url(encoded, 1024);
  if (!spki) throw new TypeError('Invalid public key encoding');
  const key = createPublicKey({ key: spki, type: 'spki', format: 'der' });
  if (!key.export({ type: 'spki', format: 'der' }).equals(spki)) throw new TypeError('Invalid SPKI encoding');
  const details = key.asymmetricKeyDetails;
  const matches = (purpose === 'SIGN' && key.asymmetricKeyType === 'ec' && details.namedCurve === 'prime256v1')
    || (purpose === 'ENC' && key.asymmetricKeyType === 'rsa'
      && details.modulusLength === 3072 && details.publicExponent === 65537n);
  if (!matches) throw new TypeError('Invalid public key profile');
  return { key, fingerprint: hash(spki).toString('base64url') };
}

function challengeBytes(challenge) {
  const { userId, keyId, purpose, nonce, expiresAt } = challenge;
  return Buffer.from(canonicalize({ purpose: 'key-proof/v1', keyPurpose: purpose, userId, keyId, nonce, expiresAt }), 'utf8');
}

function issueKeyChallenge({ userId, keyId, purpose, publicKey, publicKeyFingerprint }, now = Date.now()) {
  if (typeof userId !== 'string' || !userId || typeof keyId !== 'string' || !keyId) {
    throw new TypeError('Invalid challenge identity');
  }
  const { key, fingerprint } = importPublicKey(purpose, publicKey);
  if (fingerprint !== publicKeyFingerprint) throw new TypeError('Public key fingerprint mismatch');
  const challenge = {
    userId, keyId, purpose, nonce: randomBytes(32).toString('base64url'),
    expiresAt: new Date(now + challengeLifetimeMs).toISOString(),
  };
  const publicKeyJwk = key.export({ format: 'jwk' });
  if (purpose === 'SIGN') return { challenge, responseHash: null, publicKeyJwk };

  const secret = randomBytes(32);
  try {
    challenge.ciphertext = publicEncrypt({
      key,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
      oaepLabel: hash(challengeBytes(challenge)),
    }, secret).toString('base64url');
    return { challenge, responseHash: hash(secret).toString('base64url'), publicKeyJwk };
  } finally {
    secret.fill(0);
  }
}

// Call with the persisted challenge and associated public key, never a challenge supplied by the client.
// The caller must bind the challenge to the authenticated account and consume it once in storage.
function verifyKeyChallenge({ challenge, publicKey, response, responseHash }, now = Date.now()) {
  const expiry = Date.parse(challenge?.expiresAt);
  if (!Number.isFinite(expiry) || expiry <= now) return false;
  const encodedResponse = decodeBase64url(response, 86);
  if (!encodedResponse) return false;
  if (challenge.purpose === 'ENC') {
    const expectedHash = decodeBase64url(responseHash, 43);
    if (encodedResponse.length !== 32 || expectedHash?.length !== 32) return false;
    try {
      return timingSafeEqual(hash(encodedResponse), expectedHash);
    } finally {
      encodedResponse.fill(0);
    }
  }
  if (challenge.purpose !== 'SIGN' || encodedResponse.length !== 64) return false;
  try {
    const { key } = importPublicKey('SIGN', publicKey);
    return verify('sha256', challengeBytes(challenge), { key, dsaEncoding: 'ieee-p1363' }, encodedResponse);
  } catch {
    return false;
  }
}

module.exports = { decodeBase64url, issueKeyChallenge, verifyKeyChallenge };

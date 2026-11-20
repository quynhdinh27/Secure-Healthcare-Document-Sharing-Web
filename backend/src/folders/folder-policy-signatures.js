const { createPublicKey, verify } = require('node:crypto');
const canonicalize = require('canonicalize');

function verifySignature(publicJwk, payload, signature) {
  if (publicJwk?.kty !== 'EC' || publicJwk.crv !== 'P-256' || publicJwk.d !== undefined
      || typeof signature !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(signature)) {
    return false;
  }
  const bytes = Buffer.from(signature, 'base64url');
  if (bytes.length !== 64 || bytes.toString('base64url') !== signature) return false;

  try {
    const key = createPublicKey({ key: publicJwk, format: 'jwk' });
    return verify('sha256', Buffer.from(canonicalize(payload), 'utf8'), {
      key, dsaEncoding: 'ieee-p1363',
    }, bytes);
  } catch {
    return false;
  }
}

function createFolderPolicyVerifiers({ lookupActiveSigningKey, canReceiveFolderKeys }) {
  return {
    async verifyInitialFolderPolicy({ connection, folder, ownerId, signedPolicy, policyVersion }) {
      const publicKey = await lookupActiveSigningKey(connection, ownerId);
      const payload = {
        purpose: 'INITIAL_FOLDER_POLICY',
        folder,
        ownerId: String(ownerId),
        policyVersion,
        members: [{ userId: String(ownerId), role: 'OWNER' }],
      };
      return canonicalize(signedPolicy?.payload) === canonicalize(payload)
        && verifySignature(publicKey, payload, signedPolicy?.signature)
        && await canReceiveFolderKeys(connection, ownerId) === true;
    },

    async verifyFolderPolicy({ connection, ownerId, context, ownerSignature }) {
      if (context.ownerId !== String(ownerId)) return false;
      const publicKey = await lookupActiveSigningKey(connection, ownerId);
      if (!verifySignature(publicKey, { purpose: 'FOLDER_MEMBERSHIP_CHANGE', context }, ownerSignature)) {
        return false;
      }
      return context.action !== 'ADD_MEMBER'
        || await canReceiveFolderKeys(connection, context.target.userId) === true;
    },
  };
}

module.exports = { createFolderPolicyVerifiers };

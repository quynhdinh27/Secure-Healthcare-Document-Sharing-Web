// Development helpers shared by seed.cjs and smoke-documents.cjs. They play the
// browser's role: generate key pairs, sign policies, call the API with X-Dev-User-Id.
const { randomUUID, webcrypto } = require('node:crypto');
const { once } = require('node:events');
const fs = require('node:fs/promises');
const path = require('node:path');
const canonicalize = require('canonicalize');
const { fingerprintPublicJwk, toPublicJwk } = require('../../src/keys/mysql-key-directory');
const { buildApp } = require('../../src/main');

const { subtle } = webcrypto;
const RSA_OAEP = { name: 'RSA-OAEP', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' };
const ECDSA = { name: 'ECDSA', namedCurve: 'P-256' };

async function generateKeyPair(algorithm, usages, purpose) {
  const { publicKey, privateKey } = await subtle.generateKey(algorithm, true, usages);
  return {
    keyId: randomUUID(),
    publicJwk: toPublicJwk(await subtle.exportKey('jwk', publicKey), purpose),
    privateJwk: await subtle.exportKey('jwk', privateKey),
  };
}

async function createDevUser(executor, { email, fullName, accountType = 'STAFF', withKeys = true }) {
  const [result] = await executor.execute(
    'INSERT INTO `User` (email, full_name, account_type) VALUES (?, ?, ?)', [email, fullName, accountType],
  );
  const user = { userId: String(result.insertId), email, fullName, accountType };
  if (!withKeys) return user;
  const keys = {
    encryption: await generateKeyPair(RSA_OAEP, ['encrypt', 'decrypt'], 'ENCRYPTION'),
    signing: await generateKeyPair(ECDSA, ['sign', 'verify'], 'SIGNING'),
  };
  const rows = [
    ['ENCRYPTION', 'RSA-OAEP-3072-SHA256', keys.encryption],
    ['SIGNING', 'ECDSA-P256-SHA256', keys.signing],
  ];
  for (const [purpose, algorithm, key] of rows) {
    await executor.execute(`
      INSERT INTO User_Key (key_id, user_id, purpose, algorithm, public_key_jwk, fingerprint, status, activated_at)
      VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE', UTC_TIMESTAMP(3))
    `, [key.keyId, user.userId, purpose, algorithm, JSON.stringify(key.publicJwk), fingerprintPublicJwk(key.publicJwk)]);
  }
  return { ...user, keys };
}

async function signPayload(privateJwk, payload) {
  const key = await subtle.importKey('jwk', privateJwk, ECDSA, false, ['sign']);
  const signature = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, Buffer.from(canonicalize(payload)));
  return Buffer.from(signature).toString('base64url');
}

async function writeDevKeyFile(dir, user) {
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await fs.writeFile(path.join(dir, `${user.userId}.json`), JSON.stringify(user, null, 2), { mode: 0o600 });
}

function createApiClient(baseUrl) {
  return async function call(urlPath, userId, expectedStatus, { method = 'GET', body, form, raw = false, headers = {} } = {}) {
    const init = { method, headers: { 'x-dev-user-id': userId, ...headers } };
    if (form) init.body = form;
    else if (body !== undefined) {
      init.headers['content-type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    const response = await fetch(baseUrl + urlPath, init);
    const bytes = Buffer.from(await response.arrayBuffer());
    let data = bytes;
    if (!raw && bytes.length) {
      try {
        data = JSON.parse(bytes.toString('utf8'));
      } catch {
        data = bytes;
      }
    }
    if (response.status !== expectedStatus) {
      const detail = Buffer.isBuffer(data) ? data.toString('utf8') : JSON.stringify(data);
      throw new Error(`${method} ${urlPath}: expected ${expectedStatus}, got ${response.status} ${detail}`);
    }
    return raw ? { data, headers: response.headers } : data;
  };
}

async function addFolderMember({ call, owner, folderId, userId, role }) {
  const context = await call(`/folders/${folderId}/policy-contexts`, owner.userId, 201, {
    method: 'POST', body: { action: 'ADD_MEMBER', userId, role },
  });
  const ownerSignature = await signPayload(owner.keys.signing.privateJwk, { purpose: 'FOLDER_MEMBERSHIP_CHANGE', context });
  return call(`/folders/${folderId}/members`, owner.userId, 202, {
    method: 'POST', body: { policyContextId: context.contextId, ownerSignature },
  });
}

async function createFolderWithMembers({ call, owner, folder, members = [] }) {
  const folderId = randomUUID();
  const payload = {
    purpose: 'INITIAL_FOLDER_POLICY',
    folder: { folderId, ...folder },
    ownerId: owner.userId,
    policyVersion: 1,
    members: [{ userId: owner.userId, role: 'OWNER' }],
  };
  await call('/folders', owner.userId, 201, {
    method: 'POST',
    body: { folderId, ...folder, signedPolicy: { payload, signature: await signPayload(owner.keys.signing.privateJwk, payload) } },
  });
  for (const { user, role } of members) {
    await addFolderMember({ call, owner, folderId, userId: user.userId, role });
  }
  return folderId;
}

async function startDevServer({ config, pool }) {
  const server = buildApp({ config: { ...config, authMode: 'dev' }, pool }).listen(0, '127.0.0.1');
  await once(server, 'listening');
  return {
    baseUrl: `http://127.0.0.1:${server.address().port}/api/v1`,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

module.exports = {
  addFolderMember, createApiClient, createDevUser, createFolderWithMembers, signPayload, startDevServer, writeDevKeyFile,
};

const assert = require('node:assert/strict');
const { generateKeyPairSync, randomInt, randomUUID, sign } = require('node:crypto');
const { once } = require('node:events');
const canonicalize = require('canonicalize');
const mysql = require('mysql2/promise');
const { createApp } = require('../src/server');

async function main() {
  const pool = mysql.createPool({ host: '127.0.0.1', user: 'root', database: 'medshare_smoke' });
  const ownerId = String(randomInt(100_000_000, 900_000_000));
  const memberId = String(Number(ownerId) + 1);
  const outsiderId = String(Number(ownerId) + 2);
  const accounts = [ownerId, memberId, outsiderId];
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const publicJwk = publicKey.export({ format: 'jwk' });
  const signPayload = (payload) => sign('sha256', Buffer.from(canonicalize(payload)), {
    key: privateKey, dsaEncoding: 'ieee-p1363',
  }).toString('base64url');
  let server;

  try {
    await pool.execute('INSERT INTO `User` (user_id) VALUES (?), (?), (?)', accounts);
    const app = createApp({
      mysqlPool: pool,
      // Only this loopback test app accepts these synthetic credentials and key lookups.
      authenticate(request, _response, next) {
        const id = request.get('x-smoke-user');
        if (accounts.includes(id)) request.user = { id };
        next();
      },
      folderPolicyKeys: {
        async lookupActiveSigningKey(_connection, userId) {
          return userId === ownerId ? publicJwk : null;
        },
        async canReceiveFolderKeys(_connection, userId) {
          return accounts.includes(userId);
        },
      },
      async canReadRotationSources({ userId }) {
        return userId === ownerId || userId === memberId;
      },
    });
    server = app.listen(0, '127.0.0.1');
    await once(server, 'listening');
    const base = `http://127.0.0.1:${server.address().port}/api/v1`;

    async function call(path, userId, expectedStatus, { method = 'GET', body, headers = {} } = {}) {
      const response = await fetch(base + path, {
        method,
        headers: { 'x-smoke-user': userId, 'content-type': 'application/json', ...headers },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      const data = await response.json();
      assert.equal(response.status, expectedStatus, `${method} ${path}: ${JSON.stringify(data)}`);
      return data;
    }

    const folder = {
      folderId: randomUUID(), name: 'Membership smoke test',
      patientRef: 'fixture-patient', treatmentReference: 'fixture-episode',
    };
    const payload = {
      purpose: 'INITIAL_FOLDER_POLICY', folder, ownerId, policyVersion: 1,
      members: [{ userId: ownerId, role: 'OWNER' }],
    };
    await call('/folders', ownerId, 201, {
      method: 'POST', body: { ...folder, signedPolicy: { payload, signature: signPayload(payload) } },
    });

    const folderPath = '/folders/' + folder.folderId;
    async function changeMember(action, target, path, method) {
      const context = await call(folderPath + '/policy-contexts', ownerId, 201, {
        method: 'POST', body: { action, ...target },
      });
      const signature = signPayload({ purpose: 'FOLDER_MEMBERSHIP_CHANGE', context });
      return call(path, ownerId, 202, method === 'DELETE' ? {
        method, headers: { 'X-Policy-Context-Id': context.contextId, 'X-Policy-Signature': signature },
      } : {
        method, body: { policyContextId: context.contextId, ownerSignature: signature },
      });
    }
    const listJobs = (id) => call('/key-rotations', id, 200);
    const jobPath = (id) => '/key-rotations/' + id;
    const membersPath = folderPath + '/members';

    const added = await changeMember('ADD_MEMBER', { userId: memberId, role: 'EDITOR' }, membersPath, 'POST');
    assert.equal(added.policyVersion, 2);
    assert.equal((await call(folderPath, memberId, 200)).role, 'EDITOR');
    assert.deepEqual((await listJobs(memberId)).rotations.map((job) => job.rotationId), [added.rotationId]);
    assert.deepEqual((await listJobs(outsiderId)).rotations, []);
    const lease = await call(jobPath(added.rotationId) + '/claim', memberId, 200, { method: 'POST' });
    assert.equal(lease.generation, 1);

    const { members } = await call(membersPath, ownerId, 200);
    const membership = members.find(({ userId }) => String(userId) === memberId);
    assert.ok(membership);
    const membershipId = String(membership.membershipId);
    const memberPath = membersPath + '/' + membershipId;
    const downgraded = await changeMember('CHANGE_ROLE', { membershipId, role: 'VIEWER' }, memberPath, 'PATCH');
    assert.equal(downgraded.policyVersion, 3);
    assert.notEqual(downgraded.rotationId, added.rotationId);
    assert.equal((await call(folderPath, memberId, 200)).role, 'VIEWER');
    assert.deepEqual((await listJobs(memberId)).rotations, []);
    assert.equal((await call(jobPath(added.rotationId), ownerId, 200)).status, 'CANCELLED');
    assert.equal((await call(jobPath(added.rotationId) + '/lease/renew', memberId, 404, {
      method: 'POST', body: { generation: lease.generation },
    })).code, 'ROTATION_NOT_FOUND');

    const revoked = await changeMember('REVOKE_MEMBER', { membershipId }, memberPath, 'DELETE');
    assert.equal(revoked.policyVersion, 4);
    assert.notEqual(revoked.rotationId, downgraded.rotationId);
    await call(folderPath, memberId, 403);
    await call(folderPath + '/policies/4', memberId, 403);
    const { folders } = await call('/folders', memberId, 200);
    assert.deepEqual(folders, []);
    assert.equal((await call(folderPath, ownerId, 200)).policyVersion, 4);
    const jobs = (await listJobs(ownerId)).rotations.sort((a, b) => a.policyVersion - b.policyVersion);
    assert.deepEqual(jobs.map(({ policyVersion, status }) => [policyVersion, status]), [
      [2, 'CANCELLED'], [3, 'CANCELLED'], [4, 'PENDING'],
    ]);
    console.log('PASS: add, change role, revoke, and rotation access on MySQL');
  } finally {
    if (server) await new Promise((resolve) => server.close(resolve));
    await pool.end();
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

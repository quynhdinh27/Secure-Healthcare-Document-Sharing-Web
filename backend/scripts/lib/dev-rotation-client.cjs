const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const canonicalize = require('canonicalize');
const { signPayload } = require('./dev-accounts.cjs');
const { prepareUpload, sha256Hex, verifyAndDecrypt } = require('./dev-document-client.cjs');

async function completeRotation({ call, owner, executor, rotationId, checkGuards = false }) {
  const path = `/key-rotations/${rotationId}`;
  const claim = await call(path + '/claim', executor.userId, 200, { method: 'POST' });
  const generation = '?generation=' + claim.generation;
  const endpoint = (route) => path + route + generation;
  const { folderId, policyVersion, signerKeyId, recipients, items, nextCursor } = await call(endpoint('/items'), executor.userId, 200);
  assert.equal(nextCursor, null);
  assert.ok(items.length >= 1);
  const renewed = await call(path + '/lease/renew', executor.userId, 200, {
    method: 'POST', body: { generation: claim.generation },
  });
  assert.equal(renewed.generation, claim.generation);
  if (checkGuards) {
    const stale = await call(path + '/items?generation=' + (claim.generation + 1), executor.userId, 409);
    assert.equal(stale.code, 'LEASE_EXPIRED');
    const incomplete = await call(endpoint('/commit'), owner.userId, 409, {
      method: 'POST', body: { signature: 'A'.repeat(86) },
    });
    assert.equal(incomplete.code, 'ROTATION_INCOMPLETE');
  }

  async function openEvidence(route, user) {
    const evidence = await call(endpoint(route), user.userId, 200);
    const url = endpoint(route) + '&content=1&revisionId=' + evidence.revisionId;
    const { data } = await call(url, user.userId, 200, { raw: true });
    const plaintext = await verifyAndDecrypt(evidence, data, user);
    return { evidence, plaintext };
  }

  const results = [];
  for (const item of items) {
    const route = '/items/' + item.itemId;
    const source = await openEvidence(route + '/source', executor);
    const context = {
      ...item, contextId: rotationId, folderId, versionId: item.itemId, revisionId: randomUUID(),
      generation: claim.generation, policyVersion, signerKeyId, recipients,
    };
    const upload = await prepareUpload({
      context, author: executor, plaintext: source.plaintext, sourceManifest: source.evidence.manifest,
    });
    if (checkGuards) {
      const fields = JSON.parse(upload.form.get('metadata'));
      fields.envelopes.pop();
      const bad = new FormData();
      bad.append('metadata', JSON.stringify(fields));
      bad.append('ciphertext', new Blob([upload.ciphertext]), 'ciphertext.bin');
      const rejected = await call(endpoint(route + '/result'), executor.userId, 422, { method: 'PUT', form: bad });
      assert.equal(rejected.code, 'RECIPIENTS_MISMATCH');
    }
    const { revisionId } = await call(endpoint(route + '/result'), executor.userId, 201, {
      method: 'PUT', form: upload.form,
    });
    const ownerSource = await openEvidence(route + '/source', owner);
    const staged = await openEvidence(route + '/result', owner);
    assert.deepEqual(staged.plaintext, ownerSource.plaintext);
    assert.equal(staged.evidence.manifest.sourceRevisionId, ownerSource.evidence.revisionId);
    assert.equal(staged.evidence.manifest.sourceManifestSha256, sha256Hex(canonicalize(ownerSource.evidence.manifest)));
    assert.equal(staged.evidence.manifest.authorRecordSha256, ownerSource.evidence.manifest.authorRecordSha256);
    results.push({ itemId: item.itemId, revisionId, manifestSha256: sha256Hex(canonicalize(staged.evidence.manifest)) });
  }

  const record = {
    purpose: 'DOCUMENT_ROTATION_COMMIT', rotationId, generation: claim.generation, folderId, policyVersion,
    actorUserId: owner.userId, signerKeyId: owner.keys.signing.keyId, results,
  };
  if (checkGuards) {
    const forbidden = await call(endpoint('/commit'), executor.userId, 403, {
      method: 'POST', body: { signature: 'A'.repeat(86) },
    });
    assert.equal(forbidden.code, 'FORBIDDEN');
    const invalid = await call(endpoint('/commit'), owner.userId, 422, {
      method: 'POST', body: { signature: 'A'.repeat(86) },
    });
    assert.equal(invalid.code, 'INVALID_SIGNATURE');
  }
  const signature = await signPayload(owner.keys.signing.privateJwk, record);
  const commit = await call(endpoint('/commit'), owner.userId, 200, { method: 'POST', body: { signature } });
  assert.equal(commit.status, 'COMPLETED');
  const retried = await call(endpoint('/commit'), owner.userId, 200, { method: 'POST', body: { signature } });
  assert.deepEqual(retried, commit);
  return results;
}

module.exports = { completeRotation };

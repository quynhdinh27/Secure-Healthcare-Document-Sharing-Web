// Backend giả để chạy/xem UI khi chưa có API thật (VITE_USE_MOCK=true).
//  - Trạng thái lưu trong IndexedDB → reload trang không mất khóa/tài liệu.
//  - Server giả KHÔNG biết plaintext/DEK/private key; nó verify challenge, chữ ký policy,
//    chữ ký commit bằng chính module crypto của FE → test được vòng đời khóa thật.
//  - mock.js cũng là "bản mẫu contract" cho backend: xem shape response ở từng route.
// Đăng nhập: riley@ (Owner f-481) · alex@ (Editor f-481, Owner f-472) · sam@ · admin@hospital.org — mật khẩu bất kỳ.
import { ApiError } from './errors';
import { base64url, canonicalBytes, fromBase64url } from '../crypto/encoding';
import { importEncryptionKey } from '../crypto/primitives/rsa-oaep';
import { importSigningKey, verifyRecord } from '../crypto/primitives/ecdsa';
import { hashBytes, hashRecord, sha256 } from '../crypto/primitives/sha256';

const SCHEMA = 5;
const ROT_PURPOSE = 'rotation-item/v1';
const BLOCKING = ['WAITING_FOR_KEY', 'WAITING_FOR_CLIENT', 'IN_PROGRESS', 'WAITING_FOR_OWNER', 'FAILED'];
const iso = (d) => new Date(d).toISOString();
const uid = () => crypto.randomUUID();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const fail = (status, message, code) => { throw new ApiError(status, { message, code }); };
const json = (v) => (typeof v === 'string' ? JSON.parse(v) : v);

/* ---------------- persistence ---------------- */
const idb = () => new Promise((res, rej) => { const r = indexedDB.open('medshare-mock', 1); r.onupgradeneeded = () => r.result.createObjectStore('s'); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
const dbGet = async () => { const db = await idb(); return new Promise((res, rej) => { const q = db.transaction('s').objectStore('s').get('state'); q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error); }); };
const dbPut = async (v) => { const db = await idb(); return new Promise((res, rej) => { const t = db.transaction('s', 'readwrite'); t.objectStore('s').put(v, 'state'); t.oncomplete = () => res(); t.onerror = () => rej(t.error); }); };
export async function resetMock() {
  const db = await idb();
  await new Promise((res) => { const t = db.transaction('s', 'readwrite'); t.objectStore('s').clear(); t.oncomplete = res; });
  sessionStorage.removeItem('mock.uid');
}

/* ---------------- seed ---------------- */
function seed() {
  const users = [
    { userId: 'u-riley', name: 'Dr. Riley Morgan', email: 'riley@hospital.org', staffId: 'ST-00142', department: 'Cardiology', status: 'ACTIVE', createdAt: '2025-02-12', lastLoginAt: '2026-11-16T10:42:00Z' },
    { userId: 'u-alex', name: 'Dr. Alex Chen', email: 'alex@hospital.org', staffId: 'ST-00157', department: 'Surgery', status: 'ACTIVE', createdAt: '2025-03-02', lastLoginAt: '2026-11-15T08:00:00Z' },
    { userId: 'u-jamie', name: 'Dr. Jamie Lee', email: 'jamie@hospital.org', staffId: 'ST-00163', department: 'Laboratory', status: 'INACTIVE', createdAt: '2025-03-20', lastLoginAt: '2026-11-09T08:00:00Z' },
    { userId: 'u-sam', name: 'Dr. Sam Patel', email: 'sam@hospital.org', staffId: 'ST-00181', department: 'Respiratory', status: 'ACTIVE', createdAt: '2025-06-01', lastLoginAt: '2026-11-15T08:00:00Z' },
    { userId: 'u-admin', name: 'Hospital Administrator', email: 'admin@hospital.org', staffId: 'ST-00001', department: 'IT', status: 'ACTIVE', isHospitalAdmin: true, createdAt: '2025-01-01', lastLoginAt: '2026-11-16T09:00:00Z' },
  ];
  const mkFolder = (n, code, name, ownerId, updatedAt) => ({ folderId: `f-${n}`, code, name, treatmentRef: `TR-${n.padStart(5, '0')}`, ownerId, updatedAt, policies: [], policyVersion: 1, policyHash: `seed-policy-${n}`, keySessionId: `ks-${n}-1` });
  const folders = [
    mkFolder('481', 'TF-2026-00481', 'Cardiology follow-up', 'u-riley', '2026-11-14T10:00:00Z'),
    mkFolder('472', 'TF-2026-00472', 'Post-operative care', 'u-alex', '2026-11-13T10:00:00Z'),
    mkFolder('439', 'TF-2026-00439', 'Laboratory review', 'u-jamie', '2026-11-10T10:00:00Z'),
    mkFolder('398', 'TF-2026-00398', 'Respiratory treatment', 'u-sam', '2026-11-08T10:00:00Z'),
  ];
  const members = [['481', 'u-riley', 'OWNER'], ['481', 'u-alex', 'EDITOR'], ['481', 'u-jamie', 'VIEWER'], ['481', 'u-sam', 'EDITOR'],
    ['472', 'u-alex', 'OWNER'], ['472', 'u-riley', 'EDITOR'], ['439', 'u-jamie', 'OWNER'], ['439', 'u-riley', 'VIEWER'],
    ['398', 'u-sam', 'OWNER'], ['398', 'u-riley', 'EDITOR']]
    .map(([n, userId, role], i) => ({ membershipId: `m-${i}`, folderId: `f-${n}`, userId, role, status: 'ACTIVE' }));
  const docs = []; const versions = [];
  const seedDoc = (folderId, title, category, by, history) => {
    const documentId = uid();
    const vs = history.map(([n, who, date], i) => ({ versionId: uid(), documentId, versionNumber: n, createdByName: who, createdAt: iso(date), size: 2516582 - i * 1000, demo: true, revisions: [] }));
    versions.push(...vs);
    docs.push({ documentId, folderId, title, category, uploadedByName: by, createdAt: iso(history.at(-1)[2]), currentVersionId: vs[0].versionId });
  };
  seedDoc('f-481', 'Discharge summary.pdf', 'Medical report', 'Dr. Riley Morgan', [[3, 'Dr. Riley Morgan', '2026-11-14'], [2, 'Dr. Alex Chen', '2026-11-10'], [1, 'Dr. Riley Morgan', '2026-11-02']]);
  seedDoc('f-481', 'Blood test results.pdf', 'Laboratory result', 'Dr. Alex Chen', [[2, 'Dr. Alex Chen', '2026-11-13'], [1, 'Dr. Alex Chen', '2026-11-12']]);
  seedDoc('f-481', 'Chest X-ray.png', 'Medical image', 'Dr. Jamie Lee', [[1, 'Dr. Jamie Lee', '2026-11-11']]);
  seedDoc('f-481', 'Prescription.pdf', 'Prescription', 'Dr. Sam Patel', [[1, 'Dr. Sam Patel', '2026-11-09']]);
  seedDoc('f-472', 'Referral letter.pdf', 'Medical report', 'Dr. Alex Chen', [[1, 'Dr. Alex Chen', '2026-11-13']]);
  seedDoc('f-439', 'Lab panel.pdf', 'Laboratory result', 'Dr. Jamie Lee', [[1, 'Dr. Jamie Lee', '2026-11-10']]);
  const ev = (eventId, at, type, actorName, itemName, folderCode, folderId) => ({ eventId, occurredAt: at, type, actorName, actorUserId: users.find((u) => u.name === actorName)?.userId, itemName, folderCode, folderId });
  return {
    v: SCHEMA, krr: 1, users, folders, members, docs, versions, keys: {}, devices: {}, ctxs: {}, challenges: {}, backups: {}, rotations: [],
    events: [
      ev('e1', '2026-11-16T10:42:00Z', 'DOCUMENT_UPLOADED', 'Dr. Riley Morgan', 'Discharge summary.pdf', 'TF-2026-00481', 'f-481'),
      ev('e2', '2026-11-16T10:40:00Z', 'DOCUMENT_DOWNLOADED', 'Dr. Riley Morgan', 'Blood test results.pdf', 'TF-2026-00481', 'f-481'),
      ev('e3', '2026-11-15T15:12:00Z', 'DOCUMENT_VERSION_ADDED', 'Dr. Alex Chen', 'Referral letter.pdf', 'TF-2026-00472', 'f-472'),
      ev('e4', '2026-11-14T09:30:00Z', 'FOLDER_ACCESSED', 'Dr. Riley Morgan', 'Respiratory treatment', 'TF-2026-00398', 'f-398'),
    ],
    adminEvents: [
      { eventId: 'a1', occurredAt: '2026-11-16T11:02:00Z', type: 'ACCOUNT_STATUS_CHANGED', staffId: 'ST-00163', result: 'Deactivated' },
      { eventId: 'a2', occurredAt: '2026-11-16T09:15:00Z', type: 'ACCOUNT_CREATED', staffId: 'ST-00181', result: 'Created' },
      { eventId: 'a3', occurredAt: '2026-11-15T16:44:00Z', type: 'ACCOUNT_UPDATED', staffId: 'ST-00157', result: 'Updated' },
      { eventId: 'a4', occurredAt: '2026-11-14T13:20:00Z', type: 'ACCOUNT_REACTIVATED', staffId: 'ST-00142', result: 'Reactivated' },
    ],
  };
}

let S; // state
let queue = Promise.resolve();
function migrate(s) {
  if (s?.v === 4) { // v4 → v5: event có actorUserId; bỏ event rotation khỏi audit
    s.events.forEach((e) => { e.actorUserId ??= s.users.find((u) => u.name === e.actorName)?.userId; });
    s.v = SCHEMA;
  }
  return s?.v === SCHEMA ? s : null;
}
async function load() { if (!S) S = migrate(await dbGet()) ?? seed(); }
const save = () => dbPut(S);

/* ---------------- helpers ---------------- */
const me = () => S.users.find((u) => u.userId === sessionStorage.getItem('mock.uid'));
const need = () => me() ?? fail(401, 'Not signed in.', 'UNAUTHENTICATED');
const userOf = (id) => S.users.find((u) => u.userId === id);
const folderOf = (id) => S.folders.find((f) => f.folderId === id) ?? fail(404, 'Folder not found.', 'NOT_FOUND');
const mship = (folderId, userId) => S.members.find((m) => m.folderId === folderId && m.userId === userId && m.status === 'ACTIVE');
const must = (folderId, ...allowed) => {
  const m = mship(folderId, need().userId);
  if (!m) fail(404, 'Folder not found.', 'NOT_FOUND');
  if (allowed.length && !allowed.includes(m.role)) fail(403, 'Your folder role does not allow this action.', 'FORBIDDEN');
  return m;
};
const myKeys = (uidv = need().userId) => (S.keys[uidv] ??= []);
const activeKey = (uidv, purpose) => myKeys(uidv).find((k) => k.purpose === purpose && k.status === 'ACTIVE');
const keyById = (keyId) => Object.values(S.keys).flat().find((k) => k.keyId === keyId);
const jobOf = (id) => S.rotations.find((r) => r.rotationId === id) ?? fail(404, 'Rotation not found.', 'NOT_FOUND');
const liveJob = (folderId) => S.rotations.find((r) => r.folderId === folderId && BLOCKING.includes(r.status));
const SESSION_STATE = { WAITING_FOR_KEY: 'WAITING_FOR_KEY', WAITING_FOR_CLIENT: 'WAITING_FOR_CLIENT', IN_PROGRESS: 'ROTATING', WAITING_FOR_OWNER: 'WAITING_FOR_OWNER', FAILED: 'FAILED' };
const stateOf = (folderId) => SESSION_STATE[liveJob(folderId)?.status] ?? 'READY';
const gate = (folderId) => { if (stateOf(folderId) !== 'READY') fail(409, 'Keys for this folder are being updated. Try again when the update finishes.', 'KEY_SESSION_ROTATING'); };
const recipientsFor = (folderId) => S.members.filter((m) => m.folderId === folderId && m.status === 'ACTIVE').flatMap((m) => {
  const k = activeKey(m.userId, 'ENC');
  return k ? [{ membershipId: m.membershipId, recipientEncryptionKeyId: k.keyId, publicKey: k.publicKey }] : [];
});
const proofOf = (f) => f.policies.at(-1)?.signedPolicy ?? null;
const log = (type, extra = {}) => {
  const actor = me();
  const f = extra.folderId ? S.folders.find((x) => x.folderId === extra.folderId) : null;
  S.events.unshift({ eventId: uid(), occurredAt: iso(Date.now()), type, actorUserId: actor?.userId, actorName: actor?.name, folderCode: f?.code, ...extra });
};
const touch = (folderId) => { const f = S.folders.find((x) => x.folderId === folderId); if (f) f.updatedAt = iso(Date.now()); };
const activeRev = (v) => v.revisions.find((r) => r.cryptoRevisionId === v.activeRevisionId);
const realVersions = (folderId) => S.versions.filter((v) => !v.demo && S.docs.find((d) => d.documentId === v.documentId)?.folderId === folderId);

async function verifySigned(signed, userId, purposeCheck) {
  const key = activeKey(userId, 'SIGN') ?? fail(409, 'You need an active signing key.', 'KEY_NOT_READY');
  try { await verifyRecord(signed, await importSigningKey('spki', fromBase64url(key.publicKey))); } catch { fail(400, 'Invalid signature.', 'INVALID_SIGNATURE'); }
  if (purposeCheck && signed.record.purpose !== purposeCheck) fail(400, 'Unexpected signed record.', 'INVALID_SIGNATURE');
  if (signed.record.actorUserId !== userId || signed.record.actorSigningKeyId !== key.keyId) fail(400, 'Signer mismatch.', 'INVALID_SIGNATURE');
}

/* ---- rotation job lifecycle ---- */
const realItems = (j) => j.items.filter((i) => !i.sample);
const finishJob = (j, by) => {
  const f = folderOf(j.folderId);
  j.items.forEach((i) => { i.status = 'COMMITTED'; });
  f.keySessionId = j.target.keySessionId; j.status = 'COMPLETED'; j.completedAt = iso(Date.now()); j.committedByName = by;
};
// Mọi thay đổi membership / khóa bị lộ đều thay DEK của TẤT CẢ version trong folder và cấp lại envelope cho người còn lại.
async function startRotation(folderId, reason, { waitingFor = [], only } = {}) {
  const f = folderOf(folderId);
  const vs = S.versions.filter((v) => S.docs.find((d) => d.documentId === v.documentId)?.folderId === folderId && (!only || only(v)));
  const items = [];
  for (const v of vs) {
    const rev = activeRev(v);
    items.push(rev ? {
      itemId: uid(), versionId: v.versionId, documentId: v.documentId, status: 'PENDING', error: null, staged: null,
      sourceCryptoRevisionId: rev.cryptoRevisionId, sourceCryptoManifestHash: await hashRecord(rev.signedManifest),
      authorRecordHash: rev.signedManifest.record.authorRecordHash, targetCryptoRevisionId: uid(),
    } : { itemId: uid(), versionId: v.versionId, documentId: v.documentId, status: 'PENDING', sample: true, error: null });
  }
  const job = {
    rotationId: uid(), folderId, reason, status: waitingFor.length ? 'WAITING_FOR_KEY' : 'WAITING_FOR_CLIENT', waitingFor, generation: '0',
    createdAt: iso(Date.now()), completedAt: null, createdByName: need().name, claimedBy: null, committedByName: null, leaseExpiresAt: null,
    target: { keySessionId: `ks-${uid().slice(0, 8)}` }, recipients: [], items,
  };
  // Không có gì để mã hoá lại phía client (folder rỗng hoặc chỉ có dữ liệu mẫu chưa mã hoá) → server hoàn tất ngay.
  if (!waitingFor.length && realItems(job).length === 0) finishJob(job, 'System');
  S.rotations.unshift(job);
  return job;
}
const refreshWaiting = () => S.rotations.forEach((j) => {
  if (j.status !== 'WAITING_FOR_KEY') return;
  j.waitingFor = j.waitingFor.filter((u) => !activeKey(u, 'ENC'));
  if (!j.waitingFor.length) j.status = 'WAITING_FOR_CLIENT';
});
const summary = (j) => {
  const f = S.folders.find((x) => x.folderId === j.folderId);
  const m = mship(j.folderId, me()?.userId);
  return {
    rotationId: j.rotationId, folderId: j.folderId, folderCode: f?.code, folderName: f?.name, reason: j.reason, status: j.status, generation: j.generation,
    createdAt: j.createdAt, completedAt: j.completedAt, total: j.items.length,
    done: j.status === 'COMPLETED' ? j.items.length : j.items.filter((i) => ['STAGED', 'COMMITTED'].includes(i.status)).length, failed: j.items.filter((i) => i.status === 'FAILED').length,
    claimedByName: j.claimedBy ? userOf(j.claimedBy)?.name : null, committedByName: j.committedByName,
    canClaim: !!m && m.role !== 'VIEWER' && ['WAITING_FOR_CLIENT', 'IN_PROGRESS'].includes(j.status) && realItems(j).every((i) => hasEnvelope(j, i, m)),
    canCommit: !!m && m.role === 'OWNER' && j.status === 'WAITING_FOR_OWNER',
    waitingForNames: (j.waitingFor ?? []).map((u) => userOf(u)?.name),
  };
};
const itemDetail = (j, i) => {
  const v = S.versions.find((x) => x.versionId === i.versionId); const d = S.docs.find((x) => x.documentId === i.documentId);
  return { itemId: i.itemId, documentId: i.documentId, versionId: i.versionId, title: d?.title, versionNumber: v?.versionNumber, status: i.status, error: i.error, sample: !!i.sample,
    sourceCryptoRevisionId: i.sourceCryptoRevisionId, sourceCryptoManifestHash: i.sourceCryptoManifestHash, authorRecordHash: i.authorRecordHash, targetCryptoRevisionId: i.targetCryptoRevisionId };
};
const sourceRev = (i) => S.versions.find((v) => v.versionId === i.versionId).revisions.find((r) => r.cryptoRevisionId === i.sourceCryptoRevisionId);
// Nguồn hợp lệ cho rotation: người có envelope trên revision nguồn (kể cả key đã bị thu hồi/retired).
const hasEnvelope = (j, i, m) => !!sourceRev(i)?.envelopes.some((e) => e.membershipId === m.membershipId);
const multipart = (rev, extra, env, orig) => {
  const f = new FormData();
  f.append('ciphertext', new Blob([rev.ciphertext]), 'ciphertext.bin');
  f.append('signedManifest', JSON.stringify(rev.signedManifest));
  f.append('envelope', JSON.stringify(env));
  f.append('policyProof', JSON.stringify(rev.policyProof ?? null));
  if (rev.purpose === ROT_PURPOSE) { f.append('originalManifest', JSON.stringify(orig.signedManifest)); f.append('originalPolicyProof', JSON.stringify(orig.policyProof ?? null)); }
  return new Response(f);
};

/* ---------------- routes ---------------- */
const routes = [];
const on = (method, path, h) => routes.push([method, new RegExp('^' + path.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$'), h]);
const folderOut = (f, uidv) => ({
  folderId: f.folderId, code: f.code, name: f.name, treatmentRef: f.treatmentRef, description: f.description, ownerName: userOf(f.ownerId)?.name,
  role: mship(f.folderId, uidv)?.role, updatedAt: f.updatedAt, status: 'ACTIVE', policyVersion: f.policyVersion, cryptoState: stateOf(f.folderId),
});
const docOut = (d) => {
  const v = S.versions.find((x) => x.versionId === d.currentVersionId);
  return { ...d, currentVersionNumber: v?.versionNumber, size: v?.size, updatedAt: v?.createdAt, status: 'AVAILABLE' };
};
const myFolders = () => S.folders.filter((f) => mship(f.folderId, need().userId));

/* auth */
on('POST', '/auth/login', ({ b }) => {
  const u = S.users.find((x) => x.email === b.email);
  if (!u || !b.password) fail(401, 'Email or password is incorrect.', 'INVALID_CREDENTIALS');
  if (u.status !== 'ACTIVE') fail(403, 'This account is inactive.', 'ACCOUNT_INACTIVE');
  sessionStorage.setItem('mock.uid', u.userId);
  return { user: { ...u } };
});
on('GET', '/auth/me', () => ({ user: { ...need() } }));
on('POST', '/auth/logout', () => { sessionStorage.removeItem('mock.uid'); return null; });
on('GET', '/auth/csrf', () => ({ csrfToken: 'mock' }));
on('POST', '/auth/reauthenticate', ({ b }) => (b.password ? { ok: true } : fail(401, 'Password is incorrect.', 'INVALID_CREDENTIALS')));
on('GET', '/users', ({ q }) => S.users.filter((u) => u.status === 'ACTIVE' && !u.isHospitalAdmin && `${u.name} ${u.email}`.toLowerCase().includes((q.query || '').toLowerCase()))
  .map(({ userId, name, email, staffId }) => ({ userId, name, email, staffId, hasKeys: !!activeKey(userId, 'ENC') && !!activeKey(userId, 'SIGN') })));

on('GET', '/dashboard/summary', () => {
  const fs = myFolders();
  return {
    folderCount: fs.length,
    documentCount: S.docs.filter((d) => fs.some((f) => f.folderId === d.folderId)).length,
    recentFolders: [...fs].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)).slice(0, 5).map((f) => ({ folderId: f.folderId, name: `${f.name} · ${f.code}`, role: mship(f.folderId, need().userId).role, updatedAt: f.updatedAt })),
  };
});

/* folders & members */
on('GET', '/folders', () => myFolders().map((f) => folderOut(f, need().userId)));
on('POST', '/folders', async ({ b }) => {
  const u = need(); const sp = json(b.signedInitialPolicy);
  await verifySigned(sp, u.userId, 'initial-folder-policy/v1');
  if (sp.record.folderId !== b.folderId) fail(400, 'Policy folder mismatch.', 'INVALID_POLICY');
  const n = String(Math.floor(Math.random() * 90000) + 10000);
  const f = { folderId: b.folderId, code: `TF-2026-${n}`, name: b.name, treatmentRef: b.treatmentRef || `TR-${n}`, description: b.description, ownerId: u.userId, updatedAt: iso(Date.now()),
    policies: [{ version: 1, signedPolicy: sp }], policyVersion: 1, policyHash: await hashRecord(sp), keySessionId: `ks-${uid().slice(0, 8)}` };
  S.folders.unshift(f);
  S.members.push({ membershipId: uid(), folderId: f.folderId, userId: u.userId, role: 'OWNER', status: 'ACTIVE' });
  log('FOLDER_CREATED', { folderId: f.folderId, itemName: f.name });
  return folderOut(f, u.userId);
});
on('GET', '/folders/:id', ({ p }) => { must(p.id); return folderOut(folderOf(p.id), need().userId); });
on('PATCH', '/folders/:id', ({ p, b }) => { must(p.id, 'OWNER', 'EDITOR'); const f = folderOf(p.id); log('FOLDER_RENAMED', { folderId: p.id, itemName: b.name, detail: `Was “${f.name}”` }); Object.assign(f, { name: b.name, description: b.description, updatedAt: iso(Date.now()) }); return null; });
on('DELETE', '/folders/:id', ({ p }) => { must(p.id, 'OWNER'); log('FOLDER_DELETED', { folderId: p.id, itemName: folderOf(p.id).name }); S.folders.splice(S.folders.indexOf(folderOf(p.id)), 1); return { operationId: uid() }; });
on('GET', '/folders/:id/members', ({ p }) => { must(p.id); return S.members.filter((m) => m.folderId === p.id && m.status === 'ACTIVE').map((m) => { const u = userOf(m.userId); return { membershipId: m.membershipId, userId: u.userId, name: u.name, email: u.email, role: m.role, status: 'ACTIVE' }; }); });
on('POST', '/folders/:id/policy-contexts', ({ p, b }) => {
  must(p.id, 'OWNER');
  const c = { contextId: uid(), folderId: p.id, action: b.action, nonce: base64url(crypto.getRandomValues(new Uint8Array(16))), expiresAt: iso(Date.now() + 300000), expectedPolicyVersion: String(folderOf(p.id).policyVersion), targetUserId: b.targetUserId, membershipId: b.membershipId, role: b.role };
  Object.keys(c).forEach((k) => c[k] === undefined && delete c[k]);
  S.ctxs[c.contextId] = { ...c, used: false };
  return c;
});
async function applyPolicy(folderId, contextId, signedPolicy, action) {
  const c = S.ctxs[contextId];
  if (!c || c.used || c.action !== action || c.folderId !== folderId || Date.parse(c.expiresAt) < Date.now()) fail(400, 'Policy context is invalid or expired.', 'INVALID_POLICY');
  await verifySigned(signedPolicy, need().userId, 'folder-policy/v1');
  if (signedPolicy.record.context.contextId !== contextId) fail(400, 'Policy context mismatch.', 'INVALID_POLICY');
  const f = folderOf(folderId);
  c.used = true; f.policyVersion += 1; f.policies.push({ version: f.policyVersion, signedPolicy }); f.policyHash = await hashRecord(signedPolicy);
  return c;
}
on('POST', '/folders/:id/members', async ({ p, b }) => {
  must(p.id, 'OWNER'); const c = await applyPolicy(p.id, b.contextId, b.signedPolicy, 'ADD_MEMBER');
  if (c.targetUserId !== b.userId) fail(400, 'Policy target mismatch.', 'INVALID_POLICY');
  if (!activeKey(b.userId, 'ENC') || !activeKey(b.userId, 'SIGN')) { c.used = false; fail(409, 'This person has not set up their keys yet. Ask them to sign in and set up keys first.', 'KEY_NOT_READY'); }
  const m = { membershipId: uid(), folderId: p.id, userId: b.userId, role: c.role, status: 'ACTIVE' };
  S.members.push(m); touch(p.id);
  log('MEMBER_ADDED', { folderId: p.id, itemName: userOf(b.userId).name, detail: `Role: ${c.role}` });
  const job = await startRotation(p.id, 'MEMBER_ADDED');
  return { rotationId: job?.rotationId ?? null };
});
on('PATCH', '/folders/:id/members/:mid', async ({ p, b }) => {
  must(p.id, 'OWNER'); const c = await applyPolicy(p.id, b.contextId, b.signedPolicy, 'CHANGE_ROLE');
  const m = S.members.find((x) => x.membershipId === p.mid); m.role = c.role;
  log('MEMBER_ROLE_CHANGED', { folderId: p.id, itemName: userOf(m.userId).name, detail: `New role: ${c.role}` });
  const job = await startRotation(p.id, 'ROLE_CHANGED');
  return { rotationId: job?.rotationId ?? null };
});
on('DELETE', '/folders/:id/members/:mid', async ({ p, headers = {} }) => {
  must(p.id, 'OWNER');
  const contextId = headers['X-Policy-Context-Id']; const signedPolicy = JSON.parse(new TextDecoder().decode(fromBase64url(headers['X-Policy-Signature'] ?? '')));
  await applyPolicy(p.id, contextId, signedPolicy, 'REVOKE_MEMBER');
  const m = S.members.find((x) => x.membershipId === p.mid); m.status = 'REVOKED'; S.krr += 1;
  log('MEMBER_REVOKED', { folderId: p.id, itemName: userOf(m.userId).name });
  const job = await startRotation(p.id, 'MEMBER_REVOKED');
  return { rotationId: job?.rotationId ?? null };
});
on('GET', '/folders/:id/policies/:v', ({ p }) => {
  must(p.id); const f = folderOf(p.id);
  const ids = new Set(S.members.filter((m) => m.folderId === p.id).map((m) => m.userId));
  return {
    policyVersion: Number(p.v), ownerUserId: f.ownerId, signedPolicy: f.policies.find((x) => x.version === Number(p.v))?.signedPolicy ?? null,
    bindings: [...ids].flatMap((u) => myKeys(u).map((k) => ({ userId: u, keyId: k.keyId, purpose: k.purpose, publicKey: k.publicKey, status: k.status }))),
  };
});
on('GET', '/folders/:id/key-sessions/current', ({ p }) => { must(p.id); const f = folderOf(p.id); return { sessionId: f.keySessionId, state: stateOf(p.id) }; });

/* documents */
on('GET', '/folders/:id/documents', ({ p }) => { must(p.id); return S.docs.filter((d) => d.folderId === p.id).map(docOut); });
on('POST', '/folders/:id/upload-contexts', ({ p, b }) => {
  must(p.id, 'OWNER', 'EDITOR'); gate(p.id);
  const u = need();
  if (!activeKey(u.userId, 'ENC') || !activeKey(u.userId, 'SIGN')) fail(409, 'Set up your encryption and signing keys in Security & keys first.', 'KEY_NOT_READY');
  const f = folderOf(p.id);
  const ctx = {
    contextId: uid(), purpose: b.purpose, expiresAt: iso(Date.now() + 600000), folderId: p.id, documentId: b.documentId ?? uid(), versionId: uid(), cryptoRevisionId: uid(),
    keySessionId: f.keySessionId, policyHash: f.policyHash, keyRegistryRevision: String(S.krr), recipients: recipientsFor(p.id),
  };
  if (b.purpose === 'NEW_VERSION') {
    const d = S.docs.find((x) => x.documentId === b.documentId) ?? fail(404, 'Document not found.', 'NOT_FOUND');
    if (d.currentVersionId !== b.baseVersionId) fail(409, 'A newer version exists. Reload and try again.', 'VERSION_CONFLICT');
    ctx.baseVersionId = b.baseVersionId;
  }
  S.ctxs[ctx.contextId] = { ...ctx, userId: u.userId, used: false };
  return ctx;
});
async function acceptUpload(form, folderId, expectPurpose) {
  const u = need(); const ctx = S.ctxs[form.get('contextId')];
  if (!ctx || ctx.used || ctx.userId !== u.userId || ctx.folderId !== folderId || Date.parse(ctx.expiresAt) < Date.now()) fail(400, 'Upload context is invalid or expired.', 'INVALID_CONTEXT');
  const sm = json(form.get('signedManifest')); const r = sm.record;
  await verifySigned(sm, u.userId);
  if (r.purpose !== expectPurpose || r.contextId !== ctx.contextId || r.versionId !== ctx.versionId || r.cryptoRevisionId !== ctx.cryptoRevisionId || r.policyHash !== ctx.policyHash) fail(400, 'Manifest does not match the upload context.', 'INVALID_MANIFEST');
  const envelopes = json(form.get('envelopes'));
  const need_ = new Set(ctx.recipients.map((x) => x.membershipId));
  if (envelopes.length !== need_.size || !envelopes.every((e) => need_.has(e.membershipId))) fail(400, 'Envelopes must cover exactly the recipients in the upload context.', 'INVALID_ENVELOPES');
  const buf = await form.get('ciphertext').arrayBuffer();
  if (await hashBytes(buf) !== r.ciphertextHash) fail(400, 'Ciphertext hash mismatch.', 'INVALID_MANIFEST');
  ctx.used = true;
  const f = folderOf(folderId);
  return { ctx, version: { versionId: ctx.versionId, documentId: ctx.documentId, createdByName: u.name, createdAt: iso(Date.now()), size: buf.byteLength, activeRevisionId: ctx.cryptoRevisionId,
    revisions: [{ cryptoRevisionId: ctx.cryptoRevisionId, keySessionId: ctx.keySessionId, policyHash: ctx.policyHash, keyRegistryRevision: ctx.keyRegistryRevision, purpose: r.purpose, ciphertext: buf, signedManifest: sm, envelopes, policyProof: proofOf(f), createdAt: iso(Date.now()) }] } };
}
on('POST', '/folders/:id/documents', async ({ p, b }) => {
  must(p.id, 'OWNER', 'EDITOR'); gate(p.id);
  const { ctx, version } = await acceptUpload(b, p.id, 'document-upload/v1');
  version.versionNumber = 1; S.versions.push(version);
  const d = { documentId: ctx.documentId, folderId: p.id, title: b.get('title'), category: b.get('category'), uploadedByName: need().name, createdAt: iso(Date.now()), currentVersionId: version.versionId };
  S.docs.push(d); touch(p.id); log('DOCUMENT_UPLOADED', { folderId: p.id, itemName: d.title });
  return { documentId: d.documentId, versionId: version.versionId };
});
const docOr404 = (id) => S.docs.find((d) => d.documentId === id) ?? fail(404, 'Document not found.', 'NOT_FOUND');
on('GET', '/documents/:id', ({ p }) => { const d = docOr404(p.id); must(d.folderId); return docOut(d); });
on('PATCH', '/documents/:id', ({ p, b }) => { const d = docOr404(p.id); must(d.folderId, 'OWNER', 'EDITOR'); Object.assign(d, { title: b.title, category: b.category }); return null; });
on('DELETE', '/documents/:id', ({ p }) => {
  const d = docOr404(p.id); must(d.folderId, 'OWNER'); gate(d.folderId);
  S.versions = S.versions.filter((v) => v.documentId !== p.id); S.docs.splice(S.docs.indexOf(d), 1); log('DOCUMENT_DELETED', { folderId: d.folderId, itemName: d.title }); return null;
});
on('GET', '/documents/:id/versions', ({ p }) => { const d = docOr404(p.id); must(d.folderId); return S.versions.filter((v) => v.documentId === p.id).sort((a, b) => b.versionNumber - a.versionNumber)
  .map((v) => ({ versionId: v.versionId, versionNumber: v.versionNumber, createdByName: v.createdByName, createdAt: v.createdAt, size: v.size, isCurrent: v.versionId === d.currentVersionId })); });
on('POST', '/documents/:id/versions', async ({ p, b }) => {
  const d = docOr404(p.id); must(d.folderId, 'OWNER', 'EDITOR'); gate(d.folderId);
  const { ctx, version } = await acceptUpload(b, d.folderId, 'document-version/v1');
  if (ctx.baseVersionId !== d.currentVersionId) fail(409, 'A newer version exists. Reload and try again.', 'VERSION_CONFLICT');
  version.versionNumber = Math.max(...S.versions.filter((v) => v.documentId === p.id).map((v) => v.versionNumber)) + 1;
  S.versions.push(version); d.currentVersionId = version.versionId; touch(d.folderId); log('DOCUMENT_VERSION_ADDED', { folderId: d.folderId, itemName: d.title, detail: `v${version.versionNumber}` });
  return { versionId: version.versionId };
});
const verOr404 = (id) => S.versions.find((v) => v.versionId === id) ?? fail(404, 'Version not found.', 'NOT_FOUND');
on('GET', '/versions/:id/manifest', ({ p }) => {
  const v = verOr404(p.id); const d = docOr404(v.documentId); const m = must(d.folderId); gate(d.folderId);
  if (v.demo) return { versionId: v.versionId, documentId: d.documentId, folderId: d.folderId, demo: true };
  const rev = activeRev(v);
  // Envelope chỉ hợp lệ nếu gắn với key ĐANG ACTIVE của người đọc → key bị lộ không mở được bản mới.
  const env = rev.envelopes.find((e) => e.membershipId === m.membershipId && keyById(e.recipientEncryptionKeyId)?.status === 'ACTIVE')
    ?? fail(403, 'No key envelope for your current key on this version.', 'NO_ENVELOPE');
  const orig = v.revisions[0]; const rot = rev.signedManifest.record;
  return {
    versionId: v.versionId, documentId: d.documentId, folderId: d.folderId,
    activeRevision: { cryptoRevisionId: rev.cryptoRevisionId, keySessionId: rev.keySessionId, policyHash: rev.policyHash, keyRegistryRevision: rev.keyRegistryRevision, purpose: rev.purpose,
      ...(rev.purpose === ROT_PURPOSE ? { rotationId: rot.rotationId, itemId: rot.itemId, generation: rot.generation } : {}) },
    signedManifest: rev.signedManifest, envelope: env, policyProof: rev.policyProof,
    ...(rev.purpose === ROT_PURPOSE ? { originalManifest: orig.signedManifest, originalPolicyProof: orig.policyProof } : {}),
  };
});
on('GET', '/versions/:id/content', ({ p, q }) => {
  const v = verOr404(p.id); const d = docOr404(v.documentId); must(d.folderId); gate(d.folderId);
  if (v.demo) return new Blob(['demo']);
  if (q.cryptoRevisionId && q.cryptoRevisionId !== v.activeRevisionId) fail(409, 'The version was re-encrypted. Fetch a fresh manifest.', 'REVISION_CONFLICT');
  log('DOCUMENT_DOWNLOADED', { folderId: d.folderId, itemName: d.title, detail: `v${v.versionNumber}` });
  return new Blob([activeRev(v).ciphertext]);
});

/* keys */
on('GET', '/users/me/keys', () => myKeys().map((k) => ({ keyId: k.keyId, purpose: k.purpose, status: k.status, publicKey: k.publicKey, publicKeyFingerprint: k.publicKeyFingerprint, createdAt: k.createdAt, revokedAt: k.revokedAt })));
on('POST', '/users/me/keys', async ({ b }) => {
  const u = need();
  if (!['ENC', 'SIGN'].includes(b.purpose)) fail(400, 'Unknown key purpose.');
  const spki = fromBase64url(b.publicKey);
  if (base64url(await sha256(spki)) !== b.publicKeyFingerprint) fail(400, 'Fingerprint mismatch.');
  const keyId = `${b.purpose === 'ENC' ? 'enc' : 'sig'}_key_${uid()}`;
  const record = { purpose: 'key-proof/v1', keyPurpose: b.purpose, userId: u.userId, keyId, nonce: base64url(crypto.getRandomValues(new Uint8Array(16))), expiresAt: iso(Date.now() + 300000) };
  const challenge = { userId: u.userId, keyId, purpose: b.purpose, nonce: record.nonce, expiresAt: record.expiresAt };
  let secret = null;
  if (b.purpose === 'ENC') {
    secret = crypto.getRandomValues(new Uint8Array(32));
    const label = await sha256(canonicalBytes(record));
    challenge.ciphertext = base64url(await crypto.subtle.encrypt({ name: 'RSA-OAEP', label }, await importEncryptionKey('spki', spki), secret));
  } else await importSigningKey('spki', spki);
  myKeys().push({ keyId, purpose: b.purpose, status: 'PENDING_VERIFICATION', publicKey: b.publicKey, publicKeyFingerprint: b.publicKeyFingerprint, createdAt: iso(Date.now()) });
  S.challenges[keyId] = { record, secret: secret && base64url(secret) };
  return { keyId, challenge };
});
on('POST', '/users/me/keys/:id/activate', async ({ p, b }) => {
  const u = need(); const k = myKeys().find((x) => x.keyId === p.id) ?? fail(404, 'Key not found.', 'NOT_FOUND'); const ch = S.challenges[p.id];
  if (!ch || k.status !== 'PENDING_VERIFICATION') fail(409, 'Key is not waiting for verification.', 'INVALID_STATE');
  if (k.purpose === 'ENC') { if (b.response !== ch.secret) fail(400, 'Challenge answer is wrong.', 'INVALID_PROOF'); }
  else { try { await verifyRecord({ record: ch.record, signature: b.response }, await importSigningKey('spki', fromBase64url(k.publicKey))); } catch { fail(400, 'Challenge signature is wrong.', 'INVALID_PROOF'); } }
  myKeys().filter((x) => x.purpose === k.purpose && x.status === 'ACTIVE').forEach((x) => { x.status = 'RETIRED'; });
  k.status = 'ACTIVE'; delete S.challenges[p.id]; S.krr += 1; refreshWaiting();
  log('KEY_REGISTERED', { keyType: k.purpose, keyId: k.keyId, result: 'SUCCESS', detail: `Key activated for ${u.name}` });
  return { keyId: k.keyId, status: k.status };
});
on('PUT', '/users/me/keys/:id/backup', ({ p, b }) => { const k = myKeys().find((x) => x.keyId === p.id) ?? fail(404, 'Key not found.', 'NOT_FOUND'); S.backups[p.id] = b.backup; log('KEY_BACKUP_SAVED', { keyType: k.purpose, keyId: k.keyId, result: 'SUCCESS' }); return null; });
on('GET', '/users/me/keys/:id/backup', ({ p }) => {
  const k = myKeys().find((x) => x.keyId === p.id) ?? fail(404, 'Key not found.', 'NOT_FOUND');
  return { backup: S.backups[p.id] ?? fail(404, 'No backup saved for this key.', 'NOT_FOUND'), publicKey: k.publicKey, binding: { userId: need().userId, keyId: k.keyId, purpose: k.purpose, publicKeyFingerprint: k.publicKeyFingerprint } };
});
on('POST', '/users/me/keys/:id/compromise', async ({ p }) => {
  const u = need(); const k = myKeys().find((x) => x.keyId === p.id) ?? fail(404, 'Key not found.', 'NOT_FOUND');
  if (k.status === 'REVOKED') fail(409, 'Key is already revoked.', 'INVALID_STATE');
  k.status = 'REVOKED'; k.revokedAt = iso(Date.now()); S.krr += 1;
  log('KEY_COMPROMISE_REPORTED', { keyType: k.purpose, keyId: k.keyId, result: 'SUCCESS', detail: 'Key revoked. Sessions closed. Document keys will be replaced.' });
  const affected = [];
  if (k.purpose === 'ENC') {
    for (const f of S.folders.filter((x) => mship(x.folderId, u.userId))) {
      const touched = realVersions(f.folderId).some((v) => activeRev(v)?.envelopes.some((e) => e.recipientEncryptionKeyId === k.keyId));
      if (!touched) continue;
      const job = await startRotation(f.folderId, 'KEY_COMPROMISE', { waitingFor: activeKey(u.userId, 'ENC') ? [] : [u.userId] });
      if (job) affected.push(job.rotationId);
    }
  }
  return { rotationIds: affected };
});
on('GET', '/users/me/devices', () => S.devices[need().userId] ?? []);
on('POST', '/users/me/devices', ({ b }) => { const d = { deviceId: uid(), name: b.name, lastActiveAt: iso(Date.now()), status: 'ACTIVE' }; (S.devices[need().userId] ??= []).push(d); log('DEVICE_REGISTERED', { itemName: b.name }); return d; });
on('DELETE', '/users/me/devices/:id', ({ p }) => { const l = S.devices[need().userId]; l.splice(l.findIndex((d) => d.deviceId === p.id), 1); log('DEVICE_REVOKED', {}); return null; });

/* rotation */
on('GET', '/key-rotations', () => S.rotations.filter((j) => { const m = mship(j.folderId, need().userId); return m && m.role !== 'VIEWER'; }).map(summary));
on('GET', '/key-rotations/:id', ({ p }) => {
  const j = jobOf(p.id); const m = mship(j.folderId, need().userId); if (!m || m.role === 'VIEWER') fail(403, 'Not allowed.', 'FORBIDDEN');
  return { ...summary(j), keySessionId: j.target.keySessionId, policyHash: j.target.policyHash, keyRegistryRevision: j.target.keyRegistryRevision, itemIds: realItems(j).map((i) => i.itemId), items: j.items.map((i) => itemDetail(j, i)),
    recipientNames: (j.status === 'COMPLETED' || j.generation !== '0' ? j.recipients : recipientsFor(j.folderId)).map((r) => userOf(S.members.find((m) => m.membershipId === r.membershipId)?.userId)?.name) };
});
on('POST', '/key-rotations/:id/claim', ({ p }) => {
  const j = jobOf(p.id); const m = mship(j.folderId, need().userId);
  if (!m || m.role === 'VIEWER') fail(403, 'Only Owners and Editors can run a key update.', 'FORBIDDEN');
  if (j.status === 'IN_PROGRESS' && j.claimedBy !== need().userId && Date.parse(j.leaseExpiresAt) > Date.now()) fail(409, 'Another member is already running this key update.', 'LEASE_HELD');
  if (!['WAITING_FOR_CLIENT', 'IN_PROGRESS'].includes(j.status)) fail(409, j.status === 'WAITING_FOR_KEY' ? 'Waiting for a member to register new keys.' : 'This key update cannot be claimed now.', 'INVALID_STATE');
  if (!realItems(j).every((i) => hasEnvelope(j, i, m))) fail(403, 'You do not hold a valid source key for these documents.', 'NO_VALID_SOURCE');
  const f = folderOf(j.folderId);
  j.generation = String(Number(j.generation) + 1); j.claimedBy = need().userId; j.status = 'IN_PROGRESS'; j.leaseExpiresAt = iso(Date.now() + 300000);
  j.target = { ...j.target, policyHash: f.policyHash, keyRegistryRevision: String(S.krr) }; j.recipients = recipientsFor(j.folderId);
  j.items.forEach((i) => { i.status = i.sample ? 'STAGED' : 'PENDING'; i.staged = null; i.error = null; });
  return { generation: j.generation, leaseExpiresAt: j.leaseExpiresAt };
});
const lease = (j) => { if (j.claimedBy !== need().userId || j.status !== 'IN_PROGRESS' || Date.parse(j.leaseExpiresAt) < Date.now()) fail(409, 'You no longer hold the lease for this key update.', 'LEASE_LOST'); };
on('POST', '/key-rotations/:id/lease/renew', ({ p }) => { const j = jobOf(p.id); lease(j); j.leaseExpiresAt = iso(Date.now() + 300000); return { leaseExpiresAt: j.leaseExpiresAt }; });
on('GET', '/key-rotations/:id/items', ({ p }) => {
  const j = jobOf(p.id); lease(j);
  return realItems(j).map((i) => { const r = sourceRev(i); const rec = r.signedManifest.record;
    return { ...itemDetail(j, i), recipients: j.recipients,
      source: { cryptoRevisionId: r.cryptoRevisionId, keySessionId: r.keySessionId, policyHash: r.policyHash, keyRegistryRevision: r.keyRegistryRevision, purpose: r.purpose,
        ...(r.purpose === ROT_PURPOSE ? { rotationId: rec.rotationId, itemId: rec.itemId, generation: rec.generation } : {}) } }; });
});
on('GET', '/key-rotations/:id/items/:itemId/source', ({ p }) => {
  const j = jobOf(p.id); lease(j); const m = mship(j.folderId, need().userId); const i = j.items.find((x) => x.itemId === p.itemId) ?? fail(404, 'Item not found.', 'NOT_FOUND');
  const rev = sourceRev(i); const env = rev.envelopes.find((e) => e.membershipId === m.membershipId) ?? fail(403, 'No source envelope for you.', 'NO_VALID_SOURCE');
  return multipart(rev, null, env, S.versions.find((v) => v.versionId === i.versionId).revisions[0]);
});
on('PUT', '/key-rotations/:id/items/:itemId/result', async ({ p, b }) => {
  const j = jobOf(p.id); lease(j); const i = j.items.find((x) => x.itemId === p.itemId) ?? fail(404, 'Item not found.', 'NOT_FOUND');
  const sm = json(b.get('signedManifest')); const r = sm.record;
  await verifySigned(sm, need().userId, ROT_PURPOSE);
  if (r.rotationId !== j.rotationId || r.itemId !== i.itemId || r.generation !== j.generation || r.cryptoRevisionId !== i.targetCryptoRevisionId || r.keySessionId !== j.target.keySessionId || r.sourceCryptoRevisionId !== i.sourceCryptoRevisionId) fail(400, 'Rotation manifest does not match the job.', 'INVALID_MANIFEST');
  if (r.authorRecordHash !== i.authorRecordHash) fail(400, 'Author record must not change during rotation.', 'INVALID_MANIFEST');
  const envelopes = json(b.get('envelopes')); const want = new Set(j.recipients.map((x) => x.membershipId));
  if (envelopes.length !== want.size || !envelopes.every((e) => want.has(e.membershipId))) fail(400, 'Envelopes must cover exactly the target recipients.', 'INVALID_ENVELOPES');
  const buf = await b.get('ciphertext').arrayBuffer();
  if (await hashBytes(buf) !== r.ciphertextHash) fail(400, 'Ciphertext hash mismatch.', 'INVALID_MANIFEST');
  i.staged = { ciphertext: buf, signedManifest: sm, envelopes }; i.status = 'STAGED';
  if (j.items.every((x) => x.status === 'STAGED')) j.status = 'WAITING_FOR_OWNER';
  return null;
});
on('GET', '/key-rotations/:id/items/:itemId/result', ({ p }) => {
  const j = jobOf(p.id); const m = must(j.folderId, 'OWNER'); const i = j.items.find((x) => x.itemId === p.itemId) ?? fail(404, 'Item not found.', 'NOT_FOUND');
  if (!i.staged) fail(409, 'Nothing staged for this item.', 'INVALID_STATE');
  const env = i.staged.envelopes.find((e) => e.membershipId === m.membershipId) ?? fail(403, 'No staged envelope for you. Set up your keys first.', 'NO_ENVELOPE');
  const v = S.versions.find((x) => x.versionId === i.versionId);
  return multipart({ ciphertext: i.staged.ciphertext, signedManifest: i.staged.signedManifest, policyProof: proofOf(folderOf(j.folderId)), purpose: ROT_PURPOSE }, null, env, v.revisions[0]);
});
on('POST', '/key-rotations/:id/commit', async ({ p, b }) => {
  const j = jobOf(p.id); must(j.folderId, 'OWNER');
  if (j.status !== 'WAITING_FOR_OWNER') fail(409, 'This key update is not ready to be activated.', 'INVALID_STATE');
  const sc = json(b.signedCommit); await verifySigned(sc, need().userId, 'rotation-commit/v1');
  const r = sc.record;
  if (r.rotationId !== j.rotationId || r.generation !== j.generation || r.keySessionId !== j.target.keySessionId || r.policyHash !== j.target.policyHash || r.results.length !== realItems(j).length) fail(400, 'Commit does not match the key update.', 'INVALID_COMMIT');
  for (const i of realItems(j)) {
    const res = r.results.find((x) => x.itemId === i.itemId);
    if (!res || res.cryptoRevisionId !== i.targetCryptoRevisionId || res.manifestHash !== await hashRecord(i.staged.signedManifest)) fail(400, 'Commit result mismatch.', 'INVALID_COMMIT');
  }
  const f = folderOf(j.folderId); const rec = (i) => i.staged.signedManifest.record;
  for (const i of realItems(j)) {
    const v = S.versions.find((x) => x.versionId === i.versionId);
    v.revisions.push({ cryptoRevisionId: i.targetCryptoRevisionId, keySessionId: j.target.keySessionId, policyHash: j.target.policyHash, keyRegistryRevision: j.target.keyRegistryRevision, purpose: ROT_PURPOSE,
      ciphertext: i.staged.ciphertext, signedManifest: i.staged.signedManifest, envelopes: i.staged.envelopes, policyProof: proofOf(f), rotation: { rotationId: j.rotationId, itemId: i.itemId, generation: rec(i).generation }, createdAt: iso(Date.now()) });
    v.activeRevisionId = i.targetCryptoRevisionId; i.staged = { ...i.staged, ciphertext: null };
  }
  finishJob(j, need().name);
  return { status: 'COMPLETED' };
});
on('POST', '/key-rotations/:id/retry', ({ p, b }) => {
  const j = jobOf(p.id); must(j.folderId, 'OWNER');
  if (!['FAILED', 'WAITING_FOR_OWNER'].includes(j.status)) fail(409, 'Nothing to retry.', 'INVALID_STATE');
  const rej = new Set(b?.rejectedItemIds ?? j.items.map((i) => i.itemId));
  j.items.forEach((i) => { if (rej.has(i.itemId)) { i.status = 'PENDING'; i.staged = null; } });
  j.status = 'WAITING_FOR_CLIENT'; j.claimedBy = null; return null;
});

/* audit */
// Audit log = hoạt động CỦA CHÍNH USER ĐANG ĐĂNG NHẬP về tài liệu / folder / quyền thành viên.
// Sự kiện khóa & rotation nằm ở /key-rotations và category=KEY, không có trong audit.
const AUDIT_TYPES = /^(DOCUMENT_|FOLDER_|MEMBER_)/;
on('GET', '/audit-events', ({ q }) => {
  const u = need();
  if (q.scope === 'admin') return S.adminEvents;
  if (q.category === 'KEY') return S.events.filter((e) => /^KEY_/.test(e.type) && e.actorUserId === u.userId);
  return S.events.filter((e) => AUDIT_TYPES.test(e.type) && e.actorUserId === u.userId && (!q.folderId || e.folderId === q.folderId));
});

/* admin */
const adminOnly = () => (need().isHospitalAdmin ? true : fail(403, 'Hospital Administrator only.', 'FORBIDDEN'));
const adminLog = (type, u, result) => S.adminEvents.unshift({ eventId: uid(), occurredAt: iso(Date.now()), type, staffId: u.staffId, result });
on('GET', '/admin/users', () => { adminOnly(); return S.users.filter((u) => !u.isHospitalAdmin); });
on('POST', '/admin/users', ({ b }) => { adminOnly(); const u = { userId: uid(), status: 'ACTIVE', createdAt: iso(Date.now()), ...b }; S.users.push(u); adminLog('ACCOUNT_CREATED', u, 'Created'); return u; });
on('GET', '/admin/users/:id', ({ p }) => { adminOnly(); return userOf(p.id) ?? fail(404, 'Account not found.', 'NOT_FOUND'); });
on('PATCH', '/admin/users/:id', ({ p, b }) => { adminOnly(); const u = userOf(p.id); Object.assign(u, b); adminLog('ACCOUNT_UPDATED', u, 'Updated'); return u; });
on('PATCH', '/admin/users/:id/status', ({ p, b }) => { adminOnly(); const u = userOf(p.id); u.status = b.status; adminLog('ACCOUNT_STATUS_CHANGED', u, b.status === 'ACTIVE' ? 'Reactivated' : 'Deactivated'); return u; });

export function mockHandle(method, path, { query = {}, body, headers } = {}) {
  const run = async () => {
    await load(); await sleep(80);
    for (const [m, re, h] of routes) {
      if (m !== method) continue;
      const x = re.exec(path);
      if (!x) continue;
      try { return await h({ p: x.groups ?? {}, q: query, b: body, headers }); }
      finally { if (method !== 'GET') await save(); }
    }
    throw new ApiError(404, { message: `Mock: ${method} ${path} is not implemented.` });
  };
  const next = queue.then(run, run);
  queue = next.catch(() => {});
  return next;
}

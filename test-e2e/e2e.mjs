import 'fake-indexeddb/auto';
const store = new Map();
globalThis.sessionStorage = { getItem: k => store.get(k) ?? null, setItem: (k, v) => store.set(k, String(v)), removeItem: k => store.delete(k) };
import { api } from '../src/api/endpoints.js';
import * as V from '../src/services/vault.js';
import * as D from '../src/services/documents.js';
import * as ROT from '../src/services/rotation.js';
import { signFolderPolicy, signInitialFolderPolicy, loadLocalKey } from '../src/crypto/index.js';
const { openVersion } = D;

let n = 0; const ok = (c, m) => { if (!c) { console.error('FAIL:', m); process.exit(1); } console.log(`ok ${String(++n).padStart(2)}  ${m}`); };
const rejects = async (p, re, m) => { try { await p; } catch (e) { ok(re.test(`${e.code} ${e.message}`), `${m} → ${e.code ?? e.message}`); return; } ok(false, m + ' (did not throw)'); };
const login = async (email) => { await api.logout().catch(() => {}); const r = await api.login(email, 'x'); return (await api.getCurrentUser()).user; };
const mkFile = (txt, name) => new File([new TextEncoder().encode(txt)], name, { type: 'application/pdf' });
const text = async (o) => new TextDecoder().decode(await o.blob.arrayBuffer());
const PASS = 'correct horse battery';

/* --- riley: keys + folder + uploads --- */
let riley = await login('riley@hospital.org');
await V.setupKeys(riley.userId, PASS);
let ov = await V.keyOverview(riley.userId);
ok(ov.ENC?.status === 'ACTIVE' && ov.SIGN?.status === 'ACTIVE' && ov.ENC.onDevice, 'riley: 2 key pairs ACTIVE, private keys on device');
const oldEncId = ov.ENC.id;

const folderId = crypto.randomUUID();
{
  const keys = await V.loadKeys(); const signer = await V.loadSigner(riley.userId, keys);
  const policy = { policyVersion: '1', members: [{ userId: riley.userId, role: 'OWNER', encryptionKeyId: V.activeKey(keys, 'ENC').id }] };
  await api.createFolder({ folderId, name: 'E2E folder', signedInitialPolicy: await signInitialFolderPolicy({ folderId, policy, signer }) });
}
ok((await api.getFolder(folderId)).role === 'OWNER', 'folder created with signed initial policy');
const a = await D.uploadNewDocument({ folderId, title: 'A', category: 'Other', file: mkFile('alpha v1', 'a.pdf'), userId: riley.userId });
const b = await D.uploadNewDocument({ folderId, title: 'B', category: 'Other', file: mkFile('bravo v1', 'b.pdf'), userId: riley.userId });
let da = await api.getDocument(a.documentId);
await D.uploadNewVersion({ folderId, documentId: a.documentId, baseVersionId: da.currentVersionId, file: mkFile('alpha v2', 'a.pdf'), userId: riley.userId });
da = await api.getDocument(a.documentId);
let opened = await openVersion({ versionId: da.currentVersionId, userId: riley.userId });
ok(await text(opened) === 'alpha v2' && opened.metadata.fileName === 'a.pdf' && opened.integrity.ok, 'riley opens A v2 (signature + policy proof + hash verified; metadata decrypted)');
const srvDocs = await api.listFolderDocuments(folderId);
ok(!JSON.stringify(srvDocs).includes('a.pdf'), 'server-visible metadata does not contain the file name');

/* --- alex joins: keys → add member → rotation --- */
const alex = await login('alex@hospital.org');
await V.setupKeys(alex.userId, PASS);
riley = await login('riley@hospital.org');
{
  const signer = await V.loadSigner(riley.userId);
  const ctx = await api.createPolicyContext(folderId, { action: 'ADD_MEMBER', targetUserId: alex.userId, role: 'EDITOR' });
  const signedPolicy = await signFolderPolicy({ context: ctx, signer });
  const r = await api.addFolderMember(folderId, { contextId: ctx.contextId, signedPolicy, userId: alex.userId, role: 'EDITOR' });
  ok(!!r.rotationId, 'riley adds alex (signed policy) → rotation job created');
}
ok((await api.getCurrentKeySession(folderId)).state === 'WAITING_FOR_CLIENT', 'folder key session is WAITING_FOR_CLIENT');
await rejects(openVersion({ versionId: da.currentVersionId, userId: riley.userId }), /KEY_SESSION_ROTATING/, 'opening documents is blocked while keys are changing');
let job = (await api.listRotations()).find((j) => j.folderId === folderId);
ok(job.total === 3 && job.canClaim, 'job covers 3 document versions; riley can claim');
await ROT.runRotation({ rotationId: job.rotationId, userId: riley.userId });
job = (await api.listRotations()).find((j) => j.rotationId === job.rotationId);
ok(job.status === 'WAITING_FOR_OWNER' && job.done === 3, 'executor staged 3/3 → WAITING_FOR_OWNER');
await ROT.commitRotationAsOwner({ rotationId: job.rotationId, userId: riley.userId });
ok((await api.getRotation(job.rotationId)).status === 'COMPLETED', 'Owner verified staged items + signed commit → COMPLETED');
const alex2 = await login('alex@hospital.org');
ok(await text(await openVersion({ versionId: da.currentVersionId, userId: alex2.userId })) === 'alpha v2', 'alex (new member) can now open A v2');
riley = await login('riley@hospital.org');
ok(await text(await openVersion({ versionId: da.currentVersionId, userId: riley.userId })) === 'alpha v2', 'riley still opens A v2 on the rotated revision');

/* --- compromise --- */
await api.reportKeyCompromise(oldEncId, { reason: 'USER_REPORTED' });
await rejects(openVersion({ versionId: da.currentVersionId, userId: riley.userId }), /KEY_SESSION_ROTATING/, 'after compromise: documents locked');
riley = await login('riley@hospital.org'); // "đăng nhập lại"
await rejects(openVersion({ versionId: da.currentVersionId, userId: riley.userId }), /KEY_SESSION_ROTATING/, 'after re-login: STILL cannot open documents with the old key');
ov = await V.keyOverview(riley.userId);
ok(!ov.ENC && ov.history.some((h) => h.id === oldEncId && h.status === 'REVOKED'), 'Security & keys: ENC not set up, old key listed as REVOKED in history');
job = (await api.listRotations()).find((j) => j.reason === 'KEY_COMPROMISE' && j.folderId === folderId);
ok(job.status === 'WAITING_FOR_KEY', 'compromise rotation job WAITING_FOR_KEY (until new key)');
ok(!job.canClaim, 'cannot run rotation before a new key exists');
await V.setupKeys(riley.userId, PASS);
ov = await V.keyOverview(riley.userId);
ok(ov.ENC.status === 'ACTIVE' && ov.ENC.id !== oldEncId, 'new key pair created after compromise');
job = (await api.listRotations()).find((j) => j.rotationId === job.rotationId);
ok(job.status === 'WAITING_FOR_CLIENT' && job.canClaim, 'job unlocks → WAITING_FOR_CLIENT after new key activation');
await ROT.runRotation({ rotationId: job.rotationId, userId: riley.userId });
await ROT.commitRotationAsOwner({ rotationId: job.rotationId, userId: riley.userId });
const done = await api.getRotation(job.rotationId);
ok(done.status === 'COMPLETED' && done.items.length === 3 && done.items.every((i) => i.status === 'COMMITTED'), 'compromise rotation: 3/3 items COMMITTED');
ok(await text(await openVersion({ versionId: da.currentVersionId, userId: riley.userId })) === 'alpha v2', 'riley opens A v2 again with the NEW key');
const alex3 = await login('alex@hospital.org');
ok(await text(await openVersion({ versionId: da.currentVersionId, userId: alex3.userId })) === 'alpha v2', 'alex unaffected');
riley = await login('riley@hospital.org');
ok(!(await loadLocalKey(riley.userId, oldEncId)), 'compromised private key purged from this device after all jobs finished');

/* --- audit log: chỉ hoạt động của CHÍNH user, chỉ tài liệu/folder/quyền --- */
const mine = await api.listAuditEvents();
ok(mine.length > 0 && mine.every((e) => e.actorUserId === riley.userId), 'audit log returns only the signed-in user’s own activity');
ok(mine.every((e) => /^(DOCUMENT_|FOLDER_|MEMBER_)/.test(e.type)), 'audit log has NO key or rotation events');
const types = (await api.listAuditEvents({ folderId })).map((e) => e.type);
for (const t of ['MEMBER_ADDED', 'DOCUMENT_UPLOADED', 'DOCUMENT_VERSION_ADDED', 'DOCUMENT_DOWNLOADED']) ok(types.includes(t), `audit log has ${t}`);
const alexAudit = await login('alex@hospital.org').then(() => api.listAuditEvents());
ok(alexAudit.every((e) => e.actorName === 'Dr. Alex Chen'), 'alex’s audit log does not show riley’s activity (and vice-versa)');
riley = await login('riley@hospital.org');

/* --- key rotation log --- */
const keyEv = (await api.listAuditEvents({ category: 'KEY' })).map((e) => e.type);
ok(keyEv.includes('KEY_COMPROMISE_REPORTED') && keyEv.includes('KEY_REGISTERED'), 'key log has KEY_COMPROMISE_REPORTED + KEY_REGISTERED');
ok((await api.listRotations()).filter((j) => j.folderId === folderId && j.status === 'COMPLETED').length === 2, 'rotation log: 2 completed jobs (member added, key compromise)');

/* --- revoke: LUÔN đổi DEK của tất cả document + cấp lại envelope cho người còn lại --- */
const revoke = async (fid, userId) => {
  const signer = await V.loadSigner((await api.getCurrentUser()).user.userId);
  const m = (await api.listFolderMembers(fid)).find((x) => x.userId === userId);
  const ctx = await api.createPolicyContext(fid, { action: 'REVOKE_MEMBER', membershipId: m.membershipId });
  await api.revokeFolderMember(fid, m.membershipId, { contextId: ctx.contextId, signedPolicy: await signFolderPolicy({ context: ctx, signer }) });
};
await revoke(folderId, alex.userId);
let rj = (await api.listRotations()).find((j) => j.folderId === folderId && j.reason === 'MEMBER_REVOKED');
ok(rj.total === 3 && rj.canClaim && rj.status === 'WAITING_FOR_CLIENT', 'revoke → rotation job covers ALL 3 document versions');
await ROT.runRotation({ rotationId: rj.rotationId, userId: riley.userId });
await ROT.commitRotationAsOwner({ rotationId: rj.rotationId, userId: riley.userId });
const rd = await api.getRotation(rj.rotationId);
ok(rd.status === 'COMPLETED' && rd.items.length === 3 && rd.items.every((i) => i.status === 'COMMITTED'), 'revoke rotation: 3/3 versions re-encrypted with new DEKs');
ok(rd.recipientNames.length === 1 && rd.recipientNames[0] === 'Dr. Riley Morgan', 'new envelopes issued only to remaining members (revoked member excluded)');
ok(await text(await openVersion({ versionId: da.currentVersionId, userId: riley.userId })) === 'alpha v2', 'riley still opens A v2 after revoke-rotation');
await login('alex@hospital.org');
await rejects(openVersion({ versionId: da.currentVersionId, userId: alex.userId }), /NOT_FOUND|FORBIDDEN|NO_ENVELOPE/, 'revoked alex can no longer open the document');

/* --- folder chỉ có dữ liệu mẫu chưa mã hoá: vẫn có job, server tự hoàn tất --- */
await revoke('f-472', 'u-riley'); // alex là Owner của f-472
let sj = (await api.listRotations()).find((j) => j.folderId === 'f-472' && j.reason === 'MEMBER_REVOKED');
ok(sj.status === 'COMPLETED' && sj.total === 1 && sj.done === 1, 'sample-only folder: revoke still creates a job (1/1), completed by System');
ok((await api.getRotation(sj.rotationId)).items[0].sample === true && (await api.getCurrentKeySession('f-472')).state === 'READY', 'sample item flagged; folder session READY');

/* --- folder rỗng: add/revoke vẫn tạo job (0/0) --- */
riley = await login('riley@hospital.org');
const f2 = crypto.randomUUID();
{
  const keys = await V.loadKeys(); const signer = await V.loadSigner(riley.userId, keys);
  await api.createFolder({ folderId: f2, name: 'Empty', signedInitialPolicy: await signInitialFolderPolicy({ folderId: f2, policy: { policyVersion: '1', members: [{ userId: riley.userId, role: 'OWNER', encryptionKeyId: V.activeKey(keys, 'ENC').id }] }, signer }) });
  const ctx = await api.createPolicyContext(f2, { action: 'ADD_MEMBER', targetUserId: alex.userId, role: 'VIEWER' });
  await api.addFolderMember(f2, { contextId: ctx.contextId, signedPolicy: await signFolderPolicy({ context: ctx, signer }), userId: alex.userId, role: 'VIEWER' });
}
await revoke(f2, alex.userId);
const ej = (await api.listRotations()).filter((j) => j.folderId === f2);
ok(ej.length === 2 && ej.every((j) => j.status === 'COMPLETED' && j.total === 0), 'empty folder: member added + revoked → 2 completed jobs (0/0), nothing "not needed"');
console.log('\nALL PASSED');

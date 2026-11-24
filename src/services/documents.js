import { api } from '../api/endpoints';
import { USE_MOCK } from '../api/client';
import { openDocument, prepareUpload } from '../crypto';
import { loadKeys, loadSigner, recipientFor } from './vault';
import { createTrust } from './trust';
import { saveBlob } from '../utils/format';

// CONTRACT: tên field multipart (README crypto: "FE serializes encrypted for the team's multipart contract")
function buildForm(fields, enc) {
  const f = new FormData();
  Object.entries(fields).forEach(([k, v]) => v != null && f.append(k, v));
  f.append('contextId', enc.contextId);
  f.append('signedManifest', JSON.stringify(enc.signedManifest));
  f.append('envelopes', JSON.stringify(enc.envelopes));
  f.append('ciphertext', new Blob([enc.ciphertext]), 'ciphertext.bin');
  return f;
}

// Tên file / loại file nằm TRONG container mã hoá; server chỉ thấy title + category.
const encryptedMetadata = (file) => ({ fileName: file.name, mimeType: file.type || 'application/octet-stream', size: file.size });

export async function uploadNewDocument({ folderId, title, category, file, userId, onStep = () => {} }) {
  const signer = await loadSigner(userId, await loadKeys());
  onStep('Requesting upload permission…');
  const context = await api.createUploadContext(folderId, { purpose: 'NEW_DOCUMENT' });
  onStep('Encrypting on this device…');
  const enc = await prepareUpload({ file, metadata: encryptedMetadata(file), context, signer });
  onStep('Uploading…');
  return api.uploadDocument(folderId, buildForm({ title, category }, enc));
}

export async function uploadNewVersion({ folderId, documentId, baseVersionId, file, userId, onStep = () => {} }) {
  const signer = await loadSigner(userId, await loadKeys());
  onStep('Requesting upload permission…');
  const context = await api.createUploadContext(folderId, { purpose: 'NEW_VERSION', documentId, baseVersionId });
  onStep('Encrypting on this device…');
  const enc = await prepareUpload({ file, metadata: encryptedMetadata(file), context, signer });
  onStep('Uploading…');
  return api.createDocumentVersion(documentId, buildForm({ baseVersionId }, enc));
}

/** Manifest + ciphertext (ghim theo cryptoRevisionId) → verify chữ ký/policy/hash → giải mã. Thử lại 1 lần nếu revision đổi. */
async function fetchBundle(versionId, retry = true) {
  const m = await api.getVersionManifest(versionId);
  if (m.demo) return { demo: true, m };
  try {
    const ciphertext = new Uint8Array(await (await api.downloadVersionCiphertext(versionId, m.activeRevision.cryptoRevisionId)).arrayBuffer());
    return { m, ciphertext };
  } catch (e) {
    if (retry && e.code === 'REVISION_CONFLICT') return fetchBundle(versionId, false);
    throw e;
  }
}

export async function openVersion({ versionId, userId }) {
  const { demo, m, ciphertext } = await fetchBundle(versionId);
  if (USE_MOCK && demo) return { demo: true };
  // expected lấy từ activeRevision do API trả (nguồn thẩm quyền), không lấy từ chính manifest đang verify.
  const expected = { folderId: m.folderId, documentId: m.documentId, versionId: m.versionId, ...m.activeRevision };
  const recipient = await recipientFor(userId, m.envelope);
  const opened = await openDocument({
    bundle: { ciphertext, signedManifest: m.signedManifest, envelope: m.envelope, policyProof: m.policyProof, originalManifest: m.originalManifest, originalPolicyProof: m.originalPolicyProof },
    expected, recipient, trust: createTrust(m.folderId),
  });
  return {
    blob: new Blob([opened.file], { type: opened.metadata?.mimeType }), metadata: opened.metadata,
    authorUserId: opened.authorUserId, integrity: { ok: true },
  };
}

export async function downloadVersion({ versionId, fallbackName, userId }) {
  const out = await openVersion({ versionId, userId });
  if (out.demo) { saveBlob(new Blob(['Demo file from mock data.\n']), fallbackName || 'demo.txt'); return { ok: true, demo: true }; }
  saveBlob(out.blob, out.metadata?.fileName || fallbackName || 'document');
  return { ok: true, metadata: out.metadata };
}

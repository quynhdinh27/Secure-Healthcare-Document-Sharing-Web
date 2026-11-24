// Rotation phía client: executor (Owner/Editor) re-encrypt từng version; Owner verify + ký commit.
import { api } from '../api/endpoints';
import { prepareRotationCommit, prepareRotationItem } from '../crypto';
import { loadKeys, loadSigner, purgeRetiredKeys, recipientFor } from './vault';
import { createTrust } from './trust';

const ACTIVE = ['WAITING_FOR_KEY', 'WAITING_FOR_CLIENT', 'IN_PROGRESS', 'WAITING_FOR_OWNER', 'FAILED'];
export const isActiveJob = (j) => ACTIVE.includes(String(j.status).toUpperCase());

export async function findFolderRotation(folderId) {
  return (await api.listRotations()).find((j) => j.folderId === folderId && isActiveJob(j));
}

// CONTRACT: multipart của source / staged result (README API: "ciphertext + manifest + envelope của chính mình")
async function readBundle(response) {
  const form = await response.formData();
  const parse = (k) => (form.has(k) ? JSON.parse(form.get(k)) : undefined);
  return {
    ciphertext: new Uint8Array(await form.get('ciphertext').arrayBuffer()),
    signedManifest: parse('signedManifest'), envelope: parse('envelope'), policyProof: parse('policyProof'),
    originalManifest: parse('originalManifest'), originalPolicyProof: parse('originalPolicyProof'),
  };
}

/** Executor: claim → re-encrypt từng item bằng DEK mới → submit kết quả staged. */
export async function runRotation({ rotationId, userId, onProgress = () => {} }) {
  const signer = await loadSigner(userId, await loadKeys()); // khóa SIGN ĐANG ACTIVE (khóa mới sau compromise)
  await api.claimRotation(rotationId);
  const job = await api.getRotation(rotationId);
  const items = await api.listRotationItems(rotationId);
  const trust = createTrust(job.folderId);
  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    onProgress(`Re-encrypting ${i + 1} of ${items.length}…`);
    await api.renewRotationLease(rotationId);
    const source = await readBundle(await api.getRotationItemSource(rotationId, item.itemId));
    const recipient = await recipientFor(userId, source.envelope); // có thể là khóa cũ đã retired
    const common = { rotationId, generation: job.generation, folderId: job.folderId, keySessionId: job.keySessionId, policyHash: job.policyHash, keyRegistryRevision: job.keyRegistryRevision };
    const out = await prepareRotationItem({
      source,
      expectedSource: { folderId: job.folderId, documentId: item.documentId, versionId: item.versionId, ...item.source },
      target: { ...common, itemId: item.itemId, documentId: item.documentId, versionId: item.versionId, cryptoRevisionId: item.targetCryptoRevisionId, recipients: item.recipients },
      recipient, signer, trust,
    });
    const form = new FormData();
    form.append('ciphertext', new Blob([out.ciphertext]), 'ciphertext.bin');
    form.append('envelopes', JSON.stringify(out.envelopes));
    form.append('signedManifest', JSON.stringify(out.signedManifest));
    await api.submitRotationItemResult(rotationId, item.itemId, form);
  }
  onProgress('Waiting for the folder Owner to review.');
}

/** Owner: tải kết quả staged, decrypt + verify toàn bộ rồi ký commit. */
export async function commitRotationAsOwner({ rotationId, userId, onProgress = () => {} }) {
  const signer = await loadSigner(userId, await loadKeys());
  const job = await api.getRotation(rotationId);
  const trust = createTrust(job.folderId);
  const staged = []; let recipient;
  const real = job.items.filter((x) => !x.sample); // dữ liệu mẫu không có ciphertext để verify
  for (let i = 0; i < real.length; i++) {
    const item = real[i];
    onProgress(`Verifying ${i + 1} of ${real.length}…`);
    const bundle = await readBundle(await api.getStagedRotationItemResult(rotationId, item.itemId));
    recipient ??= await recipientFor(userId, bundle.envelope);
    staged.push({ bundle, expected: {
      itemId: item.itemId, documentId: item.documentId, versionId: item.versionId, cryptoRevisionId: item.targetCryptoRevisionId,
      sourceCryptoRevisionId: item.sourceCryptoRevisionId, sourceCryptoManifestHash: item.sourceCryptoManifestHash, authorRecordHash: item.authorRecordHash,
    } });
  }
  const signedCommit = await prepareRotationCommit({
    job: { rotationId, generation: job.generation, folderId: job.folderId, keySessionId: job.keySessionId, policyHash: job.policyHash, keyRegistryRevision: job.keyRegistryRevision, itemIds: job.itemIds },
    items: staged, signer, recipient, trust,
  });
  await api.commitRotation(rotationId, { signedCommit });
  // Sau khi mọi job đã xong thì xoá private key của khóa bị thu hồi khỏi máy này.
  if (!(await api.listRotations()).some(isActiveJob)) await purgeRetiredKeys(userId);
}

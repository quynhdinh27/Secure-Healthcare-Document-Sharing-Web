// Trust callbacks cho openDocument / prepareRotationItem / prepareRotationCommit.
// Nguồn tin cậy: getFolderPolicy (chữ ký policy + binding public key, kể cả key lịch sử).
import { api } from '../api/endpoints';
import { USE_MOCK } from '../api/client';
import { verifyFolderPolicy } from '../crypto';
import { hashRecord } from '../crypto/primitives/sha256';

export function createTrust(folderId) {
  const cache = new Map();
  let currentVersion;
  const policy = (v) => { if (!cache.has(v)) cache.set(v, api.getFolderPolicy(folderId, v)); return cache.get(v); };
  const current = async () => (currentVersion ??= (await api.getFolder(folderId)).policyVersion ?? 1);

  // Tìm public key (SPKI base64url) của {userId,keyId}; duyệt ngược policy để thấy cả key đã thay/thu hồi.
  async function resolveSigningKey({ userId, keyId }) {
    for (let v = await current(); v >= 1; v--) {
      const hit = (await policy(v)).bindings?.find((b) => b.userId === userId && b.keyId === keyId && b.purpose === 'SIGN');
      if (hit) return hit.publicKey;
    }
    throw new Error('Signing key is not bound to this folder’s policy.');
  }

  // CONTRACT: policyProof là signed policy {record, signature}. Cần bổ sung kiểm tra membership +
  // "historical action" theo spec nguồn (README crypto: verifyPolicyProof).
  async function verifyPolicyProof({ record, policyProof }) {
    if (!policyProof) return USE_MOCK; // mock: folder seed chưa có policy ký; backend thật bắt buộc có proof
    const owner = (await policy(await current())).ownerUserId;
    const r = policyProof.record;
    if (r.actorUserId !== owner) return false;
    const publicKey = await resolveSigningKey({ userId: r.actorUserId, keyId: r.actorSigningKeyId });
    await verifyFolderPolicy({ signedPolicy: policyProof, trustedOwner: { userId: r.actorUserId, keyId: r.actorSigningKeyId, publicKey, folderId } });
    return (await hashRecord(policyProof)) === record.policyHash;
  }
  return { resolveSigningKey, verifyPolicyProof };
}

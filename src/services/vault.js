// Quản lý khóa phía client, nối module crypto với API khóa.
// Private key là non-extractable, lưu IndexedDB theo (userId, keyId). Backup tạo MỘT LẦN lúc enrollment.
import { api } from '../api/endpoints';
import { nKey } from '../api/normalize';
import {
  answerKeyChallenge, beginKeyEnrollment, finalizeLocalKey, loadLocalKey, removeLocalKey, restorePrivateKey, saveLocalKey,
} from '../crypto';
import { deriveArgon2id } from '../crypto/argon2';

export const loadKeys = async () => (await api.listMyKeys()).map(nKey);
export const activeKey = (keys, purpose) => keys.find((k) => k.purpose === purpose && k.status === 'ACTIVE');
export const hasActivePair = (keys) => !!activeKey(keys, 'ENC') && !!activeKey(keys, 'SIGN');

/** Trạng thái cho trang Security & keys: key đang dùng + lịch sử (đã thay/thu hồi) + có private key trên máy này không. */
export async function keyOverview(userId) {
  const keys = await loadKeys();
  const withLocal = await Promise.all(keys.map(async (k) => ({ ...k, onDevice: !!(await loadLocalKey(userId, k.id)) })));
  const current = (p) => withLocal.find((k) => k.purpose === p && k.status === 'ACTIVE') ?? withLocal.find((k) => k.purpose === p && k.status === 'PENDING_VERIFICATION');
  return {
    ENC: current('ENC'), SIGN: current('SIGN'),
    history: withLocal.filter((k) => !['ACTIVE', 'PENDING_VERIFICATION'].includes(k.status)).sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt))),
  };
}

/** Người ký: khóa SIGN đang active + private key trên máy này. */
export async function loadSigner(userId, keys) {
  const key = activeKey(keys ?? (await loadKeys()), 'SIGN');
  if (!key) throw new Error('You don’t have an active signing key. Set up keys in Security & keys.');
  const privateKey = await loadLocalKey(userId, key.id);
  if (!privateKey) throw new Error('Your signing key isn’t on this device. Restore it from backup in Security & keys.');
  return { userId, keyId: key.id, privateKey };
}

/** Người nhận: dùng key ENC mà envelope được cấp cho (có thể là key cũ đã retired khi làm nguồn rotation). */
export async function recipientFor(userId, envelope) {
  const privateKey = await loadLocalKey(userId, envelope.recipientEncryptionKeyId);
  if (!privateKey) throw new Error('This version is encrypted for a key that isn’t on this device. Restore your key from backup in Security & keys.');
  return { membershipId: envelope.membershipId, recipientEncryptionKeyId: envelope.recipientEncryptionKeyId, privateKey };
}

/** Sinh cặp khóa mới trên máy, đăng ký, chứng minh sở hữu, lưu backup mã hoá (Argon2id), kích hoạt. */
export async function setupKeys(userId, passphrase, onStep = () => {}) {
  for (const purpose of ['SIGN', 'ENC']) {
    onStep(purpose === 'ENC' ? 'Creating encryption key…' : 'Creating signing key…');
    const enrollment = await beginKeyEnrollment({ userId, purpose });
    const { registration } = enrollment;
    // CONTRACT: body đăng ký + dạng challenge (userId, keyId, purpose, nonce, expiresAt, ciphertext cho ENC)
    const reg = await api.registerPublicKey({ purpose, publicKey: registration.publicKey, publicKeyFingerprint: registration.publicKeyFingerprint });
    const { privateKey, backup } = await finalizeLocalKey(enrollment, { keyId: reg.keyId, passphrase, deriveArgon2id });
    await saveLocalKey(userId, reg.keyId, privateKey);
    const response = await answerKeyChallenge(enrollment, { keyId: reg.keyId, challenge: reg.challenge });
    await api.saveEncryptedKeyBackup(reg.keyId, { backup });
    await api.activatePublicKey(reg.keyId, { response });
  }
}

/** Khôi phục private key từ backup (thiết bị mới / mất key trên máy). */
export async function restoreKey(userId, key, passphrase) {
  const r = await api.getEncryptedKeyBackup(key.id);
  const binding = r.binding ?? { userId, keyId: key.id, purpose: key.purpose, publicKeyFingerprint: key.fingerprint };
  const privateKey = await restorePrivateKey({ backup: r.backup, binding, publicKey: r.publicKey ?? key.publicKey, passphrase, deriveArgon2id });
  await saveLocalKey(userId, key.id, privateKey);
}

/** Xoá private key của các khóa đã bị thu hồi/thay thế khỏi máy này (sau khi rotation xong). */
export async function purgeRetiredKeys(userId) {
  const keys = await loadKeys();
  for (const k of keys.filter((x) => ['REVOKED', 'RETIRED'].includes(x.status))) await removeLocalKey(userId, k.id);
}

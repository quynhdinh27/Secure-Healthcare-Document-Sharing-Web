export const CATEGORIES = ['Medical report', 'Laboratory result', 'Prescription', 'Medical image', 'Other'];
export const ACCEPT = '.pdf,.jpg,.jpeg,.png,application/pdf,image/jpeg,image/png';
export const MAX_FILE_BYTES = 50 * 1024 * 1024; // giới hạn phía client — chỉnh theo backend
export const KEY_PURPOSE = { ENC: 'Encryption / decryption key pair', SIGN: 'Digital-signature key pair' };
export const SESSION_LABEL = {
  READY: 'Keys are up to date.',
  ROTATING: 'Keys are being updated for this folder.',
  WAITING_FOR_CLIENT: 'Waiting for a folder Owner or Editor to continue re-encrypting documents.',
  WAITING_FOR_KEY: 'Waiting for a member to register a valid key.',
  WAITING_FOR_OWNER: 'Waiting for the folder Owner to review and activate the new keys.',
  FAILED: 'Key update failed. The folder Owner can retry it.',
};

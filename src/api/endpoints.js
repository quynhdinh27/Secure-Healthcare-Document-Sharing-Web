// Mỗi hàm tương ứng 1 handler trong "API_AND_FUNCTION_NAMES.md".
import { request as r, rootGet } from './client';
import { asList } from './normalize';
import { base64url } from '../crypto/encoding';

const list = (p) => p.then(asList);
const b64json = (o) => base64url(new TextEncoder().encode(JSON.stringify(o)));

export const api = {
  // 1. Auth
  login: (email, password) => r('POST', '/auth/login', { body: { email, password } }),
  getCurrentUser: () => r('GET', '/auth/me'),
  logout: () => r('POST', '/auth/logout'),
  getCsrfToken: () => r('GET', '/auth/csrf'),
  reauthenticate: (password) => r('POST', '/auth/reauthenticate', { body: { password } }),
  searchStaff: (query) => list(r('GET', '/users', { query: { query } })),

  // 2. Folders & members
  listFolders: () => list(r('GET', '/folders')),
  createFolder: (body) => r('POST', '/folders', { body }),
  getFolder: (id) => r('GET', `/folders/${id}`),
  updateFolder: (id, body) => r('PATCH', `/folders/${id}`, { body }),
  deleteFolder: (id) => r('DELETE', `/folders/${id}`),
  listFolderMembers: (id) => list(r('GET', `/folders/${id}/members`)),
  createPolicyContext: (id, body) => r('POST', `/folders/${id}/policy-contexts`, { body }),
  addFolderMember: (id, body) => r('POST', `/folders/${id}/members`, { body }),
  changeFolderMemberRole: (id, mid, body) => r('PATCH', `/folders/${id}/members/${mid}`, { body }),
  // CONTRACT: README crypto — revoke gửi context ID + chữ ký trong header (tên header cần chốt)
  revokeFolderMember: (id, mid, { contextId, signedPolicy }) => r('DELETE', `/folders/${id}/members/${mid}`, {
    headers: { 'X-Policy-Context-Id': contextId, 'X-Policy-Signature': b64json(signedPolicy) },
  }),

  // 3. Documents & versions
  listFolderDocuments: (id, query) => list(r('GET', `/folders/${id}/documents`, { query })),
  createUploadContext: (id, body) => r('POST', `/folders/${id}/upload-contexts`, { body }),
  uploadDocument: (id, form) => r('POST', `/folders/${id}/documents`, { body: form }),
  getDocument: (docId) => r('GET', `/documents/${docId}`),
  updateDocumentMetadata: (docId, body) => r('PATCH', `/documents/${docId}`, { body }),
  deleteDocument: (docId) => r('DELETE', `/documents/${docId}`),
  listDocumentVersions: (docId) => list(r('GET', `/documents/${docId}/versions`)),
  createDocumentVersion: (docId, form) => r('POST', `/documents/${docId}/versions`, { body: form }),
  getVersionManifest: (vId) => r('GET', `/versions/${vId}/manifest`),
  // ciphertext được ghim theo cryptoRevisionId đang active (crypto README: Upload and read)
  downloadVersionCiphertext: (vId, cryptoRevisionId) => r('GET', `/versions/${vId}/content`, { query: { cryptoRevisionId }, raw: 'blob' }),

  // 4. Policy & key sessions
  getFolderPolicy: (id, v) => r('GET', `/folders/${id}/policies/${v}`),
  getCurrentKeySession: (id) => r('GET', `/folders/${id}/key-sessions/current`),
  listKeySessions: (id) => list(r('GET', `/folders/${id}/key-sessions`)),

  // 5. Keys & backup
  listMyKeys: () => list(r('GET', '/users/me/keys')),
  registerPublicKey: (body) => r('POST', '/users/me/keys', { body }),
  activatePublicKey: (keyId, body) => r('POST', `/users/me/keys/${keyId}/activate`, { body }),
  saveEncryptedKeyBackup: (keyId, body) => r('PUT', `/users/me/keys/${keyId}/backup`, { body }),
  getEncryptedKeyBackup: (keyId) => r('GET', `/users/me/keys/${keyId}/backup`),
  reportKeyCompromise: (keyId, body) => r('POST', `/users/me/keys/${keyId}/compromise`, { body }),

  // 6. Devices
  listMyDevices: () => list(r('GET', '/users/me/devices')),
  registerDevice: (body) => r('POST', '/users/me/devices', { body }),
  revokeDevice: (id) => r('DELETE', `/users/me/devices/${id}`),

  // 7. Rotation
  listRotations: () => list(r('GET', '/key-rotations')),
  getRotation: (id) => r('GET', `/key-rotations/${id}`),
  claimRotation: (id) => r('POST', `/key-rotations/${id}/claim`),
  renewRotationLease: (id) => r('POST', `/key-rotations/${id}/lease/renew`),
  listRotationItems: (id) => list(r('GET', `/key-rotations/${id}/items`)),
  getRotationItemSource: (id, itemId) => r('GET', `/key-rotations/${id}/items/${itemId}/source`, { raw: 'response' }),
  submitRotationItemResult: (id, itemId, form) => r('PUT', `/key-rotations/${id}/items/${itemId}/result`, { body: form }),
  getStagedRotationItemResult: (id, itemId) => r('GET', `/key-rotations/${id}/items/${itemId}/result`, { raw: 'response' }),
  commitRotation: (id, body) => r('POST', `/key-rotations/${id}/commit`, { body }),
  retryRotation: (id, body) => r('POST', `/key-rotations/${id}/retry`, { body }),

  // 8. Audit & operations
  listAuditEvents: (query) => list(r('GET', '/audit-events', { query })),
  getOperation: (id) => r('GET', `/operations/${id}`),

  // 9. Health (root, không prefix)
  getLiveness: () => rootGet('/health/live'),
  getReadiness: () => rootGet('/health/ready'),

  // 10. Dashboard
  getDashboardSummary: () => r('GET', '/dashboard/summary'),

  // 11. Admin (đề xuất bổ sung theo FRS)
  listAdminUsers: (query) => list(r('GET', '/admin/users', { query })),
  createAdminUser: (body) => r('POST', '/admin/users', { body }),
  getAdminUser: (id) => r('GET', `/admin/users/${id}`),
  updateAdminUser: (id, body) => r('PATCH', `/admin/users/${id}`, { body }),
  updateAdminUserStatus: (id, body) => r('PATCH', `/admin/users/${id}/status`, { body }),
};

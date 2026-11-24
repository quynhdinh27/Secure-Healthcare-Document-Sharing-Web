// Response schema chi tiết chưa chốt (trừ Dashboard) → chuẩn hoá tại một chỗ.
// Khi backend chốt schema, chỉ cần sửa file này.
const pick = (o, ...paths) => {
  for (const p of paths) {
    const v = p.split('.').reduce((a, k) => (a == null ? a : a[k]), o);
    if (v !== undefined && v !== null) return v;
  }
  return undefined;
};
const str = (v) => (typeof v === 'string' ? v : undefined);
const up = (v, d = '') => String(v ?? d).toUpperCase();

export const asList = (r) => (Array.isArray(r) ? r : r?.items ?? r?.data ?? r?.results ?? []);
export const shortId = (id) => (id ? String(id).slice(0, 8) : '');
export const humanize = (t) => {
  const s = String(t ?? '').toLowerCase().replace(/[_.-]+/g, ' ').trim();
  return s ? s[0].toUpperCase() + s.slice(1) : '—';
};

export const nUser = (u = {}) => ({
  id: pick(u, 'userId', 'id'),
  name: pick(u, 'fullName', 'name', 'displayName') ?? u.email,
  email: u.email,
  staffId: pick(u, 'staffId', 'staffCode'),
  department: u.department,
  status: up(u.status ?? (u.active === false ? 'INACTIVE' : 'ACTIVE')),
  isAdmin: !!(u.isHospitalAdmin || u.isAdmin || u.systemRole === 'HOSPITAL_ADMIN' || u.roles?.includes?.('HOSPITAL_ADMIN')),
  createdAt: u.createdAt,
  lastSignIn: pick(u, 'lastLoginAt', 'lastSignInAt'),
});

export const nFolder = (f = {}) => {
  const id = pick(f, 'folderId', 'id');
  return {
    id,
    name: f.name,
    code: pick(f, 'code', 'folderCode', 'displayId') ?? shortId(id),
    treatmentRef: pick(f, 'treatmentRef', 'treatmentReference', 'treatmentCode'),
    description: f.description,
    ownerName: pick(f, 'ownerName', 'owner.name', 'owner.fullName'),
    role: up(f.role),
    updatedAt: pick(f, 'updatedAt', 'lastUpdatedAt'),
    status: up(f.status, 'ACTIVE'),
    cryptoState: pick(f, 'cryptoState', 'keySessionState'),
  };
};

export const nDoc = (d = {}) => ({
  id: pick(d, 'documentId', 'id'),
  folderId: d.folderId,
  title: pick(d, 'title', 'name', 'fileName'),
  category: d.category,
  mimeType: pick(d, 'mimeType', 'contentType'),
  size: pick(d, 'size', 'sizeBytes'),
  uploadedBy: pick(d, 'uploadedByName', 'uploadedBy.name', 'author.name', 'createdBy.name') ?? str(d.uploadedBy),
  createdAt: d.createdAt,
  updatedAt: pick(d, 'updatedAt', 'createdAt'),
  currentVersionId: d.currentVersionId,
  currentVersion: pick(d, 'currentVersionNumber', 'currentVersion.versionNumber', 'versionNumber') ?? (typeof d.currentVersion === 'number' ? d.currentVersion : undefined),
  status: up(d.status, 'AVAILABLE'),
});

export const nVersion = (v = {}) => ({
  id: pick(v, 'versionId', 'id'),
  number: pick(v, 'versionNumber', 'number'),
  isCurrent: !!pick(v, 'isCurrent', 'current'),
  updatedBy: pick(v, 'createdByName', 'authorName', 'createdBy.name', 'uploadedBy.name'),
  createdAt: v.createdAt,
  size: pick(v, 'size', 'sizeBytes'),
});

export const nMember = (m = {}) => ({
  id: pick(m, 'membershipId', 'id'),
  userId: pick(m, 'userId', 'user.userId', 'user.id'),
  name: pick(m, 'name', 'fullName', 'user.name', 'user.fullName'),
  email: pick(m, 'email', 'user.email'),
  role: up(m.role),
  status: up(m.status, 'ACTIVE'),
});

export const nKey = (k = {}) => {
  const purpose = up(pick(k, 'purpose', 'type', 'keyType'));
  return {
    id: pick(k, 'keyId', 'id'),
    purpose: purpose.startsWith('ENC') ? 'ENC' : 'SIGN',
    status: up(k.status),
    publicKey: k.publicKey,
    fingerprint: k.publicKeyFingerprint,
    createdAt: k.createdAt,
    revokedAt: k.revokedAt,
  };
};

export const nDevice = (d = {}) => ({
  id: pick(d, 'deviceId', 'id'),
  name: pick(d, 'name', 'deviceName') ?? 'Unnamed device',
  lastActiveAt: pick(d, 'lastActiveAt', 'lastSeenAt'),
  status: up(d.status, 'ACTIVE'),
});

export const EVENT_LABELS = {
  DOCUMENT_UPLOADED: 'Uploaded document', DOCUMENT_VERSION_ADDED: 'Added document version', DOCUMENT_DOWNLOADED: 'Downloaded document', DOCUMENT_DELETED: 'Deleted document',
  FOLDER_CREATED: 'Created folder', FOLDER_RENAMED: 'Renamed folder', FOLDER_DELETED: 'Deleted folder', FOLDER_ACCESSED: 'Accessed folder',
  MEMBER_ADDED: 'Added member', MEMBER_ROLE_CHANGED: 'Changed member role', MEMBER_REVOKED: 'Revoked member access',
  KEY_REGISTERED: 'Registered key', KEY_BACKUP_SAVED: 'Saved key backup', KEY_COMPROMISE_REPORTED: 'Reported key compromise', KEY_RETIRED: 'Retired key',
  ROTATION_STARTED: 'Key update started', ROTATION_CLAIMED: 'Started re-encrypting documents', ROTATION_READY_FOR_OWNER: 'Re-encryption finished, waiting for Owner',
  ROTATION_COMMITTED: 'Owner committed key update', ROTATION_RETRIED: 'Owner retried key update', ROTATION_NOT_NEEDED: 'Key update not needed',
  DEVICE_REGISTERED: 'Registered device', DEVICE_REVOKED: 'Revoked device',
  ACCOUNT_CREATED: 'New account created', ACCOUNT_UPDATED: 'Account details updated', ACCOUNT_STATUS_CHANGED: 'Account status changed', ACCOUNT_REACTIVATED: 'Account reactivated',
};
export const ROTATION_REASONS = {
  MEMBER_ADDED: 'Member added', MEMBER_REVOKED: 'Member access revoked', ROLE_CHANGED: 'Member role changed',
  KEY_COMPROMISE: 'Key compromised — keys re-issued', KEY_REPLACED: 'Key replaced',
};

export const nEvent = (e = {}) => ({
  id: pick(e, 'eventId', 'id'),
  at: pick(e, 'occurredAt', 'createdAt', 'timestamp'),
  type: pick(e, 'type', 'eventType', 'action'),
  label: EVENT_LABELS[pick(e, 'type', 'eventType', 'action')] ?? pick(e, 'description', 'label') ?? humanize(pick(e, 'type', 'eventType', 'action')),
  actor: pick(e, 'actorName', 'actor.name', 'actor.fullName'),
  item: pick(e, 'targetName', 'itemName', 'documentName', 'folderName'),
  detail: e.detail,
  folder: pick(e, 'folderCode', 'folderId'),
  staffId: pick(e, 'staffId', 'targetStaffId'),
  keyType: pick(e, 'keyType', 'purpose'),
  keyId: e.keyId,
  result: pick(e, 'result', 'outcome', 'status'),
});

export const nRotation = (r = {}) => ({
  id: pick(r, 'rotationId', 'id'),
  folderId: r.folderId,
  folder: [r.folderName, r.folderCode].filter(Boolean).join(' · ') || shortId(r.folderId),
  reason: r.reason,
  reasonLabel: ROTATION_REASONS[r.reason] ?? humanize(r.reason),
  status: up(r.status),
  generation: r.generation,
  createdAt: r.createdAt,
  completedAt: r.completedAt,
  total: pick(r, 'total', 'progress.total') ?? r.items?.length ?? 0,
  done: pick(r, 'done', 'progress.completed') ?? 0,
  failed: pick(r, 'failed', 'progress.failed') ?? 0,
  executor: r.claimedByName,
  committedBy: r.committedByName,
  waitingFor: r.waitingForNames ?? [],
  canClaim: !!r.canClaim,
  canCommit: !!r.canCommit,
  recipients: r.recipientNames ?? [],
  items: (r.items ?? []).map((i) => ({ id: i.itemId, itemId: i.itemId, title: i.title, versionNumber: i.versionNumber, status: up(i.status), error: i.error, sample: !!i.sample })),
});

export const nSession = (s = {}) => ({ state: up(pick(s, 'state', 'status'), 'READY'), id: pick(s, 'sessionId', 'id') });

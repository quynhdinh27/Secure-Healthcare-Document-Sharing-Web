const SENSITIVE_EXACT_KEYS = new Set([
  'token',
  'sid',
  'medsharesid',
  'medsharecsrf',
]);

const SENSITIVE_SUBSTRINGS = [
  'password',
  'tokenhash',
  'sessiontoken',
  'csrftoken',
  'privatekey',
  'passphrase',
  'dek',
  'secret',
  'cookie',
  'authorization',
];

function isSensitiveKey(key) {
  const normalized = String(key).replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
  if (SENSITIVE_EXACT_KEYS.has(normalized)) return true;
  return SENSITIVE_SUBSTRINGS.some((needle) => normalized.includes(needle));
}

function sanitizeAuditValue(value, seen = new WeakSet()) {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'bigint') {
    return value.toString();
  }
  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value.toISOString();
  }
  if (typeof value !== 'object') {
    return String(value);
  }
  if (seen.has(value)) {
    return '[Circular]';
  }
  seen.add(value);

  if (Array.isArray(value)) {
    return value.map((item) => sanitizeAuditValue(item, seen));
  }

  const out = {};
  for (const [key, item] of Object.entries(value)) {
    if (isSensitiveKey(key)) continue;
    if (item === undefined) continue;
    out[key] = sanitizeAuditValue(item, seen);
  }
  return out;
}

function createAuditService({ auditRepository }) {
  if (!auditRepository || typeof auditRepository.record !== 'function') {
    throw new Error('auditRepository.record is required');
  }

  return {
    async record({
      actorId = null,
      actionType,
      targetType,
      targetId = null,
      folderId = null,
      documentId = null,
      versionId = null,
      result,
      details = null,
      ipAddress = null,
      deviceId = null,
    }, connection = null) {
      const sanitizedDetails = details && typeof details === 'object'
        ? sanitizeAuditValue(details)
        : null;
      return auditRepository.record({
        actorId: actorId == null ? null : String(actorId),
        actionType,
        targetType,
        targetId: targetId == null ? null : String(targetId).slice(0, 64),
        folderId: folderId ?? null,
        documentId: documentId ?? null,
        versionId: versionId ?? null,
        result,
        details: sanitizedDetails,
        ipAddress: ipAddress == null ? null : String(ipAddress).slice(0, 45),
        deviceId: deviceId == null ? null : String(deviceId),
      }, connection);
    },
  };
}

module.exports = {
  createAuditService,
  sanitizeAuditValue,
  isSensitiveKey,
};

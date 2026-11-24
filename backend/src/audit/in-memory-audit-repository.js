function createInMemoryAuditRepository() {
  let nextLogId = 1n;
  const entries = [];

  return {
    async record(entry) {
      const stored = {
        logId: String(nextLogId++),
        actorId: entry.actorId ?? null,
        actionType: entry.actionType,
        targetType: entry.targetType,
        targetId: entry.targetId == null ? null : String(entry.targetId).slice(0, 64),
        folderId: entry.folderId ?? null,
        documentId: entry.documentId ?? null,
        versionId: entry.versionId ?? null,
        result: entry.result,
        details: entry.details ? structuredClone(entry.details) : null,
        ipAddress: entry.ipAddress == null ? null : String(entry.ipAddress).slice(0, 45),
        deviceId: entry.deviceId ?? null,
        createdAt: new Date().toISOString(),
      };
      entries.push(stored);
      return structuredClone(stored);
    },

    async list() {
      return entries.map((entry) => structuredClone(entry));
    },
  };
}

module.exports = { createInMemoryAuditRepository };

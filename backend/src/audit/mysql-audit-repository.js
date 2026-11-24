function createMysqlAuditRepository(pool) {
  return {
    async record(entry, connection = null) {
      const executor = connection ?? pool;
      const targetId = entry.targetId == null ? null : String(entry.targetId).slice(0, 64);
      const ipAddress = entry.ipAddress == null ? null : String(entry.ipAddress).slice(0, 45);
      const detailsJson = entry.details == null ? null : JSON.stringify(entry.details);

      const [result] = await executor.execute(
        `INSERT INTO Audit_Log (
           actor_id, action_type, target_type, target_id,
           folder_id, document_id, version_id,
           result, details, ip_address, device_id, created_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(3))`,
        [
          entry.actorId ?? null,
          String(entry.actionType).slice(0, 100),
          String(entry.targetType).slice(0, 50),
          targetId,
          entry.folderId ?? null,
          entry.documentId ?? null,
          entry.versionId ?? null,
          entry.result,
          detailsJson,
          ipAddress,
          entry.deviceId ?? null,
        ],
      );

      return {
        logId: result?.insertId != null ? String(result.insertId) : null,
        actorId: entry.actorId ?? null,
        actionType: entry.actionType,
        targetType: entry.targetType,
        targetId,
        result: entry.result,
      };
    },
  };
}

module.exports = { createMysqlAuditRepository };

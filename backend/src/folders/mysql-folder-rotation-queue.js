const { randomUUID } = require('node:crypto');

// The caller holds the folder lock for the duration of the transaction.
async function cancelMysqlFolderRotations(connection, folderId) {
  await connection.execute(`
    UPDATE Folder_Rotation_Job SET status = 'CANCELLED', finished_at = UTC_TIMESTAMP(3)
    WHERE folder_id = ?
      AND status IN ('PENDING', 'IN_PROGRESS', 'WAITING_FOR_CLIENT',
                     'WAITING_FOR_KEY', 'WAITING_FOR_OWNER')
  `, [folderId]);
}

async function queueMysqlFolderRotation({ connection, folderId, policyVersion, ownerId, action }) {
  await cancelMysqlFolderRotations(connection, folderId);
  const rotationId = randomUUID();
  await connection.execute(`
    INSERT INTO Folder_Rotation_Job (rotation_id, folder_id, policy_version, requested_by, action)
    VALUES (?, ?, ?, ?, ?)
  `, [rotationId, folderId, policyVersion, ownerId, action]);
  return rotationId;
}

module.exports = { cancelMysqlFolderRotations, queueMysqlFolderRotation };

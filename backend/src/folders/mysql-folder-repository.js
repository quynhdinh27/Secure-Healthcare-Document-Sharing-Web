const memberFoldersQuery = `
  SELECT f.folder_id AS folderId, f.folder_name AS name, f.episode_ref AS treatmentReference,
         f.updated_at AS updatedAt, m.role, m.status
  FROM Treatment_Folder AS f
  INNER JOIN Folder_Membership AS m ON m.folder_id = f.folder_id
  WHERE m.user_id = ? AND m.status = 'ACTIVE'
`;

function toEntry({ role, status, ...folder }) {
  return { folder, membership: { role, status } };
}

function createMysqlFolderRepository(pool) {
  const findFolderQuery = memberFoldersQuery + ' AND f.folder_id = ?';

  return {
    async listForUser(userId) {
      const [rows] = await pool.execute(
        memberFoldersQuery + ' ORDER BY f.updated_at DESC, f.folder_id',
        [userId],
      );
      return rows.map(toEntry);
    },

    async findForUser(userId, folderId) {
      const [[row]] = await pool.execute(findFolderQuery, [userId, folderId]);
      return row ? toEntry(row) : null;
    },

    async renameForUser(userId, folderId, name, allowedRoles) {
      const connection = await pool.getConnection();
      try {
        await connection.beginTransaction();
        // Lock the folder and active membership until the authorized write finishes.
        const [[row]] = await connection.execute(findFolderQuery + ' FOR UPDATE', [userId, folderId]);
        if (!row || !allowedRoles.includes(row.role)) {
          await connection.rollback();
          return null;
        }

        if (row.name !== name) {
          await connection.execute(
            'UPDATE Treatment_Folder SET folder_name = ?, updated_at = CURRENT_TIMESTAMP WHERE folder_id = ?',
            [name, folderId],
          );
        }
        const [[updated]] = await connection.execute(findFolderQuery, [userId, folderId]);
        const result = toEntry(updated);
        await connection.commit();
        return result;
      } catch (error) {
        await connection.rollback();
        throw error;
      } finally {
        connection.release();
      }
    },
  };
}

module.exports = { createMysqlFolderRepository };

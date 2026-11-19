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
    async createForOwner({ folder, ownerId, signedPolicy, verifyInitialFolderPolicy }) {
      const connection = await pool.getConnection();
      try {
        await connection.beginTransaction();
        // The verifier checks the active signing key and binds policy version 1
        // to this folder, this owner and the initial owner-only membership.
        const verified = await verifyInitialFolderPolicy({ connection, folder, ownerId, signedPolicy, policyVersion: 1 });
        if (verified !== true) {
          await connection.rollback();
          return { code: 'INVALID_SIGNATURE' };
        }

        try {
          await connection.execute(
            'INSERT INTO Treatment_Folder (folder_id, folder_name, patient_ref, episode_ref) VALUES (?, ?, ?, ?)',
            [folder.folderId, folder.name, folder.patientRef, folder.treatmentReference],
          );
        } catch (error) {
          if (error.code !== 'ER_DUP_ENTRY') throw error;
          await connection.rollback();
          return { code: 'FOLDER_ALREADY_EXISTS' };
        }
        await connection.execute(
          "INSERT INTO Folder_Membership (folder_id, user_id, role, granted_by) VALUES (?, ?, 'OWNER', ?)",
          [folder.folderId, ownerId, ownerId],
        );
        await connection.execute(
          'INSERT INTO Folder_Policy (folder_id, policy_version, signed_policy) VALUES (?, 1, ?)',
          [folder.folderId, JSON.stringify(signedPolicy)],
        );
        const [[row]] = await connection.execute(findFolderQuery, [ownerId, folder.folderId]);
        const entry = toEntry(row);
        await connection.commit();
        return { folder: { ...entry.folder, role: entry.membership.role, policyVersion: 1 } };
      } catch (error) {
        await connection.rollback();
        throw error;
      } finally {
        connection.release();
      }
    },

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

    async listMembersForUser(userId, folderId) {
      const [members] = await pool.execute(`
        SELECT member.membership_id AS membershipId, member.user_id AS userId, member.role
        FROM Folder_Membership AS member
        WHERE member.folder_id = ? AND member.status = 'ACTIVE'
          AND EXISTS (
            SELECT 1 FROM Folder_Membership AS requester
            WHERE requester.folder_id = member.folder_id
              AND requester.user_id = ? AND requester.status = 'ACTIVE'
          )
        ORDER BY member.membership_id
      `, [folderId, userId]);
      return members.length ? members : null;
    },

    async getDashboardSummary(userId) {
      const [rows] = await pool.execute(`
        WITH visible_folders AS (${memberFoldersQuery}),
        counts AS (
          SELECT f.folderId, f.name, f.treatmentReference, f.updatedAt, f.role,
                 COUNT(d.document_id) AS documentCount
          FROM visible_folders AS f
          LEFT JOIN Document AS d ON d.folder_id = f.folderId
          GROUP BY f.folderId, f.name, f.treatmentReference, f.updatedAt, f.role
        )
        SELECT counts.*, COUNT(*) OVER () AS totalFolders,
               SUM(documentCount) OVER () AS totalDocuments
        FROM counts
        ORDER BY updatedAt DESC, folderId
        LIMIT 5
      `, [userId]);
      return {
        folderCount: Number(rows[0]?.totalFolders ?? 0),
        documentCount: Number(rows[0]?.totalDocuments ?? 0),
        recentFolders: rows.map(({ totalFolders, totalDocuments, documentCount, ...folder }) => ({
          ...folder,
          documentCount: Number(documentCount),
        })),
      };
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

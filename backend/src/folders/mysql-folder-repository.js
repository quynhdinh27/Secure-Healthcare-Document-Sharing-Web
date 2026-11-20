const { randomBytes, randomUUID } = require('node:crypto');

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

async function writeMemberChange(connection, { folderId, ownerId, action, target }) {
  if (action === 'ADD_MEMBER') {
    await connection.execute(
      'INSERT INTO Folder_Membership (folder_id, user_id, role, granted_by) VALUES (?, ?, ?, ?)',
      [folderId, target.userId, target.role, ownerId],
    );
    return true;
  }
  const filter = " WHERE folder_id = ? AND membership_id = ? AND status = 'ACTIVE' AND role <> 'OWNER'";
  const [result] = action === 'CHANGE_ROLE'
    ? await connection.execute('UPDATE Folder_Membership SET role = ?' + filter, [target.role, folderId, target.membershipId])
    : await connection.execute(
      "UPDATE Folder_Membership SET status = 'REVOKED', revoked_by = ?, revoked_at = CURRENT_TIMESTAMP" + filter,
      [ownerId, folderId, target.membershipId],
    );
  return result.affectedRows === 1;
}

async function commitMemberChange(connection, input) {
  const { ownerId, folderId, membershipId, action, policyContextId, ownerSignature, verifyFolderPolicy, queueFolderRotation } = input;
  // Serialize folder policy changes with context creation.
  await connection.execute('SELECT folder_id FROM Treatment_Folder WHERE folder_id = ? FOR UPDATE', [folderId]);
  const [[owner]] = await connection.execute(
    "SELECT CAST(membership_id AS CHAR) AS membershipId FROM Folder_Membership WHERE folder_id = ? AND user_id = ? AND role = 'OWNER' AND status = 'ACTIVE' FOR UPDATE",
    [folderId, ownerId],
  );
  if (!owner) return { code: 'FORBIDDEN' };

  const [[stored]] = await connection.execute(`
    SELECT payload, consumed_at AS consumedAt, expires_at <= UTC_TIMESTAMP(3) AS expired
    FROM Folder_Policy_Context
    WHERE context_id = ? AND folder_id = ? AND owner_membership_id = ? FOR UPDATE
  `, [policyContextId, folderId, owner.membershipId]);
  if (!stored || stored.consumedAt || Number(stored.expired)) return { code: 'POLICY_CONTEXT_INVALID' };
  const context = typeof stored.payload === 'string' ? JSON.parse(stored.payload) : stored.payload;
  if (context.action !== action || context.target.membershipId !== membershipId) {
    return { code: 'POLICY_CONTEXT_MISMATCH' };
  }
  const [[policy]] = await connection.execute(
    'SELECT MAX(policy_version) AS version FROM Folder_Policy WHERE folder_id = ?', [folderId],
  );
  if (Number(policy.version) !== context.expectedPolicyVersion) return { code: 'POLICY_CONTEXT_STALE' };

  // Verify the signature over the stored context using the active, account-bound key.
  // For ADD_MEMBER the verifier also checks target account and encryption-key eligibility.
  if (await verifyFolderPolicy({ connection, ownerId, context, ownerSignature }) !== true) {
    return { code: 'INVALID_SIGNATURE' };
  }

  const updated = await writeMemberChange(connection, { folderId, ownerId, action, target: context.target });
  if (!updated) return { code: 'INVALID_MEMBERSHIP_CHANGE' };
  const policyVersion = context.proposedPolicy.policyVersion;
  await connection.execute(
    'INSERT INTO Folder_Policy (folder_id, policy_version, signed_policy) VALUES (?, ?, ?)',
    [folderId, policyVersion, JSON.stringify({ context, ownerSignature })],
  );
  const [consumed] = await connection.execute(`
    UPDATE Folder_Policy_Context SET consumed_at = UTC_TIMESTAMP(3)
    WHERE context_id = ? AND consumed_at IS NULL AND expires_at > UTC_TIMESTAMP(3)
  `, [policyContextId]);
  if (consumed.affectedRows !== 1) return { code: 'POLICY_CONTEXT_INVALID' };
  // The queue must write the job and transition the folder on this connection.
  const rotationId = await queueFolderRotation({ connection, folderId, policyVersion, ownerId, action });
  if (!rotationId) throw new Error('Folder rotation was not queued');
  return { policyVersion, rotationId };
}

function createMysqlFolderRepository(pool) {
  const findFolderQuery = memberFoldersQuery + ' AND f.folder_id = ?';

  return {
    async applyMemberChange(input) {
      const connection = await pool.getConnection();
      try {
        await connection.beginTransaction();
        const result = await commitMemberChange(connection, input);
        if (result.code) await connection.rollback();
        else await connection.commit();
        return result;
      } catch (error) {
        await connection.rollback();
        throw error;
      } finally {
        connection.release();
      }
    },

    async createPolicyContext(ownerId, folderId, action, target) {
      const connection = await pool.getConnection();
      try {
        await connection.beginTransaction();
        const [[folder]] = await connection.execute(
          'SELECT folder_id FROM Treatment_Folder WHERE folder_id = ? FOR UPDATE', [folderId],
        );
        const [members] = folder ? await connection.execute(`
          SELECT CAST(membership_id AS CHAR) AS membershipId, CAST(user_id AS CHAR) AS userId, role
          FROM Folder_Membership WHERE folder_id = ? AND status = 'ACTIVE' ORDER BY user_id FOR UPDATE
        `, [folderId]) : [[]];
        const owner = members.find((member) => member.userId === String(ownerId) && member.role === 'OWNER');
        if (!owner) {
          await connection.rollback();
          return { code: 'FORBIDDEN' };
        }
        const [[policy]] = await connection.execute(
          'SELECT MAX(policy_version) AS version FROM Folder_Policy WHERE folder_id = ?', [folderId],
        );
        const expectedPolicyVersion = Number(policy.version);
        if (!expectedPolicyVersion || expectedPolicyVersion === 4294967295) {
          await connection.rollback();
          return { code: 'POLICY_NOT_READY' };
        }

        const member = members.find((entry) => entry.membershipId === target.membershipId);
        const proposedMembers = members.map(({ userId, role }) => ({ userId, role }));
        if (action === 'ADD_MEMBER') {
          if (members.some((entry) => entry.userId === target.userId)) {
            await connection.rollback();
            return { code: 'MEMBER_ALREADY_ACTIVE' };
          }
          proposedMembers.push({ userId: target.userId, role: target.role });
        } else {
          if (!member || member.role === 'OWNER' || member.role === target.role) {
            await connection.rollback();
            return { code: 'INVALID_MEMBERSHIP_CHANGE' };
          }
          const index = proposedMembers.findIndex((entry) => entry.userId === member.userId);
          if (action === 'CHANGE_ROLE') proposedMembers[index].role = target.role;
          else proposedMembers.splice(index, 1);
        }

        const context = {
          contextId: randomUUID(),
          folderId,
          ownerId: owner.userId,
          action,
          target,
          expectedPolicyVersion,
          nonce: randomBytes(16).toString('hex'),
          expiresAt: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
          proposedPolicy: { policyVersion: expectedPolicyVersion + 1, members: proposedMembers },
        };
        await connection.execute(
          'INSERT INTO Folder_Policy_Context (context_id, folder_id, owner_membership_id, payload, expires_at) VALUES (?, ?, ?, ?, ?)',
          [context.contextId, folderId, owner.membershipId, JSON.stringify(context), context.expiresAt.slice(0, -1).replace('T', ' ')],
        );
        await connection.commit();
        return context;
      } catch (error) {
        await connection.rollback();
        throw error;
      } finally {
        connection.release();
      }
    },

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

    async findRotationForUser(userId, rotationId) {
      const [[job]] = await pool.execute(`
        SELECT j.rotation_id AS rotationId, j.folder_id AS folderId,
               j.policy_version AS policyVersion, j.action, j.status,
               j.created_at AS createdAt, j.finished_at AS finishedAt
        FROM Folder_Rotation_Job AS j
        INNER JOIN Folder_Membership AS m ON m.folder_id = j.folder_id
        WHERE j.rotation_id = ? AND m.user_id = ?
          AND m.status = 'ACTIVE' AND m.role IN ('OWNER', 'EDITOR')
      `, [rotationId, userId]);
      return job ?? null;
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

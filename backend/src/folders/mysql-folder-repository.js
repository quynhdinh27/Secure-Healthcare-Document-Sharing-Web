const { randomBytes, randomUUID } = require('node:crypto');
const { cancelMysqlFolderRotations } = require('./mysql-folder-rotation-queue');

const memberFoldersQuery = `
  SELECT f.folder_id AS folderId, f.folder_name AS name, f.episode_ref AS treatmentReference,
         f.updated_at AS updatedAt, f.description, m.role, m.status
  FROM Treatment_Folder AS f
  INNER JOIN Folder_Membership AS m ON m.folder_id = f.folder_id
  WHERE m.user_id = ? AND m.status = 'ACTIVE'
`;

const rotationJobColumns = `
  j.rotation_id AS rotationId, j.folder_id AS folderId,
  j.policy_version AS policyVersion, j.action, j.status,
  j.created_at AS createdAt, j.finished_at AS finishedAt
`;

const rotationJobMembership = `
  FROM Folder_Rotation_Job AS j
  INNER JOIN Folder_Membership AS m ON m.folder_id = j.folder_id
`;

function toEntry({ role, status, ...folder }) {
  return { folder, membership: { role, status } };
}

function folderCryptoState(rotationStatus, leaseExpired) {
  switch (rotationStatus) {
    case 'PENDING':
      return 'ROTATING';
    case 'IN_PROGRESS':
      return Number(leaseExpired) === 1 ? 'WAITING_FOR_CLIENT' : 'ROTATING';
    case 'WAITING_FOR_CLIENT':
    case 'WAITING_FOR_KEY':
    case 'WAITING_FOR_OWNER':
    case 'FAILED':
      return rotationStatus;
    case 'COMPLETED':
      return 'READY';
    default:
      return null;
  }
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

async function lockRotationForUser(connection, userId, rotationId) {
  const [[location]] = await connection.execute(
    'SELECT folder_id AS folderId FROM Folder_Rotation_Job WHERE rotation_id = ?', [rotationId],
  );
  if (!location) return null;

  // Use the same lock order as membership changes and job cancellation.
  await connection.execute('SELECT folder_id FROM Treatment_Folder WHERE folder_id = ? FOR UPDATE', [location.folderId]);
  const [[job]] = await connection.execute(`
    SELECT j.folder_id AS folderId, j.policy_version AS policyVersion, j.status, j.generation,
           CAST(j.executor_id AS CHAR) AS executorId,
           j.lease_expires_at > UTC_TIMESTAMP(3) AS leaseActive,
           DATE_FORMAT(j.lease_expires_at, '%Y-%m-%dT%H:%i:%s.%fZ') AS leaseExpiresAt
    FROM Folder_Rotation_Job AS j
    INNER JOIN Folder_Membership AS m ON m.folder_id = j.folder_id
    WHERE j.rotation_id = ? AND m.user_id = ?
      AND m.status = 'ACTIVE' AND m.role IN ('OWNER', 'EDITOR')
    FOR UPDATE
  `, [rotationId, userId]);
  return job ?? null;
}

async function readRotationLease(connection, rotationId) {
  const [[lease]] = await connection.execute(`
    SELECT generation, DATE_FORMAT(lease_expires_at, '%Y-%m-%dT%H:%i:%s.%fZ') AS leaseExpiresAt
    FROM Folder_Rotation_Job WHERE rotation_id = ? FOR UPDATE
  `, [rotationId]);
  return { rotationId, ...lease, status: 'IN_PROGRESS' };
}

async function claimRotation(connection, userId, rotationId, canReadRotationSources) {
  const job = await lockRotationForUser(connection, userId, rotationId);
  if (!job) return { code: 'ROTATION_NOT_FOUND' };
  if (!['PENDING', 'WAITING_FOR_CLIENT', 'IN_PROGRESS'].includes(job.status)) {
    return { code: 'ROTATION_NOT_CLAIMABLE' };
  }

  const leaseActive = job.status === 'IN_PROGRESS' && Number(job.leaseActive) === 1;
  if (leaseActive && job.executorId !== String(userId)) return { code: 'ROTATION_ALREADY_CLAIMED' };

  // The source checker performs server-side checks using current reads on this connection.
  if (await canReadRotationSources({ connection, userId, rotationId, folderId: job.folderId, policyVersion: job.policyVersion }) !== true) {
    return { code: 'ROTATION_SOURCE_UNAVAILABLE' };
  }

  if (leaseActive) {
    return { rotationId, generation: job.generation, leaseExpiresAt: job.leaseExpiresAt, status: 'IN_PROGRESS' };
  }

  await connection.execute(`
    UPDATE Folder_Rotation_Job
    SET status = 'IN_PROGRESS', executor_id = ?, generation = generation + 1,
        lease_expires_at = UTC_TIMESTAMP(3) + INTERVAL 5 MINUTE
    WHERE rotation_id = ?
  `, [userId, rotationId]);
  return readRotationLease(connection, rotationId);
}

async function renewRotationLease(connection, userId, rotationId, generation, canReadRotationSources) {
  const job = await lockRotationForUser(connection, userId, rotationId);
  if (!job) return { code: 'ROTATION_NOT_FOUND' };
  if (job.status !== 'IN_PROGRESS' || job.executorId !== String(userId)
      || job.generation !== generation || Number(job.leaseActive) !== 1) {
    return { code: 'LEASE_EXPIRED' };
  }

  if (await canReadRotationSources({ connection, userId, rotationId, folderId: job.folderId, policyVersion: job.policyVersion }) !== true) {
    return { code: 'ROTATION_SOURCE_UNAVAILABLE' };
  }

  const [result] = await connection.execute(`
    UPDATE Folder_Rotation_Job
    SET lease_expires_at = UTC_TIMESTAMP(3) + INTERVAL 5 MINUTE
    WHERE rotation_id = ? AND lease_expires_at > UTC_TIMESTAMP(3)
  `, [rotationId]);
  if (result.affectedRows !== 1) return { code: 'LEASE_EXPIRED' };
  return readRotationLease(connection, rotationId);
}

async function beginFolderDeletion(connection, ownerId, folderId) {
  const [[folder]] = await connection.execute(
    'SELECT folder_id FROM Treatment_Folder WHERE folder_id = ? FOR UPDATE', [folderId],
  );
  if (!folder) return { code: 'FORBIDDEN' };

  const [[previous]] = await connection.execute(`
    SELECT operation_id AS operationId, status
    FROM Folder_Deletion_Operation WHERE folder_id = ? AND requested_by = ? FOR UPDATE
  `, [folderId, ownerId]);
  if (previous) return previous;

  const [[owner]] = await connection.execute(`
    SELECT membership_id FROM Folder_Membership
    WHERE folder_id = ? AND user_id = ? AND role = 'OWNER' AND status = 'ACTIVE'
    FOR UPDATE
  `, [folderId, ownerId]);
  if (!owner) return { code: 'FORBIDDEN' };

  const operationId = randomUUID();
  await connection.execute(`
    INSERT INTO Folder_Deletion_Operation (operation_id, folder_id, requested_by)
    VALUES (?, ?, ?)
  `, [operationId, folderId, ownerId]);
  await connection.execute(`
    UPDATE Folder_Membership
    SET status = 'REVOKED', revoked_by = ?, revoked_at = CURRENT_TIMESTAMP
    WHERE folder_id = ? AND status = 'ACTIVE'
  `, [ownerId, folderId]);
  await cancelMysqlFolderRotations(connection, folderId);
  return { operationId, status: 'PENDING' };
}

function createMysqlFolderRepository(pool) {
  const findFolderQuery = memberFoldersQuery + ' AND f.folder_id = ?';

  async function runFolderTransaction(operation) {
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      const result = await operation(connection);
      if (result.code) await connection.rollback();
      else await connection.commit();
      return result;
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  async function updateForUser(userId, folderId, { name, description }, allowedRoles) {
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      // Lock the folder and active membership until the authorized write finishes.
      const [[row]] = await connection.execute(findFolderQuery + ' FOR UPDATE', [userId, folderId]);
      if (!row || !allowedRoles.includes(row.role)) {
        await connection.rollback();
        return null;
      }

      const columns = [];
      const values = [];
      if (name !== undefined && row.name !== name) {
        columns.push('folder_name = ?');
        values.push(name);
      }
      if (description !== undefined && row.description !== description) {
        columns.push('description = ?');
        values.push(description);
      }
      if (columns.length) {
        await connection.execute(
          'UPDATE Treatment_Folder SET ' + columns.join(', ') + ', updated_at = CURRENT_TIMESTAMP WHERE folder_id = ?',
          [...values, folderId],
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
  }

  return {
    deleteForOwner(ownerId, folderId) {
      return runFolderTransaction((connection) => beginFolderDeletion(connection, ownerId, folderId));
    },

    async findDeletionOperationForUser(userId, operationId) {
      const [[operation]] = await pool.execute(`
        SELECT operation_id AS operationId, folder_id AS folderId, status, created_at AS createdAt
        FROM Folder_Deletion_Operation WHERE operation_id = ? AND requested_by = ?
      `, [operationId, userId]);
      return operation ?? null;
    },

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
      const [[row]] = await pool.execute(`
        SELECT detail.*, j.status AS rotationStatus,
               COALESCE(j.lease_expires_at <= UTC_TIMESTAMP(3), 1) AS leaseExpired
        FROM (
          SELECT folder.*,
                 (SELECT MAX(p.policy_version) FROM Folder_Policy AS p
                  WHERE p.folder_id = folder.folderId) AS policyVersion
          FROM (${findFolderQuery}) AS folder
        ) AS detail
        LEFT JOIN Folder_Rotation_Job AS j
          ON j.folder_id = detail.folderId AND j.policy_version = detail.policyVersion
      `, [userId, folderId]);
      if (!row) return null;
      const { rotationStatus, leaseExpired, ...detail } = row;
      return toEntry({ ...detail, cryptoState: folderCryptoState(rotationStatus, leaseExpired) });
    },

    async findPolicyForUser(userId, folderId, policyVersion) {
      const [[row]] = await pool.execute(`
        SELECT p.policy_version AS policyVersion, p.signed_policy AS signedPolicy
        FROM Folder_Membership AS m
        LEFT JOIN Folder_Policy AS p ON p.folder_id = m.folder_id AND p.policy_version = ?
        WHERE m.folder_id = ? AND m.user_id = ? AND m.status = 'ACTIVE'
      `, [policyVersion, folderId, userId]);
      if (!row) return { code: 'FORBIDDEN' };
      if (row.policyVersion === null) return { code: 'POLICY_NOT_FOUND' };

      const stored = typeof row.signedPolicy === 'string' ? JSON.parse(row.signedPolicy) : row.signedPolicy;
      const signedPolicy = row.policyVersion === 1
        ? { payload: stored.payload, signature: stored.signature }
        : { context: stored.context, ownerSignature: stored.ownerSignature };
      return { folderId, policyVersion: row.policyVersion, signedPolicy };
    },

    async findRotationForUser(userId, rotationId) {
      const [[job]] = await pool.execute(`
        SELECT ${rotationJobColumns}
        ${rotationJobMembership}
        WHERE j.rotation_id = ? AND m.user_id = ?
          AND m.status = 'ACTIVE' AND m.role IN ('OWNER', 'EDITOR')
      `, [rotationId, userId]);
      return job ?? null;
    },

    async listRotationsForUser(userId, page) {
      const pageSize = 50;
      const [jobs] = await pool.query(`
        SELECT ${rotationJobColumns},
               CASE WHEN j.status IN ('PENDING', 'WAITING_FOR_CLIENT')
                      OR (j.status = 'IN_PROGRESS' AND
                          (j.executor_id = m.user_id OR j.lease_expires_at IS NULL
                           OR j.lease_expires_at <= UTC_TIMESTAMP(3)))
                    THEN 1 ELSE 0 END AS canAttemptClaim
        ${rotationJobMembership}
        WHERE m.user_id = ? AND m.status = 'ACTIVE' AND m.role IN ('OWNER', 'EDITOR')
        ORDER BY j.created_at DESC, j.rotation_id DESC
        LIMIT ? OFFSET ?
      `, [userId, pageSize + 1, (page - 1) * pageSize]);
      return {
        rotations: jobs.slice(0, pageSize).map(({ canAttemptClaim, ...job }) => ({
          ...job,
          canClaim: Number(canAttemptClaim) === 1 ? null : false,
        })),
        nextPage: jobs.length > pageSize ? page + 1 : null,
      };
    },

    claimRotationForUser(userId, rotationId, canReadRotationSources) {
      return runFolderTransaction((connection) => claimRotation(connection, userId, rotationId, canReadRotationSources));
    },

    renewRotationLeaseForUser(userId, rotationId, generation, canReadRotationSources) {
      return runFolderTransaction(
        (connection) => renewRotationLease(connection, userId, rotationId, generation, canReadRotationSources),
      );
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

    renameForUser(userId, folderId, name, allowedRoles) {
      return updateForUser(userId, folderId, { name }, allowedRoles);
    },

    updateForUser,
  };
}

module.exports = { createMysqlFolderRepository };

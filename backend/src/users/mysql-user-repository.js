const ADMIN_USER_SELECT = `
  SELECT
    CAST(u.user_id AS CHAR) AS userId,
    u.email,
    u.full_name AS fullName,
    u.account_type AS accountType,
    u.account_status AS accountStatus,
    CAST(u.department_id AS CHAR) AS departmentId,
    d.department_name AS departmentName,
    CAST(u.created_by AS CHAR) AS createdBy,
    CAST(u.updated_by AS CHAR) AS updatedBy,
    DATE_FORMAT(u.created_at, '%Y-%m-%dT%H:%i:%s.%fZ') AS createdAt,
    DATE_FORMAT(u.updated_at, '%Y-%m-%dT%H:%i:%s.%fZ') AS updatedAt
  FROM \`User\` AS u
  LEFT JOIN Department AS d ON d.department_id = u.department_id
`;

function escapeLikePattern(value) {
  return String(value).replace(/[!%_]/g, '!$&');
}

function normalizeUserRow(row) {
  if (!row) return null;
  return {
    userId: String(row.userId),
    email: row.email,
    fullName: row.fullName,
    accountType: row.accountType,
    accountStatus: row.accountStatus,
    departmentId: row.departmentId == null ? null : String(row.departmentId),
    departmentName: row.departmentName ?? null,
    createdBy: row.createdBy == null ? null : String(row.createdBy),
    updatedBy: row.updatedBy == null ? null : String(row.updatedBy),
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function createMysqlUserRepository(pool) {
  function runQuery(sql, params) {
    const fn = pool.query ?? pool.execute;
    return fn.call(pool, sql, params);
  }

  async function runTransaction(operation) {
    const connection = await pool.getConnection();
    try {
      await connection.beginTransaction();
      const result = await operation(connection);
      if (result.code) {
        await connection.rollback();
      } else {
        await connection.commit();
      }
      return result;
    } catch (error) {
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  }

  return {
    async findByEmailWithAuth(email) {
      const [rows] = await pool.execute(
        `SELECT
           CAST(u.user_id AS CHAR) AS userId,
           u.email,
           u.password_hash AS passwordHash,
           u.full_name AS fullName,
           u.account_type AS accountType,
           u.account_status AS accountStatus,
           CAST(u.department_id AS CHAR) AS departmentId,
           d.department_name AS departmentName,
           CAST(u.created_by AS CHAR) AS createdBy,
           CAST(u.updated_by AS CHAR) AS updatedBy,
           DATE_FORMAT(u.created_at, '%Y-%m-%dT%H:%i:%s.%fZ') AS createdAt,
           DATE_FORMAT(u.updated_at, '%Y-%m-%dT%H:%i:%s.%fZ') AS updatedAt
         FROM \`User\` AS u
         LEFT JOIN Department AS d ON d.department_id = u.department_id
         WHERE u.email = ?`,
        [String(email).trim().toLowerCase()],
      );
      const row = rows[0];
      if (!row) return null;
      return {
        ...normalizeUserRow(row),
        passwordHash: row.passwordHash ?? null,
      };
    },

    async findById(userId) {
      const [rows] = await pool.execute(`${ADMIN_USER_SELECT} WHERE u.user_id = ?`, [userId]);
      return normalizeUserRow(rows[0]);
    },

    async findByIdWithAuth(userId) {
      const [rows] = await pool.execute(
        `SELECT
           CAST(u.user_id AS CHAR) AS userId,
           u.email,
           u.password_hash AS passwordHash,
           u.full_name AS fullName,
           u.account_type AS accountType,
           u.account_status AS accountStatus,
           CAST(u.department_id AS CHAR) AS departmentId,
           d.department_name AS departmentName,
           CAST(u.created_by AS CHAR) AS createdBy,
           CAST(u.updated_by AS CHAR) AS updatedBy,
           DATE_FORMAT(u.created_at, '%Y-%m-%dT%H:%i:%s.%fZ') AS createdAt,
           DATE_FORMAT(u.updated_at, '%Y-%m-%dT%H:%i:%s.%fZ') AS updatedAt
         FROM \`User\` AS u
         LEFT JOIN Department AS d ON d.department_id = u.department_id
         WHERE u.user_id = ?`,
        [userId],
      );
      const row = rows[0];
      if (!row) return null;
      return {
        ...normalizeUserRow(row),
        passwordHash: row.passwordHash ?? null,
      };
    },

    async searchActiveStaff({ query = '', limit = 20 }) {
      const trimmed = query.trim().toLowerCase();
      const conditions = ["u.account_type = 'STAFF'", "u.account_status = 'ACTIVE'"];
      const params = [];
      if (trimmed.length > 0) {
        const pattern = `%${escapeLikePattern(trimmed)}%`;
        conditions.push("(LOWER(u.full_name) LIKE ? ESCAPE '!' OR LOWER(u.email) LIKE ? ESCAPE '!')");
        params.push(pattern, pattern);
      }
      const [rows] = await runQuery(
        `SELECT
           CAST(u.user_id AS CHAR) AS userId,
           u.full_name AS fullName,
           u.email,
           CAST(u.department_id AS CHAR) AS departmentId,
           d.department_name AS departmentName,
           u.account_type AS accountType,
           u.account_status AS accountStatus
         FROM \`User\` AS u
         LEFT JOIN Department AS d ON d.department_id = u.department_id
         WHERE ${conditions.join(' AND ')}
         ORDER BY u.full_name ASC, u.user_id ASC
         LIMIT ?`,
        [...params, limit],
      );
      return rows.map((row) => ({
        userId: String(row.userId),
        fullName: row.fullName,
        email: row.email,
        departmentId: row.departmentId == null ? null : String(row.departmentId),
        departmentName: row.departmentName ?? null,
        accountType: row.accountType,
        accountStatus: row.accountStatus,
      }));
    },

    async listAdminUsers({ query = '', status = null, accountType = null, page = 1, pageSize = 20 }) {
      const conditions = [];
      const params = [];
      const trimmed = query.trim().toLowerCase();
      if (status) {
        conditions.push('u.account_status = ?');
        params.push(status);
      }
      if (accountType) {
        conditions.push('u.account_type = ?');
        params.push(accountType);
      }
      if (trimmed.length > 0) {
        const pattern = `%${escapeLikePattern(trimmed)}%`;
        conditions.push("(LOWER(u.full_name) LIKE ? ESCAPE '!' OR LOWER(u.email) LIKE ? ESCAPE '!')");
        params.push(pattern, pattern);
      }
      const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
      const [[countRow]] = await pool.execute(
        `SELECT COUNT(*) AS total FROM \`User\` AS u ${whereClause}`,
        params,
      );
      const total = Number(countRow?.total ?? 0);
      const offset = (page - 1) * pageSize;
      const [rows] = await runQuery(
        `${ADMIN_USER_SELECT} ${whereClause} ORDER BY u.user_id ASC LIMIT ? OFFSET ?`,
        [...params, pageSize, offset],
      );
      return {
        users: rows.map(normalizeUserRow),
        pagination: {
          page,
          pageSize,
          total,
          totalPages: total === 0 ? 0 : Math.ceil(total / pageSize),
        },
      };
    },

    createUser({ email, fullName, passwordHash, accountType, departmentId, actorId }) {
      return runTransaction(async (connection) => {
        if (departmentId !== null && departmentId !== undefined) {
          const [deptRows] = await connection.execute(
            'SELECT CAST(department_id AS CHAR) AS departmentId FROM Department WHERE department_id = ?',
            [departmentId],
          );
          if (deptRows.length === 0) {
            return { code: 'DEPARTMENT_NOT_FOUND' };
          }
        }

        let insertResult;
        try {
          [insertResult] = await connection.execute(
            `INSERT INTO \`User\` (
               department_id, email, password_hash, full_name,
               account_type, account_status, created_by, updated_by,
               created_at, updated_at
             ) VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP())`,
            [
              departmentId ?? null,
              email.trim().toLowerCase(),
              passwordHash,
              fullName,
              accountType,
              actorId,
              actorId,
            ],
          );
        } catch (error) {
          if (error?.code === 'ER_DUP_ENTRY') {
            return { code: 'EMAIL_ALREADY_EXISTS' };
          }
          throw error;
        }

        const [rows] = await connection.execute(
          `${ADMIN_USER_SELECT} WHERE u.user_id = ?`,
          [insertResult.insertId],
        );
        return { user: normalizeUserRow(rows[0]) };
      });
    },

    updateUser({ userId, fullName, departmentId, hasDepartmentId, accountType, actorId }) {
      return runTransaction(async (connection) => {
        const [existingRows] = await connection.execute(
          `SELECT
             CAST(user_id AS CHAR) AS userId,
             full_name AS fullName,
             account_type AS accountType,
             account_status AS accountStatus,
             CAST(department_id AS CHAR) AS departmentId
           FROM \`User\`
           WHERE user_id = ?
           FOR UPDATE`,
          [userId],
        );
        const existing = existingRows[0];
        if (!existing) return { code: 'USER_NOT_FOUND' };

        const previousAccountType = existing.accountType;
        const nextAccountType = accountType ?? existing.accountType;
        const nextDepartmentId = hasDepartmentId
          ? (departmentId == null ? null : String(departmentId))
          : (existing.departmentId == null ? null : String(existing.departmentId));

        if (nextAccountType === 'STAFF' && nextDepartmentId === null) {
          return { code: 'STAFF_DEPARTMENT_REQUIRED' };
        }
        if (nextDepartmentId !== null) {
          const [deptRows] = await connection.execute(
            'SELECT CAST(department_id AS CHAR) AS departmentId FROM Department WHERE department_id = ?',
            [nextDepartmentId],
          );
          if (deptRows.length === 0) {
            return { code: 'DEPARTMENT_NOT_FOUND' };
          }
        }

        if (nextAccountType === 'STAFF' && previousAccountType === 'ADMIN') {
          if (String(existing.userId) === String(actorId)) {
            return { code: 'CANNOT_DEMOTE_SELF' };
          }
          const [adminRows] = await connection.execute(
            `SELECT CAST(user_id AS CHAR) AS userId
             FROM \`User\`
             WHERE account_type = 'ADMIN' AND account_status = 'ACTIVE'
             FOR UPDATE`,
          );
          if (existing.accountStatus === 'ACTIVE') {
            const remaining = adminRows.filter((row) => String(row.userId) !== String(existing.userId));
            if (remaining.length === 0) {
              return { code: 'LAST_ADMIN_REQUIRED' };
            }
          }
        }

        const nextFullName = fullName !== undefined ? fullName : existing.fullName;
        await connection.execute(
          `UPDATE \`User\`
           SET full_name = ?, department_id = ?, account_type = ?, updated_by = ?, updated_at = UTC_TIMESTAMP()
           WHERE user_id = ?`,
          [nextFullName, nextDepartmentId, nextAccountType, actorId, userId],
        );

        const roleChanged = accountType !== undefined && accountType !== previousAccountType;
        if (roleChanged) {
          await connection.execute(
            `UPDATE User_Session
             SET revoked_at = UTC_TIMESTAMP(3), revoke_reason = 'ROLE_CHANGED'
             WHERE user_id = ? AND revoked_at IS NULL`,
            [userId],
          );
        }

        const [rows] = await connection.execute(`${ADMIN_USER_SELECT} WHERE u.user_id = ?`, [userId]);
        return { user: normalizeUserRow(rows[0]), roleChanged };
      });
    },

    updateUserStatus({ userId, accountStatus, actorId }) {
      return runTransaction(async (connection) => {
        const [existingRows] = await connection.execute(
          `SELECT
             CAST(user_id AS CHAR) AS userId,
             account_type AS accountType,
             account_status AS accountStatus
           FROM \`User\`
           WHERE user_id = ?
           FOR UPDATE`,
          [userId],
        );
        const existing = existingRows[0];
        if (!existing) return { code: 'USER_NOT_FOUND' };

        if (accountStatus === 'DISABLED' && String(existing.userId) === String(actorId)) {
          return { code: 'CANNOT_DISABLE_SELF' };
        }

        if (accountStatus === 'DISABLED' && existing.accountType === 'ADMIN' && existing.accountStatus === 'ACTIVE') {
          const [adminRows] = await connection.execute(
            `SELECT CAST(user_id AS CHAR) AS userId
             FROM \`User\`
             WHERE account_type = 'ADMIN' AND account_status = 'ACTIVE'
             FOR UPDATE`,
          );
          const remaining = adminRows.filter((row) => String(row.userId) !== String(existing.userId));
          if (remaining.length === 0) {
            return { code: 'LAST_ADMIN_REQUIRED' };
          }
        }

        await connection.execute(
          `UPDATE \`User\`
           SET account_status = ?, updated_by = ?, updated_at = UTC_TIMESTAMP()
           WHERE user_id = ?`,
          [accountStatus, actorId, userId],
        );

        if (accountStatus === 'DISABLED') {
          await connection.execute(
            `UPDATE User_Session
             SET revoked_at = UTC_TIMESTAMP(3), revoke_reason = 'ACCOUNT_DISABLED'
             WHERE user_id = ? AND revoked_at IS NULL`,
            [userId],
          );
        }

        const [rows] = await connection.execute(`${ADMIN_USER_SELECT} WHERE u.user_id = ?`, [userId]);
        return { user: normalizeUserRow(rows[0]), previousStatus: existing.accountStatus };
      });
    },
  };
}

module.exports = { createMysqlUserRepository, escapeLikePattern };

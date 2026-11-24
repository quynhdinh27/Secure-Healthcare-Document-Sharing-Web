function createMysqlSessionRepository(pool) {
  return {
    async createSession({ sessionId, userId, tokenHash, csrfTokenHash, ttlMs, ipAddress = null, userAgent = null }) {
      const clippedIp = ipAddress == null ? null : String(ipAddress).slice(0, 45);
      const clippedUa = userAgent == null ? null : String(userAgent).slice(0, 255);
      const ttlMicroseconds = Math.max(1000, Math.floor(Number(ttlMs) * 1000));

      await pool.execute(
        `INSERT INTO User_Session (
           session_id, user_id, token_hash, csrf_token_hash,
           reauthenticated_at, expires_at, ip_address, user_agent,
           created_at, last_seen_at
         ) VALUES (?, ?, ?, ?, NULL, TIMESTAMPADD(MICROSECOND, ?, UTC_TIMESTAMP(3)), ?, ?, UTC_TIMESTAMP(3), UTC_TIMESTAMP(3))`,
        [sessionId, userId, tokenHash, csrfTokenHash, ttlMicroseconds, clippedIp, clippedUa],
      );

      return {
        sessionId,
        userId: String(userId),
      };
    },

    async findActiveSessionWithUserByTokenHash(tokenHash) {
      const [rows] = await pool.execute(
        `SELECT
           s.session_id AS sessionId,
           CAST(s.user_id AS CHAR) AS userId,
           s.csrf_token_hash AS csrfTokenHash,
           DATE_FORMAT(s.reauthenticated_at, '%Y-%m-%dT%H:%i:%s.%fZ') AS reauthenticatedAt,
           DATE_FORMAT(s.expires_at, '%Y-%m-%dT%H:%i:%s.%fZ') AS expiresAt,
           DATE_FORMAT(s.revoked_at, '%Y-%m-%dT%H:%i:%s.%fZ') AS revokedAt,
           s.revoke_reason AS revokeReason,
           DATE_FORMAT(s.created_at, '%Y-%m-%dT%H:%i:%s.%fZ') AS createdAt,
           DATE_FORMAT(s.last_seen_at, '%Y-%m-%dT%H:%i:%s.%fZ') AS lastSeenAt,
           u.email,
           u.full_name AS fullName,
           u.account_type AS accountType,
           u.account_status AS accountStatus,
           CAST(u.department_id AS CHAR) AS departmentId,
           d.department_name AS departmentName,
           DATE_FORMAT(u.created_at, '%Y-%m-%dT%H:%i:%s.%fZ') AS userCreatedAt,
           DATE_FORMAT(u.updated_at, '%Y-%m-%dT%H:%i:%s.%fZ') AS userUpdatedAt
         FROM User_Session AS s
         INNER JOIN \`User\` AS u ON u.user_id = s.user_id
         LEFT JOIN Department AS d ON d.department_id = u.department_id
         WHERE s.token_hash = ?
           AND s.revoked_at IS NULL
           AND s.expires_at > UTC_TIMESTAMP(3)`,
        [tokenHash],
      );
      const row = rows[0];
      if (!row) return null;

      return {
        session: {
          sessionId: row.sessionId,
          userId: String(row.userId),
          csrfTokenHash: row.csrfTokenHash,
          reauthenticatedAt: row.reauthenticatedAt ?? null,
          expiresAt: row.expiresAt,
          revokedAt: row.revokedAt ?? null,
          revokeReason: row.revokeReason ?? null,
          createdAt: row.createdAt,
          lastSeenAt: row.lastSeenAt,
        },
        user: {
          userId: String(row.userId),
          email: row.email,
          fullName: row.fullName,
          accountType: row.accountType,
          accountStatus: row.accountStatus,
          departmentId: row.departmentId == null ? null : String(row.departmentId),
          departmentName: row.departmentName ?? null,
          createdAt: row.userCreatedAt,
          updatedAt: row.userUpdatedAt,
        },
      };
    },

    async touchLastSeen(sessionId) {
      const [result] = await pool.execute(
        `UPDATE User_Session
         SET last_seen_at = UTC_TIMESTAMP(3)
         WHERE session_id = ? AND revoked_at IS NULL`,
        [sessionId],
      );
      return (result?.affectedRows ?? 0) === 1;
    },

    async updateCsrfTokenHash(sessionId, csrfTokenHash) {
      const [result] = await pool.execute(
        `UPDATE User_Session
         SET csrf_token_hash = ?
         WHERE session_id = ? AND revoked_at IS NULL`,
        [csrfTokenHash, sessionId],
      );
      return (result?.affectedRows ?? 0) === 1;
    },

    async updateReauthenticatedAt(sessionId) {
      const [result] = await pool.execute(
        `UPDATE User_Session
         SET reauthenticated_at = UTC_TIMESTAMP(3)
         WHERE session_id = ? AND revoked_at IS NULL AND expires_at > UTC_TIMESTAMP(3)`,
        [sessionId],
      );
      if ((result?.affectedRows ?? 0) !== 1) return null;

      const [rows] = await pool.execute(
        `SELECT DATE_FORMAT(reauthenticated_at, '%Y-%m-%dT%H:%i:%s.%fZ') AS reauthenticatedAt
         FROM User_Session
         WHERE session_id = ?`,
        [sessionId],
      );
      const row = rows[0];
      return row?.reauthenticatedAt ? { reauthenticatedAt: row.reauthenticatedAt } : null;
    },

    async revokeSessionByTokenHash(tokenHash, reason) {
      const [result] = await pool.execute(
        `UPDATE User_Session
         SET revoked_at = UTC_TIMESTAMP(3), revoke_reason = ?
         WHERE token_hash = ? AND revoked_at IS NULL`,
        [reason, tokenHash],
      );
      if ((result?.affectedRows ?? 0) !== 1) {
        return { revoked: false };
      }
      const [rows] = await pool.execute(
        `SELECT session_id AS sessionId, CAST(user_id AS CHAR) AS userId
         FROM User_Session
         WHERE token_hash = ?`,
        [tokenHash],
      );
      const row = rows[0];
      return {
        revoked: true,
        sessionId: row?.sessionId ?? null,
        userId: row?.userId == null ? null : String(row.userId),
      };
    },

    async revokeUserSessions(userId, reason, connection = null) {
      const executor = connection ?? pool;
      const [result] = await executor.execute(
        `UPDATE User_Session
         SET revoked_at = UTC_TIMESTAMP(3), revoke_reason = ?
         WHERE user_id = ? AND revoked_at IS NULL`,
        [reason, userId],
      );
      return result?.affectedRows ?? 0;
    },
  };
}

module.exports = { createMysqlSessionRepository };

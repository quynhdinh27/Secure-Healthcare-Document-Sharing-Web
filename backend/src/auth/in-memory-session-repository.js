function createInMemorySessionRepository({ userRepository }) {
  const sessionsById = new Map();
  const sessionIdByTokenHash = new Map();

  return {
    async createSession({ sessionId, userId, tokenHash, csrfTokenHash, ttlMs, ipAddress = null, userAgent = null }) {
      const now = Date.now();
      const createdAt = new Date(now).toISOString();
      const expiresAt = new Date(now + ttlMs).toISOString();
      const session = {
        sessionId,
        userId: String(userId),
        tokenHash,
        csrfTokenHash,
        reauthenticatedAt: null,
        expiresAt,
        revokedAt: null,
        revokeReason: null,
        ipAddress: ipAddress == null ? null : String(ipAddress).slice(0, 45),
        userAgent: userAgent == null ? null : String(userAgent).slice(0, 255),
        createdAt,
        lastSeenAt: createdAt,
      };
      sessionsById.set(sessionId, session);
      sessionIdByTokenHash.set(tokenHash, sessionId);
      return {
        sessionId: session.sessionId,
        userId: session.userId,
        expiresAt: session.expiresAt,
        createdAt: session.createdAt,
      };
    },

    async findActiveSessionWithUserByTokenHash(tokenHash) {
      const sessionId = sessionIdByTokenHash.get(tokenHash);
      if (!sessionId) return null;
      const session = sessionsById.get(sessionId);
      if (!session || session.revokedAt !== null || Date.parse(session.expiresAt) <= Date.now()) {
        return null;
      }
      const user = await userRepository.findById(session.userId);
      if (!user) return null;
      return {
        session: {
          sessionId: session.sessionId,
          userId: session.userId,
          csrfTokenHash: session.csrfTokenHash,
          reauthenticatedAt: session.reauthenticatedAt,
          expiresAt: session.expiresAt,
          revokedAt: session.revokedAt,
          revokeReason: session.revokeReason,
          createdAt: session.createdAt,
          lastSeenAt: session.lastSeenAt,
        },
        user,
      };
    },

    async touchLastSeen(sessionId) {
      const session = sessionsById.get(sessionId);
      if (!session || session.revokedAt !== null) return false;
      session.lastSeenAt = new Date().toISOString();
      return true;
    },

    async updateCsrfTokenHash(sessionId, csrfTokenHash) {
      const session = sessionsById.get(sessionId);
      if (!session || session.revokedAt !== null) return false;
      session.csrfTokenHash = csrfTokenHash;
      return true;
    },

    async updateReauthenticatedAt(sessionId) {
      const session = sessionsById.get(sessionId);
      if (!session || session.revokedAt !== null || Date.parse(session.expiresAt) <= Date.now()) {
        return null;
      }
      session.reauthenticatedAt = new Date().toISOString();
      return { reauthenticatedAt: session.reauthenticatedAt };
    },

    async revokeSessionByTokenHash(tokenHash, reason) {
      const sessionId = sessionIdByTokenHash.get(tokenHash);
      if (!sessionId) return { revoked: false };
      const session = sessionsById.get(sessionId);
      if (!session || session.revokedAt !== null) {
        return { revoked: false };
      }
      session.revokedAt = new Date().toISOString();
      session.revokeReason = reason;
      return {
        revoked: true,
        sessionId: session.sessionId,
        userId: session.userId,
      };
    },

    async revokeUserSessions(userId, reason) {
      const targetUserId = String(userId);
      const nowIso = new Date().toISOString();
      let count = 0;
      for (const session of sessionsById.values()) {
        if (session.userId === targetUserId && session.revokedAt === null) {
          session.revokedAt = nowIso;
          session.revokeReason = reason;
          count += 1;
        }
      }
      return count;
    },

    async inspectSession(sessionId) {
      const session = sessionsById.get(sessionId);
      return session ? structuredClone(session) : null;
    },
  };
}

module.exports = { createInMemorySessionRepository };

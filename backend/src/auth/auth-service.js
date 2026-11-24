const { createHash, randomBytes, randomUUID } = require('node:crypto');
const { DUMMY_PASSWORD_HASH, verifyPassword } = require('./password');
const {
  accountDisabled,
  invalidCredentials,
  unauthenticated,
} = require('./auth-errors');

function sha256Hex(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function generateOpaqueToken() {
  return randomBytes(32).toString('base64url');
}

function toSafeUserDto(user) {
  return {
    userId: String(user.userId),
    email: user.email,
    fullName: user.fullName,
    accountType: user.accountType,
    accountStatus: user.accountStatus,
    departmentId: user.departmentId == null ? null : String(user.departmentId),
    departmentName: user.departmentName ?? null,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };
}

function createAuthService({
  userRepository,
  sessionRepository,
  auditService,
  sessionTtlMs = 8 * 60 * 60 * 1000,
  reauthTtlMs = 5 * 60 * 1000,
  lastSeenThrottleMs = 60_000,
}) {
  return {
    sessionTtlMs,
    reauthTtlMs,

    async issueCsrfToken({ sessionToken = null } = {}) {
      const csrfToken = generateOpaqueToken();
      const csrfTokenHash = sha256Hex(csrfToken);

      if (typeof sessionToken === 'string' && sessionToken.length > 0 && sessionToken.length <= 512) {
        const tokenHash = sha256Hex(sessionToken);
        const found = await sessionRepository.findActiveSessionWithUserByTokenHash(tokenHash);
        if (found && found.user.accountStatus === 'ACTIVE') {
          await sessionRepository.updateCsrfTokenHash(found.session.sessionId, csrfTokenHash);
        }
      }

      return { csrfToken };
    },

    async login({ email, password, csrfToken, ipAddress = null, userAgent = null }) {
      const normalizedEmail = email.trim().toLowerCase();
      const clippedIp = ipAddress == null ? null : String(ipAddress).slice(0, 45);
      const clippedUa = userAgent == null ? null : String(userAgent).slice(0, 255);

      const user = await userRepository.findByEmailWithAuth(normalizedEmail);
      const passwordValid = await verifyPassword(password, user?.passwordHash || DUMMY_PASSWORD_HASH);

      if (!user || !user.passwordHash || !passwordValid) {
        await auditService.record({
          actorId: user?.userId ?? null,
          actionType: 'AUTH_LOGIN',
          targetType: 'USER',
          targetId: user?.userId ?? normalizedEmail,
          result: 'FAILURE',
          details: { reason: 'INVALID_CREDENTIALS' },
          ipAddress: clippedIp,
        });
        throw invalidCredentials();
      }

      if (user.accountStatus !== 'ACTIVE') {
        await auditService.record({
          actorId: user.userId,
          actionType: 'AUTH_LOGIN',
          targetType: 'USER',
          targetId: user.userId,
          result: 'FAILURE',
          details: { reason: 'ACCOUNT_DISABLED' },
          ipAddress: clippedIp,
        });
        throw accountDisabled();
      }

      const sessionId = randomUUID();
      const sessionToken = generateOpaqueToken();
      const tokenHash = sha256Hex(sessionToken);
      const csrfTokenHash = sha256Hex(csrfToken);

      await sessionRepository.createSession({
        sessionId,
        userId: user.userId,
        tokenHash,
        csrfTokenHash,
        ttlMs: sessionTtlMs,
        ipAddress: clippedIp,
        userAgent: clippedUa,
      });

      await auditService.record({
        actorId: user.userId,
        actionType: 'AUTH_LOGIN',
        targetType: 'USER_SESSION',
        targetId: sessionId,
        result: 'SUCCESS',
        details: { accountType: user.accountType },
        ipAddress: clippedIp,
      });

      return {
        sessionToken,
        csrfToken,
        user: toSafeUserDto(user),
      };
    },

    async verifySession(sessionToken) {
      if (typeof sessionToken !== 'string' || sessionToken.length === 0 || sessionToken.length > 512) {
        return null;
      }
      const tokenHash = sha256Hex(sessionToken);
      const found = await sessionRepository.findActiveSessionWithUserByTokenHash(tokenHash);
      if (!found || found.user.accountStatus !== 'ACTIVE') {
        return null;
      }

      const lastSeenMs = found.session.lastSeenAt ? Date.parse(found.session.lastSeenAt) : NaN;
      if (!Number.isFinite(lastSeenMs) || Date.now() - lastSeenMs >= lastSeenThrottleMs) {
        await sessionRepository.touchLastSeen(found.session.sessionId);
      }

      const userIdStr = String(found.user.userId);
      return {
        user: {
          id: userIdStr,
          userId: userIdStr,
          email: found.user.email,
          fullName: found.user.fullName,
          accountType: found.user.accountType,
          accountStatus: found.user.accountStatus,
          departmentId: found.user.departmentId == null ? null : String(found.user.departmentId),
          sessionId: found.session.sessionId,
          reauthenticatedAt: found.session.reauthenticatedAt ?? null,
        },
        safeUser: toSafeUserDto(found.user),
        session: found.session,
      };
    },

    async getCurrentUser(userId) {
      const user = await userRepository.findById(userId);
      if (!user || user.accountStatus !== 'ACTIVE') {
        throw unauthenticated();
      }
      return { user: toSafeUserDto(user) };
    },

    async logout({ sessionToken = null, ipAddress = null } = {}) {
      const clippedIp = ipAddress == null ? null : String(ipAddress).slice(0, 45);
      if (typeof sessionToken === 'string' && sessionToken.length > 0 && sessionToken.length <= 512) {
        const tokenHash = sha256Hex(sessionToken);
        const result = await sessionRepository.revokeSessionByTokenHash(tokenHash, 'USER_LOGOUT');
        if (result?.revoked) {
          await auditService.record({
            actorId: result.userId ?? null,
            actionType: 'AUTH_LOGOUT',
            targetType: 'USER_SESSION',
            targetId: result.sessionId ?? null,
            result: 'SUCCESS',
            ipAddress: clippedIp,
          });
        }
      }
      return { loggedOut: true };
    },

    async reauthenticate({ userId, sessionId, password, ipAddress = null }) {
      const clippedIp = ipAddress == null ? null : String(ipAddress).slice(0, 45);
      const user = await userRepository.findByIdWithAuth(userId);
      const passwordValid = await verifyPassword(password, user?.passwordHash || DUMMY_PASSWORD_HASH);

      if (!user || user.accountStatus !== 'ACTIVE' || !user.passwordHash || !passwordValid) {
        await auditService.record({
          actorId: userId,
          actionType: 'AUTH_REAUTHENTICATE',
          targetType: 'USER_SESSION',
          targetId: sessionId,
          result: 'FAILURE',
          details: { reason: 'INVALID_CREDENTIALS' },
          ipAddress: clippedIp,
        });
        throw invalidCredentials();
      }

      const updated = await sessionRepository.updateReauthenticatedAt(sessionId);
      if (!updated?.reauthenticatedAt) {
        throw unauthenticated();
      }

      await auditService.record({
        actorId: userId,
        actionType: 'AUTH_REAUTHENTICATE',
        targetType: 'USER_SESSION',
        targetId: sessionId,
        result: 'SUCCESS',
        ipAddress: clippedIp,
      });

      const reauthMs = Date.parse(updated.reauthenticatedAt);
      const reauthExpiresAt = new Date(reauthMs + reauthTtlMs).toISOString();
      return {
        reauthenticatedAt: updated.reauthenticatedAt,
        reauthExpiresAt,
      };
    },

    verifyFolderDeletionReauth(request) {
      const reauthenticatedAt = request?.user?.reauthenticatedAt;
      if (typeof reauthenticatedAt !== 'string') return false;
      const parsed = Date.parse(reauthenticatedAt);
      if (!Number.isFinite(parsed)) return false;
      return Date.now() - parsed <= reauthTtlMs;
    },
  };
}

module.exports = {
  createAuthService,
  toSafeUserDto,
  sha256Hex,
};

const { hashPassword, validatePasswordPolicy } = require('../auth/password');
const { conflict, notFound, validationError } = require('../auth/auth-errors');

const MAX_BIGINT_UNSIGNED = 18446744073709551615n;
const ALLOWED_ACCOUNT_TYPES = new Set(['STAFF', 'ADMIN']);
const ALLOWED_ACCOUNT_STATUSES = new Set(['ACTIVE', 'DISABLED']);
const ALLOWED_UPDATE_KEYS = new Set(['fullName', 'departmentId', 'accountType']);
const ALLOWED_STATUS_KEYS = new Set(['accountStatus', 'reason']);

function isValidBigIntId(value) {
  return (
    typeof value === 'string'
    && /^[1-9][0-9]{0,19}$/.test(value)
    && BigInt(value) <= MAX_BIGINT_UNSIGNED
  );
}

function isValidEmail(value) {
  if (typeof value !== 'string') return false;
  const trimmed = value.trim();
  return trimmed.length > 0 && trimmed.length <= 255 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed);
}

function toSafeAdminUserDto(user) {
  return {
    userId: String(user.userId),
    email: user.email,
    fullName: user.fullName,
    accountType: user.accountType,
    accountStatus: user.accountStatus,
    departmentId: user.departmentId == null ? null : String(user.departmentId),
    departmentName: user.departmentName ?? null,
    createdBy: user.createdBy == null ? null : String(user.createdBy),
    updatedBy: user.updatedBy == null ? null : String(user.updatedBy),
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };
}

function createUserService({ userRepository, sessionRepository, auditService }) {
  const revokeHook = sessionRepository && typeof sessionRepository.revokeUserSessions === 'function'
    ? (userId, reason) => sessionRepository.revokeUserSessions(userId, reason)
    : undefined;

  return {
    async searchStaff({ query, limit }) {
      const normalizedQuery = query === undefined ? '' : query.trim();
      if (normalizedQuery.length > 100) {
        throw validationError('query must be 100 characters or fewer.');
      }
      let parsedLimit = 20;
      if (limit !== undefined) {
        if (!/^[1-9][0-9]{0,2}$/.test(limit) || Number(limit) < 1 || Number(limit) > 50) {
          throw validationError('limit must be an integer between 1 and 50.');
        }
        parsedLimit = Number(limit);
      }
      const users = await userRepository.searchActiveStaff({
        query: normalizedQuery,
        limit: parsedLimit,
      });
      return { users };
    },

    async listAdminUsers({ query, status, accountType, page, pageSize }) {
      const normalizedQuery = query === undefined ? '' : query.trim();
      if (normalizedQuery.length > 100) {
        throw validationError('query must be 100 characters or fewer.');
      }
      if (status !== undefined && status !== '' && !ALLOWED_ACCOUNT_STATUSES.has(status)) {
        throw validationError('status must be ACTIVE or DISABLED.');
      }
      if (accountType !== undefined && accountType !== '' && !ALLOWED_ACCOUNT_TYPES.has(accountType)) {
        throw validationError('accountType must be STAFF or ADMIN.');
      }

      let parsedPage = 1;
      if (page !== undefined) {
        if (!/^[1-9][0-9]{0,8}$/.test(page)) {
          throw validationError('page must be a positive integer.');
        }
        parsedPage = Number(page);
      }

      let parsedPageSize = 20;
      if (pageSize !== undefined) {
        if (!/^[1-9][0-9]{0,2}$/.test(pageSize) || Number(pageSize) < 1 || Number(pageSize) > 100) {
          throw validationError('pageSize must be an integer between 1 and 100.');
        }
        parsedPageSize = Number(pageSize);
      }

      const result = await userRepository.listAdminUsers({
        query: normalizedQuery,
        status: status || null,
        accountType: accountType || null,
        page: parsedPage,
        pageSize: parsedPageSize,
      });
      return {
        users: result.users.map(toSafeAdminUserDto),
        pagination: result.pagination,
      };
    },

    async getAdminUser(userId) {
      if (!isValidBigIntId(userId)) {
        throw validationError('Invalid userId.');
      }
      const user = await userRepository.findById(userId);
      if (!user) {
        throw notFound('USER_NOT_FOUND', 'User not found.');
      }
      return { user: toSafeAdminUserDto(user) };
    },

    async createAdminUser({ actorId, body, ipAddress = null }) {
      const { email, fullName, password, accountType, departmentId } = body;
      if (!isValidEmail(email)) {
        throw validationError('Valid email is required.');
      }
      if (typeof fullName !== 'string' || fullName.trim().length === 0 || fullName.trim().length > 255) {
        throw validationError('fullName must be a non-empty string up to 255 characters.');
      }
      if (!validatePasswordPolicy(password)) {
        throw validationError('password must be a string between 8 and 128 characters.');
      }
      if (!ALLOWED_ACCOUNT_TYPES.has(accountType)) {
        throw validationError('accountType must be STAFF or ADMIN.');
      }

      let normalizedDepartmentId = null;
      if (accountType === 'STAFF') {
        if (!isValidBigIntId(departmentId)) {
          throw validationError('STAFF accounts require a valid decimal-string departmentId.');
        }
        normalizedDepartmentId = departmentId;
      } else if (departmentId !== undefined && departmentId !== null) {
        if (!isValidBigIntId(departmentId)) {
          throw validationError('departmentId must be a valid decimal-string ID or null.');
        }
        normalizedDepartmentId = departmentId;
      }

      const passwordHash = await hashPassword(password);
      const created = await userRepository.createUser({
        email: email.trim().toLowerCase(),
        fullName: fullName.trim(),
        passwordHash,
        accountType,
        departmentId: normalizedDepartmentId,
        actorId,
      });

      if (created.code === 'EMAIL_ALREADY_EXISTS') {
        throw conflict('EMAIL_ALREADY_EXISTS', 'A user with this email already exists.');
      }
      if (created.code === 'DEPARTMENT_NOT_FOUND') {
        throw notFound('DEPARTMENT_NOT_FOUND', 'Department not found.');
      }

      const safeUser = toSafeAdminUserDto(created.user);
      await auditService.record({
        actorId,
        actionType: 'ADMIN_USER_CREATE',
        targetType: 'USER',
        targetId: safeUser.userId,
        result: 'SUCCESS',
        details: {
          email: safeUser.email,
          accountType: safeUser.accountType,
          departmentId: safeUser.departmentId,
        },
        ipAddress,
      });

      return { user: safeUser };
    },

    async updateAdminUser({ actorId, userId, body, ipAddress = null }) {
      if (!isValidBigIntId(userId)) {
        throw validationError('Invalid userId.');
      }
      const keys = Object.keys(body);
      if (keys.length === 0) {
        throw validationError('At least one allowed field (fullName, departmentId, accountType) is required.');
      }
      for (const key of keys) {
        if (!ALLOWED_UPDATE_KEYS.has(key)) {
          throw validationError(`Field '${key}' cannot be modified via this endpoint.`);
        }
      }

      let normalizedFullName;
      if ('fullName' in body) {
        if (typeof body.fullName !== 'string' || body.fullName.trim().length === 0 || body.fullName.trim().length > 255) {
          throw validationError('fullName must be a non-empty string up to 255 characters.');
        }
        normalizedFullName = body.fullName.trim();
      }

      let normalizedAccountType;
      if ('accountType' in body) {
        if (!ALLOWED_ACCOUNT_TYPES.has(body.accountType)) {
          throw validationError('accountType must be STAFF or ADMIN.');
        }
        normalizedAccountType = body.accountType;
      }

      const hasDepartmentId = 'departmentId' in body;
      let normalizedDepartmentId;
      if (hasDepartmentId) {
        if (body.departmentId !== null) {
          if (!isValidBigIntId(body.departmentId)) {
            throw validationError('departmentId must be a valid decimal-string ID or null.');
          }
          normalizedDepartmentId = body.departmentId;
        } else {
          normalizedDepartmentId = null;
        }
      }

      const updated = await userRepository.updateUser({
        userId,
        fullName: normalizedFullName,
        departmentId: normalizedDepartmentId,
        hasDepartmentId,
        accountType: normalizedAccountType,
        actorId,
        revokeUserSessions: revokeHook,
      });

      if (updated.code === 'USER_NOT_FOUND') {
        throw notFound('USER_NOT_FOUND', 'User not found.');
      }
      if (updated.code === 'DEPARTMENT_NOT_FOUND') {
        throw notFound('DEPARTMENT_NOT_FOUND', 'Department not found.');
      }
      if (updated.code === 'STAFF_DEPARTMENT_REQUIRED') {
        throw validationError('STAFF accounts require a valid departmentId.');
      }
      if (updated.code === 'CANNOT_DEMOTE_SELF') {
        throw conflict('CANNOT_DEMOTE_SELF', 'Administrators cannot demote their own account.');
      }
      if (updated.code === 'LAST_ADMIN_REQUIRED') {
        throw conflict('LAST_ADMIN_REQUIRED', 'At least one active Hospital Administrator account is required.');
      }

      const safeUser = toSafeAdminUserDto(updated.user);
      await auditService.record({
        actorId,
        actionType: 'ADMIN_USER_UPDATE',
        targetType: 'USER',
        targetId: safeUser.userId,
        result: 'SUCCESS',
        details: {
          updatedFields: keys,
          roleChanged: Boolean(updated.roleChanged),
        },
        ipAddress,
      });

      return { user: safeUser };
    },

    async updateAdminUserStatus({ actorId, userId, body, ipAddress = null }) {
      if (!isValidBigIntId(userId)) {
        throw validationError('Invalid userId.');
      }
      const keys = Object.keys(body);
      for (const key of keys) {
        if (!ALLOWED_STATUS_KEYS.has(key)) {
          throw validationError(`Unsupported field '${key}'.`);
        }
      }
      const { accountStatus, reason } = body;
      if (!ALLOWED_ACCOUNT_STATUSES.has(accountStatus)) {
        throw validationError('accountStatus must be ACTIVE or DISABLED.');
      }
      if (reason !== undefined && (typeof reason !== 'string' || reason.trim().length > 255)) {
        throw validationError('reason must be a string up to 255 characters.');
      }

      const updated = await userRepository.updateUserStatus({
        userId,
        accountStatus,
        actorId,
        revokeUserSessions: revokeHook,
      });

      if (updated.code === 'USER_NOT_FOUND') {
        throw notFound('USER_NOT_FOUND', 'User not found.');
      }
      if (updated.code === 'CANNOT_DISABLE_SELF') {
        throw conflict('CANNOT_DISABLE_SELF', 'Administrators cannot disable their own account.');
      }
      if (updated.code === 'LAST_ADMIN_REQUIRED') {
        throw conflict('LAST_ADMIN_REQUIRED', 'At least one active Hospital Administrator account is required.');
      }

      const safeUser = toSafeAdminUserDto(updated.user);
      await auditService.record({
        actorId,
        actionType: 'ADMIN_USER_STATUS_CHANGE',
        targetType: 'USER',
        targetId: safeUser.userId,
        result: 'SUCCESS',
        details: {
          previousStatus: updated.previousStatus,
          accountStatus: safeUser.accountStatus,
          reason: typeof reason === 'string' ? reason.trim() : null,
        },
        ipAddress,
      });

      return { user: safeUser };
    },
  };
}

module.exports = {
  createUserService,
  isValidBigIntId,
  toSafeAdminUserDto,
};

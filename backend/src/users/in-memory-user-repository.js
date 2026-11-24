const { hashPassword } = require('../auth/password');

const DEFAULT_IN_MEMORY_DEPARTMENTS = [
  { departmentId: '1', departmentCode: 'CARDIOLOGY', departmentName: 'Cardiology', description: 'Cardiology Department' },
  { departmentId: '2', departmentCode: 'ONCOLOGY', departmentName: 'Oncology', description: 'Oncology Department' },
  { departmentId: '3', departmentCode: 'RADIOLOGY', departmentName: 'Radiology', description: 'Radiology Department' },
  { departmentId: '4', departmentCode: 'PEDIATRICS', departmentName: 'Pediatrics', description: 'Pediatrics Department' },
  { departmentId: '5', departmentCode: 'GENERAL_MEDICINE', departmentName: 'General Medicine', description: 'General Medicine Department' },
];

function createInMemoryUserRepository({ seedUsers = [], seedDepartments = null, revokeUserSessions = null } = {}) {
  const departmentsById = new Map();
  const usersById = new Map();
  const userIdByEmail = new Map();
  let nextUserId = 1n;
  let lockChain = Promise.resolve();
  let seedPromise = null;
  let revokeHook = revokeUserSessions;

  function withLock(fn) {
    const run = lockChain.then(fn, fn);
    lockChain = run.catch(() => {});
    return run;
  }

  function registerDepartments() {
    const depts = Array.isArray(seedDepartments) ? seedDepartments : DEFAULT_IN_MEMORY_DEPARTMENTS;
    for (const dept of depts) {
      const id = String(dept.departmentId ?? dept.id);
      departmentsById.set(id, {
        departmentId: id,
        departmentCode: dept.departmentCode ?? dept.code ?? `DEPT_${id}`,
        departmentName: dept.departmentName ?? dept.name ?? `Department ${id}`,
      });
    }
    if (!Array.isArray(seedDepartments)) {
      for (const user of seedUsers) {
        if (user.departmentId != null) {
          const id = String(user.departmentId);
          if (!departmentsById.has(id)) {
            departmentsById.set(id, {
              departmentId: id,
              departmentCode: `DEPT_${id}`,
              departmentName: user.departmentName ?? `Department ${id}`,
            });
          }
        }
      }
    }
  }

  registerDepartments();

  async function initSeedUsers() {
    const nowIso = new Date().toISOString();
    for (const entry of seedUsers) {
      let userId;
      if (entry.userId != null) {
        userId = String(entry.userId);
        if (/^[1-9][0-9]*$/.test(userId) && BigInt(userId) >= nextUserId) {
          nextUserId = BigInt(userId) + 1n;
        }
      } else {
        userId = String(nextUserId++);
      }

      const normalizedEmail = entry.email == null ? null : String(entry.email).trim().toLowerCase();
      const passwordHash = entry.passwordHash !== undefined
        ? entry.passwordHash
        : (typeof entry.password === 'string' && entry.password.length > 0
          ? await hashPassword(entry.password)
          : null);

      const userRecord = {
        userId,
        email: normalizedEmail,
        passwordHash,
        fullName: entry.fullName ?? null,
        accountType: entry.accountType ?? 'STAFF',
        accountStatus: entry.accountStatus ?? 'ACTIVE',
        departmentId: entry.departmentId == null ? null : String(entry.departmentId),
        createdBy: entry.createdBy == null ? null : String(entry.createdBy),
        updatedBy: entry.updatedBy == null ? null : String(entry.updatedBy),
        createdAt: entry.createdAt ?? nowIso,
        updatedAt: entry.updatedAt ?? nowIso,
      };
      usersById.set(userId, userRecord);
      if (normalizedEmail) {
        userIdByEmail.set(normalizedEmail, userId);
      }
    }
  }

  function ensureSeeded() {
    if (!seedPromise) {
      seedPromise = initSeedUsers();
    }
    return seedPromise;
  }

  function toUserDto(record) {
    const dept = record.departmentId == null ? null : departmentsById.get(record.departmentId);
    return {
      userId: record.userId,
      email: record.email,
      fullName: record.fullName,
      accountType: record.accountType,
      accountStatus: record.accountStatus,
      departmentId: record.departmentId,
      departmentName: dept?.departmentName ?? null,
      createdBy: record.createdBy,
      updatedBy: record.updatedBy,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
    };
  }

  return {
    setRevokeUserSessionsHook(fn) {
      revokeHook = fn;
    },

    async findByEmailWithAuth(email) {
      await ensureSeeded();
      const normalized = String(email).trim().toLowerCase();
      const userId = userIdByEmail.get(normalized);
      if (!userId) return null;
      const record = usersById.get(userId);
      if (!record) return null;
      return {
        ...toUserDto(record),
        passwordHash: record.passwordHash,
      };
    },

    async findById(userId) {
      await ensureSeeded();
      const record = usersById.get(String(userId));
      return record ? toUserDto(record) : null;
    },

    async findByIdWithAuth(userId) {
      await ensureSeeded();
      const record = usersById.get(String(userId));
      if (!record) return null;
      return {
        ...toUserDto(record),
        passwordHash: record.passwordHash,
      };
    },

    async searchActiveStaff({ query = '', limit = 20 }) {
      await ensureSeeded();
      const needle = query.trim().toLowerCase();
      const matches = [];
      for (const record of usersById.values()) {
        if (record.accountType !== 'STAFF' || record.accountStatus !== 'ACTIVE') continue;
        if (needle.length > 0) {
          const fullNameMatch = (record.fullName ?? '').toLowerCase().includes(needle);
          const emailMatch = (record.email ?? '').toLowerCase().includes(needle);
          if (!fullNameMatch && !emailMatch) continue;
        }
        matches.push(toUserDto(record));
      }
      matches.sort((a, b) => {
        const nameCmp = (a.fullName ?? '').localeCompare(b.fullName ?? '');
        if (nameCmp !== 0) return nameCmp;
        return BigInt(a.userId) < BigInt(b.userId) ? -1 : 1;
      });
      return matches.slice(0, limit).map((user) => ({
        userId: user.userId,
        fullName: user.fullName,
        email: user.email,
        departmentId: user.departmentId,
        departmentName: user.departmentName,
        accountType: user.accountType,
        accountStatus: user.accountStatus,
      }));
    },

    async listAdminUsers({ query = '', status = null, accountType = null, page = 1, pageSize = 20 }) {
      await ensureSeeded();
      const needle = query.trim().toLowerCase();
      const matches = [];
      for (const record of usersById.values()) {
        if (status && record.accountStatus !== status) continue;
        if (accountType && record.accountType !== accountType) continue;
        if (needle.length > 0) {
          const fullNameMatch = (record.fullName ?? '').toLowerCase().includes(needle);
          const emailMatch = (record.email ?? '').toLowerCase().includes(needle);
          if (!fullNameMatch && !emailMatch) continue;
        }
        matches.push(toUserDto(record));
      }
      matches.sort((a, b) => (BigInt(a.userId) < BigInt(b.userId) ? -1 : 1));
      const total = matches.length;
      const offset = (page - 1) * pageSize;
      const users = matches.slice(offset, offset + pageSize);
      return {
        users,
        pagination: {
          page,
          pageSize,
          total,
          totalPages: total === 0 ? 0 : Math.ceil(total / pageSize),
        },
      };
    },

    async createUser({ email, fullName, passwordHash, accountType, departmentId, actorId }) {
      await ensureSeeded();
      return withLock(async () => {
        const normalizedEmail = email.trim().toLowerCase();
        if (userIdByEmail.has(normalizedEmail)) {
          return { code: 'EMAIL_ALREADY_EXISTS' };
        }
        const normalizedDeptId = departmentId == null ? null : String(departmentId);
        if (normalizedDeptId !== null && !departmentsById.has(normalizedDeptId)) {
          return { code: 'DEPARTMENT_NOT_FOUND' };
        }
        const nowIso = new Date().toISOString();
        const userId = String(nextUserId++);
        const record = {
          userId,
          email: normalizedEmail,
          passwordHash,
          fullName,
          accountType,
          accountStatus: 'ACTIVE',
          departmentId: normalizedDeptId,
          createdBy: actorId == null ? null : String(actorId),
          updatedBy: actorId == null ? null : String(actorId),
          createdAt: nowIso,
          updatedAt: nowIso,
        };
        usersById.set(userId, record);
        userIdByEmail.set(normalizedEmail, userId);
        return { user: toUserDto(record) };
      });
    },

    async updateUser({ userId, fullName, departmentId, hasDepartmentId, accountType, actorId, revokeUserSessions }) {
      await ensureSeeded();
      return withLock(async () => {
        const record = usersById.get(String(userId));
        if (!record) return { code: 'USER_NOT_FOUND' };

        const previousAccountType = record.accountType;
        const nextAccountType = accountType ?? record.accountType;
        const nextDepartmentId = hasDepartmentId
          ? (departmentId == null ? null : String(departmentId))
          : record.departmentId;

        if (nextAccountType === 'STAFF' && nextDepartmentId === null) {
          return { code: 'STAFF_DEPARTMENT_REQUIRED' };
        }
        if (nextDepartmentId !== null && !departmentsById.has(nextDepartmentId)) {
          return { code: 'DEPARTMENT_NOT_FOUND' };
        }

        if (nextAccountType === 'STAFF' && previousAccountType === 'ADMIN') {
          if (String(record.userId) === String(actorId)) {
            return { code: 'CANNOT_DEMOTE_SELF' };
          }
          if (record.accountStatus === 'ACTIVE') {
            let otherActiveAdmins = 0;
            for (const candidate of usersById.values()) {
              if (candidate.userId !== record.userId && candidate.accountType === 'ADMIN' && candidate.accountStatus === 'ACTIVE') {
                otherActiveAdmins += 1;
              }
            }
            if (otherActiveAdmins === 0) {
              return { code: 'LAST_ADMIN_REQUIRED' };
            }
          }
        }

        if (fullName !== undefined) record.fullName = fullName;
        if (hasDepartmentId) record.departmentId = nextDepartmentId;
        if (accountType !== undefined) record.accountType = nextAccountType;
        record.updatedBy = actorId == null ? null : String(actorId);
        record.updatedAt = new Date().toISOString();

        const roleChanged = accountType !== undefined && accountType !== previousAccountType;
        if (roleChanged) {
          const revoker = revokeUserSessions ?? revokeHook;
          if (typeof revoker === 'function') {
            await revoker(record.userId, 'ROLE_CHANGED');
          }
        }

        return { user: toUserDto(record), roleChanged };
      });
    },

    async updateUserStatus({ userId, accountStatus, actorId, revokeUserSessions }) {
      await ensureSeeded();
      return withLock(async () => {
        const record = usersById.get(String(userId));
        if (!record) return { code: 'USER_NOT_FOUND' };

        if (accountStatus === 'DISABLED' && String(record.userId) === String(actorId)) {
          return { code: 'CANNOT_DISABLE_SELF' };
        }

        if (accountStatus === 'DISABLED' && record.accountType === 'ADMIN' && record.accountStatus === 'ACTIVE') {
          let otherActiveAdmins = 0;
          for (const candidate of usersById.values()) {
            if (candidate.userId !== record.userId && candidate.accountType === 'ADMIN' && candidate.accountStatus === 'ACTIVE') {
              otherActiveAdmins += 1;
            }
          }
          if (otherActiveAdmins === 0) {
            return { code: 'LAST_ADMIN_REQUIRED' };
          }
        }

        const previousStatus = record.accountStatus;
        record.accountStatus = accountStatus;
        record.updatedBy = actorId == null ? null : String(actorId);
        record.updatedAt = new Date().toISOString();

        if (accountStatus === 'DISABLED') {
          const revoker = revokeUserSessions ?? revokeHook;
          if (typeof revoker === 'function') {
            await revoker(record.userId, 'ACCOUNT_DISABLED');
          }
        }

        return { user: toUserDto(record), previousStatus };
      });
    },
  };
}

module.exports = {
  createInMemoryUserRepository,
  DEFAULT_IN_MEMORY_DEPARTMENTS,
};

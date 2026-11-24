const { hashPassword } = require('../src/auth/password');
const { loadConfig, loadDotEnv } = require('../src/config');

const DEFAULT_DEPARTMENTS = Object.freeze([
  { code: 'CARDIOLOGY', name: 'Cardiology', description: 'Cardiology Department' },
  { code: 'ONCOLOGY', name: 'Oncology', description: 'Oncology Department' },
  { code: 'RADIOLOGY', name: 'Radiology', description: 'Radiology Department' },
  { code: 'PEDIATRICS', name: 'Pediatrics', description: 'Pediatrics Department' },
  { code: 'GENERAL_MEDICINE', name: 'General Medicine', description: 'General Medicine Department' },
]);

const DEFAULT_SEED_ACCOUNTS = Object.freeze([
  {
    email: 'admin1@hospital.local',
    fullName: 'System Admin One',
    accountType: 'ADMIN',
    accountStatus: 'ACTIVE',
    departmentCode: null,
    devPassword: 'Admin1#MedShare!',
  },
  {
    email: 'admin2@hospital.local',
    fullName: 'System Admin Two',
    accountType: 'ADMIN',
    accountStatus: 'ACTIVE',
    departmentCode: null,
    devPassword: 'Admin2#MedShare!',
  },
  {
    email: 'doctor.cardio1@hospital.local',
    fullName: 'Dr. Cardiology One',
    accountType: 'STAFF',
    accountStatus: 'ACTIVE',
    departmentCode: 'CARDIOLOGY',
    devPassword: 'CardioDoc1#MedShare!',
  },
  {
    email: 'doctor.cardio2@hospital.local',
    fullName: 'Dr. Cardiology Two',
    accountType: 'STAFF',
    accountStatus: 'ACTIVE',
    departmentCode: 'CARDIOLOGY',
    devPassword: 'CardioDoc2#MedShare!',
  },
  {
    email: 'doctor.onco1@hospital.local',
    fullName: 'Dr. Oncology One',
    accountType: 'STAFF',
    accountStatus: 'ACTIVE',
    departmentCode: 'ONCOLOGY',
    devPassword: 'OncoDoc1#MedShare!',
  },
  {
    email: 'doctor.onco2@hospital.local',
    fullName: 'Dr. Oncology Two',
    accountType: 'STAFF',
    accountStatus: 'ACTIVE',
    departmentCode: 'ONCOLOGY',
    devPassword: 'OncoDoc2#MedShare!',
  },
  {
    email: 'nurse.cardio1@hospital.local',
    fullName: 'Nurse Cardiology One',
    accountType: 'STAFF',
    accountStatus: 'ACTIVE',
    departmentCode: 'CARDIOLOGY',
    devPassword: 'CardioNurse1#MedShare!',
  },
  {
    email: 'nurse.cardio2@hospital.local',
    fullName: 'Nurse Cardiology Two',
    accountType: 'STAFF',
    accountStatus: 'ACTIVE',
    departmentCode: 'CARDIOLOGY',
    devPassword: 'CardioNurse2#MedShare!',
  },
  {
    email: 'radiologist1@hospital.local',
    fullName: 'Dr. Radiology One',
    accountType: 'STAFF',
    accountStatus: 'ACTIVE',
    departmentCode: 'RADIOLOGY',
    devPassword: 'Radio1#MedShare!',
  },
  {
    email: 'radiologist2@hospital.local',
    fullName: 'Dr. Radiology Two',
    accountType: 'STAFF',
    accountStatus: 'ACTIVE',
    departmentCode: 'RADIOLOGY',
    devPassword: 'Radio2#MedShare!',
  },
  {
    email: 'pediatrician1@hospital.local',
    fullName: 'Dr. Pediatrics One',
    accountType: 'STAFF',
    accountStatus: 'ACTIVE',
    departmentCode: 'PEDIATRICS',
    devPassword: 'Peds1#MedShare!',
  },
  {
    email: 'pediatrician2@hospital.local',
    fullName: 'Dr. Pediatrics Two',
    accountType: 'STAFF',
    accountStatus: 'ACTIVE',
    departmentCode: 'PEDIATRICS',
    devPassword: 'Peds2#MedShare!',
  },
  {
    email: 'staff.general1@hospital.local',
    fullName: 'Staff General One',
    accountType: 'STAFF',
    accountStatus: 'ACTIVE',
    departmentCode: 'GENERAL_MEDICINE',
    devPassword: 'General1#MedShare!',
  },
  {
    email: 'staff.general2@hospital.local',
    fullName: 'Staff General Two',
    accountType: 'STAFF',
    accountStatus: 'ACTIVE',
    departmentCode: 'GENERAL_MEDICINE',
    devPassword: 'General2#MedShare!',
  },
  {
    email: 'disabled.staff@hospital.local',
    fullName: 'Disabled Staff Account',
    accountType: 'STAFF',
    accountStatus: 'DISABLED',
    departmentCode: 'GENERAL_MEDICINE',
    devPassword: 'DisabledStaff#MedShare!',
  },
  {
    email: 'disabled.admin@hospital.local',
    fullName: 'Disabled Admin Account',
    accountType: 'ADMIN',
    accountStatus: 'DISABLED',
    departmentCode: null,
    devPassword: 'DisabledAdmin#MedShare!',
  },
]);

async function runWithConnection(poolOrConnection, fn) {
  if (typeof poolOrConnection.getConnection === 'function') {
    const connection = await poolOrConnection.getConnection();
    let inTransaction = false;
    try {
      await connection.beginTransaction();
      inTransaction = true;
      const result = await fn(connection);
      await connection.commit();
      return result;
    } catch (error) {
      if (inTransaction) {
        await connection.rollback();
      }
      throw error;
    } finally {
      connection.release();
    }
  }
  return fn(poolOrConnection);
}

async function seedUsers(poolOrConnection, {
  env = process.env,
  defaultPassword,
  departments = DEFAULT_DEPARTMENTS,
  accounts = DEFAULT_SEED_ACCOUNTS,
} = {}) {
  const nodeEnv = env.NODE_ENV || 'development';
  const overridePassword = defaultPassword ?? env.SEED_DEFAULT_PASSWORD ?? env.SEED_PASSWORD ?? null;

  if (nodeEnv === 'production' && !overridePassword) {
    throw new Error('Refusing to seed default development passwords when NODE_ENV=production without SEED_DEFAULT_PASSWORD');
  }

  return runWithConnection(poolOrConnection, async (connection) => {
    const departmentIdByCode = new Map();
    const seededDepartments = [];

    for (const dept of departments) {
      const [existingRows] = await connection.execute(
        'SELECT CAST(department_id AS CHAR) AS departmentId FROM Department WHERE department_code = ?',
        [dept.code],
      );
      let departmentId;
      if (existingRows.length > 0) {
        departmentId = String(existingRows[0].departmentId);
        await connection.execute(
          'UPDATE Department SET department_name = ?, description = ? WHERE department_id = ?',
          [dept.name, dept.description ?? null, departmentId],
        );
      } else {
        const [insertResult] = await connection.execute(
          'INSERT INTO Department (department_code, department_name, description) VALUES (?, ?, ?)',
          [dept.code, dept.name, dept.description ?? null],
        );
        departmentId = String(insertResult.insertId);
      }
      departmentIdByCode.set(dept.code, departmentId);
      seededDepartments.push({ departmentId, code: dept.code, name: dept.name });
    }

    const seededAccounts = [];
    for (const account of accounts) {
      const email = account.email.trim().toLowerCase();
      const departmentId = account.departmentCode
        ? (departmentIdByCode.get(account.departmentCode) ?? null)
        : null;
      if (account.accountType === 'STAFF' && !departmentId) {
        throw new Error(`Department code not found for seeded STAFF account: ${account.departmentCode}`);
      }
      const rawPassword = overridePassword || account.devPassword;
      const passwordHash = await hashPassword(rawPassword);

      const [existingUsers] = await connection.execute(
        'SELECT CAST(user_id AS CHAR) AS userId FROM `User` WHERE email = ?',
        [email],
      );
      let userId;
      if (existingUsers.length > 0) {
        userId = String(existingUsers[0].userId);
        await connection.execute(
          `UPDATE \`User\`
           SET department_id = ?, full_name = ?, password_hash = ?, account_type = ?, account_status = ?
           WHERE user_id = ?`,
          [departmentId, account.fullName, passwordHash, account.accountType, account.accountStatus, userId],
        );
      } else {
        const [insertResult] = await connection.execute(
          `INSERT INTO \`User\` (department_id, email, password_hash, full_name, account_type, account_status)
           VALUES (?, ?, ?, ?, ?, ?)`,
          [departmentId, email, passwordHash, account.fullName, account.accountType, account.accountStatus],
        );
        userId = String(insertResult.insertId);
      }

      seededAccounts.push({
        userId,
        email,
        fullName: account.fullName,
        accountType: account.accountType,
        accountStatus: account.accountStatus,
        departmentCode: account.departmentCode ?? null,
        departmentId,
      });
    }

    return {
      departments: seededDepartments,
      accounts: seededAccounts,
    };
  });
}

async function main() {
  loadDotEnv();
  const config = loadConfig();
  const mysql = require('mysql2/promise');
  const pool = mysql.createPool({ ...config.db, timezone: 'Z', waitForConnections: true, connectionLimit: 5 });
  try {
    const result = await seedUsers(pool, { env: process.env });
    console.log(`Seeded ${result.departments.length} departments and ${result.accounts.length} accounts`);
  } finally {
    await pool.end();
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}

module.exports = {
  DEFAULT_DEPARTMENTS,
  DEFAULT_SEED_ACCOUNTS,
  seedUsers,
};

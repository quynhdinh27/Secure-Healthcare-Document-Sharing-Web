// DEVELOPMENT ONLY. Creates 1 admin + 15 staff accounts with ACTIVE key pairs and
// three demo treatment folders. Private keys are written to data/dev-keys/<userId>.json
// (gitignored) so the smoke test and frontend developers can act as these users.
const path = require('node:path');
const { backendDir, loadConfig, loadDotEnv } = require('../src/config');
const { createPool } = require('../src/main');
const {
  createApiClient, createDevUser, createFolderWithMembers, startDevServer, writeDevKeyFile,
} = require('./lib/dev-accounts.cjs');
const { completeFolderRotations } = require('./dev-complete-rotations.cjs');

const DEV_KEYS_DIR = path.join(backendDir, 'data', 'dev-keys');

async function main() {
  loadDotEnv();
  const config = loadConfig();
  if (config.nodeEnv === 'production') throw new Error('seed is not allowed in production');
  const pool = createPool(config.db);
  let server;
  try {
    const [[existing]] = await pool.execute("SELECT COUNT(*) AS count FROM `User` WHERE email = 'admin@medshare.test'");
    if (Number(existing.count) > 0) {
      throw new Error('Seed data already exists. Reset with: docker compose down -v && docker compose up -d --wait && npm run migrate && npm run seed');
    }
    const admin = await createDevUser(pool, {
      email: 'admin@medshare.test', fullName: 'Quản trị viên bệnh viện', accountType: 'ADMIN', withKeys: false,
    });
    const staff = [];
    for (let index = 1; index <= 15; index += 1) {
      const number = String(index).padStart(2, '0');
      const user = await createDevUser(pool, { email: `staff${number}@medshare.test`, fullName: `Nhân viên ${number}` });
      await writeDevKeyFile(DEV_KEYS_DIR, user);
      staff.push(user);
    }
    server = await startDevServer({ config, pool });
    const call = createApiClient(server.baseUrl);
    const s = (number) => staff[number - 1];
    const folders = [
      {
        owner: s(1),
        folder: { name: 'Điều trị nội khoa - BN001', patientRef: 'DEMO-PATIENT-001', treatmentReference: 'DEMO-EPISODE-001' },
        members: [{ user: s(2), role: 'EDITOR' }, { user: s(3), role: 'EDITOR' }, { user: s(4), role: 'VIEWER' }, { user: s(5), role: 'VIEWER' }],
      },
      {
        owner: s(2),
        folder: { name: 'Xét nghiệm - BN002', patientRef: 'DEMO-PATIENT-002', treatmentReference: 'DEMO-EPISODE-002' },
        members: [{ user: s(6), role: 'EDITOR' }, { user: s(1), role: 'VIEWER' }, { user: s(7), role: 'VIEWER' }],
      },
      {
        owner: s(8),
        folder: { name: 'Chẩn đoán hình ảnh - BN003', patientRef: 'DEMO-PATIENT-003', treatmentReference: 'DEMO-EPISODE-003' },
        members: [{ user: s(9), role: 'EDITOR' }, { user: s(10), role: 'VIEWER' }],
      },
    ];
    const roles = new Map(staff.map((user) => [user.userId, []]));
    for (const entry of folders) {
      const folderId = await createFolderWithMembers({ call, ...entry });
      await completeFolderRotations(pool, folderId);
      roles.get(entry.owner.userId).push(`OWNER ${entry.folder.name} (${folderId})`);
      for (const { user, role } of entry.members) roles.get(user.userId).push(`${role} ${entry.folder.name}`);
    }
    console.log(`ADMIN  user ${admin.userId}  ${admin.email}`);
    for (const user of staff) {
      console.log(`STAFF  user ${user.userId}  ${user.email}  ${roles.get(user.userId).join('; ') || 'no folder (outsider)'}`);
    }
    console.log(`Private keys for staff accounts: ${DEV_KEYS_DIR}`);
  } finally {
    if (server) await server.close();
    await pool.end();
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});

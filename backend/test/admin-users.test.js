const test = require('node:test');
const assert = require('node:assert/strict');
const { once } = require('node:events');
const { createApp } = require('../src/server');
const { createAuditService } = require('../src/audit/audit-service');
const { createInMemoryAuditRepository } = require('../src/audit/in-memory-audit-repository');

async function startServer(app, t) {
  const server = app.listen(0, '127.0.0.1');
  t.after(() => server.close());
  await once(server, 'listening');
  return `http://127.0.0.1:${server.address().port}`;
}

function extractCookies(response, jar = new Map()) {
  for (const header of response.headers.getSetCookie()) {
    const [pair] = header.split(';');
    const idx = pair.indexOf('=');
    const name = pair.slice(0, idx);
    const value = pair.slice(idx + 1);
    if (header.includes('Max-Age=0')) jar.delete(name);
    else jar.set(name, decodeURIComponent(value));
  }
  return jar;
}

function cookieHeader(jar) {
  return [...jar.entries()].map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('; ');
}

async function loginAs(base, email, password) {
  const csrfRes = await fetch(`${base}/api/v1/auth/csrf`);
  const jar = extractCookies(csrfRes);
  const { csrfToken } = await csrfRes.json();
  const res = await fetch(`${base}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: cookieHeader(jar), 'x-csrf-token': csrfToken },
    body: JSON.stringify({ email, password }),
  });
  assert.equal(res.status, 200);
  extractCookies(res, jar);
  const body = await res.json();
  return { jar, csrfToken: body.csrfToken, user: body.user };
}

test('searchStaff and Admin user management lifecycle, concurrency guards, and audit redaction', async (t) => {
  const auditRepo = createInMemoryAuditRepository();
  const app = createApp({
    cookieSecure: false,
    auditService: createAuditService({ auditRepository: auditRepo }),
    seedUsers: [
      { email: 'admin1@hospital.local', password: 'Admin1Password!', fullName: 'Admin One', accountType: 'ADMIN' },
      { email: 'admin2@hospital.local', password: 'Admin2Password!', fullName: 'Admin Two', accountType: 'ADMIN' },
      { email: 'cardio@hospital.local', password: 'CardioPassword!', fullName: 'Dr. 100% Cardio_One', accountType: 'STAFF', departmentId: '1' },
      { email: 'onco@hospital.local', password: 'OncoPassword!', fullName: 'Dr. Oncology', accountType: 'STAFF', departmentId: '2' },
      { email: 'off@hospital.local', password: 'OffPassword!', fullName: 'Disabled Staff', accountType: 'STAFF', accountStatus: 'DISABLED', departmentId: '1' },
    ],
  });

  const base = await startServer(app, t);
  const admin1 = await loginAs(base, 'admin1@hospital.local', 'Admin1Password!');
  const admin2 = await loginAs(base, 'admin2@hospital.local', 'Admin2Password!');
  const cardio = await loginAs(base, 'cardio@hospital.local', 'CardioPassword!');

  // Unauthenticated searchStaff -> 401
  assert.equal((await fetch(`${base}/api/v1/users?query=Dr`)).status, 401);

  // searchStaff returns active STAFF safe fields only, excludes ADMIN & DISABLED, escapes %/_
  const searchRes = await fetch(`${base}/api/v1/users?query=100%25`, {
    headers: { cookie: cookieHeader(cardio.jar) },
  });
  assert.equal(searchRes.status, 200);
  const searchBody = await searchRes.json();
  assert.equal(searchBody.users.length, 1);
  assert.deepEqual(Object.keys(searchBody.users[0]).sort(), [
    'accountStatus', 'accountType', 'departmentId', 'departmentName', 'email', 'fullName', 'userId',
  ]);
  assert.equal(searchBody.users[0].email, 'cardio@hospital.local');

  // Duplicate query param -> 400 VALIDATION_ERROR
  const dupQueryRes = await fetch(`${base}/api/v1/users?query=a&query=b`, {
    headers: { cookie: cookieHeader(cardio.jar) },
  });
  assert.equal(dupQueryRes.status, 400);
  assert.equal((await dupQueryRes.json()).code, 'VALIDATION_ERROR');

  // /api/v1/users/me/keys not shadowed by searchStaff
  const futureKeyRoute = await fetch(`${base}/api/v1/users/me/keys`, {
    headers: { cookie: cookieHeader(cardio.jar) },
  });
  assert.equal(futureKeyRoute.status, 404);

  // STAFF blocked from admin routes
  const staffAdminGet = await fetch(`${base}/api/v1/admin/users`, {
    headers: { cookie: cookieHeader(cardio.jar) },
  });
  assert.equal(staffAdminGet.status, 403);
  assert.equal((await staffAdminGet.json()).code, 'FORBIDDEN');

  // Admin creates STAFF user using default in-memory departments
  const createStaffRes = await fetch(`${base}/api/v1/admin/users`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: cookieHeader(admin1.jar), 'x-csrf-token': admin1.csrfToken },
    body: JSON.stringify({
      email: 'new.nurse@hospital.local',
      fullName: 'New Nurse',
      password: 'NewNursePassword!',
      accountType: 'STAFF',
      departmentId: '3',
    }),
  });
  assert.equal(createStaffRes.status, 201);
  const createdStaff = (await createStaffRes.json()).user;
  assert.equal(createStaffRes.headers.get('location'), `/api/v1/admin/users/${createdStaff.userId}`);
  assert.deepEqual(Object.keys(createdStaff).sort(), [
    'accountStatus', 'accountType', 'createdAt', 'createdBy', 'departmentId',
    'departmentName', 'email', 'fullName', 'updatedAt', 'updatedBy', 'userId',
  ]);
  assert.equal(createdStaff.createdBy, admin1.user.userId);
  assert.equal(createdStaff.departmentName, 'Radiology');

  // Duplicate email -> 409 EMAIL_ALREADY_EXISTS
  const dupEmailRes = await fetch(`${base}/api/v1/admin/users`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: cookieHeader(admin1.jar), 'x-csrf-token': admin1.csrfToken },
    body: JSON.stringify({
      email: 'NEW.NURSE@hospital.local',
      fullName: 'Duplicate Nurse',
      password: 'NewNursePassword!',
      accountType: 'STAFF',
      departmentId: '3',
    }),
  });
  assert.equal(dupEmailRes.status, 409);
  assert.equal((await dupEmailRes.json()).code, 'EMAIL_ALREADY_EXISTS');

  // STAFF without departmentId -> 400; unknown department -> 404; ADMIN with null department -> 201
  const missingDeptRes = await fetch(`${base}/api/v1/admin/users`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: cookieHeader(admin1.jar), 'x-csrf-token': admin1.csrfToken },
    body: JSON.stringify({
      email: 'missingdept@hospital.local',
      fullName: 'Missing Dept',
      password: 'Password123!',
      accountType: 'STAFF',
    }),
  });
  assert.equal(missingDeptRes.status, 400);

  const badDeptRes = await fetch(`${base}/api/v1/admin/users`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: cookieHeader(admin1.jar), 'x-csrf-token': admin1.csrfToken },
    body: JSON.stringify({
      email: 'baddept@hospital.local',
      fullName: 'Bad Dept',
      password: 'Password123!',
      accountType: 'STAFF',
      departmentId: '999',
    }),
  });
  assert.equal(badDeptRes.status, 404);
  assert.equal((await badDeptRes.json()).code, 'DEPARTMENT_NOT_FOUND');

  // List + array query guard + getAdminUser
  const listRes = await fetch(`${base}/api/v1/admin/users?status=ACTIVE&page=1&pageSize=2`, {
    headers: { cookie: cookieHeader(admin1.jar) },
  });
  assert.equal(listRes.status, 200);
  const listBody = await listRes.json();
  assert.equal(listBody.users.length, 2);
  assert.equal(listBody.pagination.total, 5);
  assert.equal(listBody.pagination.totalPages, 3);

  const badListQuery = await fetch(`${base}/api/v1/admin/users?status=ACTIVE&status=DISABLED`, {
    headers: { cookie: cookieHeader(admin1.jar) },
  });
  assert.equal(badListQuery.status, 400);

  const getRes = await fetch(`${base}/api/v1/admin/users/${createdStaff.userId}`, {
    headers: { cookie: cookieHeader(admin1.jar) },
  });
  assert.equal(getRes.status, 200);
  assert.equal((await fetch(`${base}/api/v1/admin/users/999999`, { headers: { cookie: cookieHeader(admin1.jar) } })).status, 404);
  assert.equal((await fetch(`${base}/api/v1/admin/users/abc`, { headers: { cookie: cookieHeader(admin1.jar) } })).status, 400);

  // updateAdminUser rejects accountStatus, rejects self-demotion, revokes sessions bidirectionally (STAFF -> ADMIN & ADMIN -> STAFF)
  const badStatusPatch = await fetch(`${base}/api/v1/admin/users/${createdStaff.userId}`, {
    method: 'PATCH',
    headers: { 'content-type': 'application/json', cookie: cookieHeader(admin1.jar), 'x-csrf-token': admin1.csrfToken },
    body: JSON.stringify({ accountStatus: 'DISABLED' }),
  });
  assert.equal(badStatusPatch.status, 400);

  const selfDemoteRes = await fetch(`${base}/api/v1/admin/users/${admin1.user.userId}`, {
    method: 'PATCH',
    headers: { 'content-type': 'application/json', cookie: cookieHeader(admin1.jar), 'x-csrf-token': admin1.csrfToken },
    body: JSON.stringify({ accountType: 'STAFF', departmentId: '1' }),
  });
  assert.equal(selfDemoteRes.status, 409);
  assert.equal((await selfDemoteRes.json()).code, 'CANNOT_DEMOTE_SELF');

  // Login as new nurse, then promote STAFF -> ADMIN => old nurse session must be revoked!
  const nurseSession = await loginAs(base, 'new.nurse@hospital.local', 'NewNursePassword!');
  const promoteRes = await fetch(`${base}/api/v1/admin/users/${createdStaff.userId}`, {
    method: 'PATCH',
    headers: { 'content-type': 'application/json', cookie: cookieHeader(admin1.jar), 'x-csrf-token': admin1.csrfToken },
    body: JSON.stringify({ accountType: 'ADMIN', departmentId: null }),
  });
  assert.equal(promoteRes.status, 200);
  assert.equal((await fetch(`${base}/api/v1/auth/me`, { headers: { cookie: cookieHeader(nurseSession.jar) } })).status, 401);

  // Demoting ADMIN (with null dept) -> STAFF without departmentId fails 400; with departmentId succeeds & revokes session
  const demoteMissingDept = await fetch(`${base}/api/v1/admin/users/${createdStaff.userId}`, {
    method: 'PATCH',
    headers: { 'content-type': 'application/json', cookie: cookieHeader(admin1.jar), 'x-csrf-token': admin1.csrfToken },
    body: JSON.stringify({ accountType: 'STAFF' }),
  });
  assert.equal(demoteMissingDept.status, 400);

  const nurseAdminSession = await loginAs(base, 'new.nurse@hospital.local', 'NewNursePassword!');
  const demoteOk = await fetch(`${base}/api/v1/admin/users/${createdStaff.userId}`, {
    method: 'PATCH',
    headers: { 'content-type': 'application/json', cookie: cookieHeader(admin1.jar), 'x-csrf-token': admin1.csrfToken },
    body: JSON.stringify({ accountType: 'STAFF', departmentId: '3' }),
  });
  assert.equal(demoteOk.status, 200);
  assert.equal((await fetch(`${base}/api/v1/auth/me`, { headers: { cookie: cookieHeader(nurseAdminSession.jar) } })).status, 401);

  // Self-disable blocked
  const selfDisable = await fetch(`${base}/api/v1/admin/users/${admin1.user.userId}/status`, {
    method: 'PATCH',
    headers: { 'content-type': 'application/json', cookie: cookieHeader(admin1.jar), 'x-csrf-token': admin1.csrfToken },
    body: JSON.stringify({ accountStatus: 'DISABLED' }),
  });
  assert.equal(selfDisable.status, 409);
  assert.equal((await selfDisable.json()).code, 'CANNOT_DISABLE_SELF');

  // Concurrent mutual disable between admin1 and admin2 -> one succeeds (200), the other fails (409 LAST_ADMIN_REQUIRED or 401 UNAUTHENTICATED if session already revoked)
  const [res1, res2] = await Promise.all([
    fetch(`${base}/api/v1/admin/users/${admin2.user.userId}/status`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json', cookie: cookieHeader(admin1.jar), 'x-csrf-token': admin1.csrfToken },
      body: JSON.stringify({ accountStatus: 'DISABLED' }),
    }),
    fetch(`${base}/api/v1/admin/users/${admin1.user.userId}/status`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json', cookie: cookieHeader(admin2.jar), 'x-csrf-token': admin2.csrfToken },
      body: JSON.stringify({ accountStatus: 'DISABLED' }),
    }),
  ]);
  const statuses = [res1.status, res2.status].sort((a, b) => a - b);
  assert.equal(statuses[0], 200);
  assert.ok([401, 409].includes(statuses[1]), `Expected 401 or 409, got ${statuses[1]}`);

  // Verify surviving admin still cannot disable themselves or leave 0 admins, and direct repository concurrency returns LAST_ADMIN_REQUIRED
  const surviving = res1.status === 200 ? admin1 : admin2;
  const meSurviving = await fetch(`${base}/api/v1/auth/me`, { headers: { cookie: cookieHeader(surviving.jar) } });
  assert.equal(meSurviving.status, 200);

  // Verify repository-level concurrent mutual disable enforces LAST_ADMIN_REQUIRED deterministically
  const { createInMemoryUserRepository } = require('../src/users/in-memory-user-repository');
  const concurrentRepo = createInMemoryUserRepository({
    seedUsers: [
      { userId: '1', email: 'a1@h.local', password: 'Password1!', accountType: 'ADMIN', accountStatus: 'ACTIVE' },
      { userId: '2', email: 'a2@h.local', password: 'Password2!', accountType: 'ADMIN', accountStatus: 'ACTIVE' },
    ],
  });
  const [rA, rB] = await Promise.all([
    concurrentRepo.updateUserStatus({ userId: '2', accountStatus: 'DISABLED', actorId: '1' }),
    concurrentRepo.updateUserStatus({ userId: '1', accountStatus: 'DISABLED', actorId: '2' }),
  ]);
  const codes = [rA.code ?? 'OK', rB.code ?? 'OK'].sort();
  assert.deepEqual(codes, ['LAST_ADMIN_REQUIRED', 'OK']);

  // Verify zero secret leakage in audit logs
  const audits = await auditRepo.list();
  assert.equal(JSON.stringify(audits).includes('NewNursePassword!'), false);
});

test('ADMIN isolation against folderRepository and unconfigured folderRepository', async (t) => {
  const wiredApp = createApp({
    cookieSecure: false,
    seedUsers: [
      { email: 'admin@hospital.local', password: 'AdminPassword!', fullName: 'Admin', accountType: 'ADMIN' },
    ],
    verifyInitialFolderPolicy: async () => true,
    folderRepository: {
      async listForUser() { return []; },
      async findForUser() { return null; },
      async createForOwner() { throw new Error('ADMIN must never reach createForOwner'); },
      async getDashboardSummary() { return { folderCount: 0, documentCount: 0, recentFolders: [] }; },
    },
  });
  const base = await startServer(wiredApp, t);
  const admin = await loginAs(base, 'admin@hospital.local', 'AdminPassword!');

  const listFoldersRes = await fetch(`${base}/api/v1/folders`, {
    headers: { cookie: cookieHeader(admin.jar) },
  });
  assert.equal(listFoldersRes.status, 200);
  assert.deepEqual(await listFoldersRes.json(), { folders: [] });

  const getFolderRes = await fetch(`${base}/api/v1/folders/11111111-1111-1111-1111-111111111111`, {
    headers: { cookie: cookieHeader(admin.jar) },
  });
  assert.equal(getFolderRes.status, 403);
  assert.equal((await getFolderRes.json()).code, 'FORBIDDEN');

  // Even with verifyInitialFolderPolicy stubbed true, pre-router guard blocks ADMIN folder creation
  const createFolderRes = await fetch(`${base}/api/v1/folders`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: cookieHeader(admin.jar), 'x-csrf-token': admin.csrfToken },
    body: JSON.stringify({
      folderId: '11111111-1111-1111-1111-111111111111',
      name: 'Should Fail',
      patientRef: 'p1',
      treatmentReference: 'e1',
      signedPolicy: { payload: {}, signature: 'sig' },
    }),
  });
  assert.equal(createFolderRes.status, 403);
  assert.equal((await createFolderRes.json()).code, 'FORBIDDEN');

  const dashRes = await fetch(`${base}/api/v1/dashboard/summary`, {
    headers: { cookie: cookieHeader(admin.jar) },
  });
  assert.equal(dashRes.status, 200);
  assert.deepEqual(await dashRes.json(), { folderCount: 0, documentCount: 0, recentFolders: [] });

  const claimRes = await fetch(`${base}/api/v1/key-rotations/11111111-1111-1111-1111-111111111111/claim`, {
    method: 'POST',
    headers: { cookie: cookieHeader(admin.jar), 'x-csrf-token': admin.csrfToken },
  });
  assert.equal(claimRes.status, 403);

  // Unconfigured folderRepository keeps 503 on GET /folders while still blocking ADMIN mutations with 403
  const unwiredApp = createApp({
    cookieSecure: false,
    seedUsers: [
      { email: 'admin@hospital.local', password: 'AdminPassword!', fullName: 'Admin', accountType: 'ADMIN' },
    ],
  });
  const unwiredBase = await startServer(unwiredApp, t);
  const unwiredAdmin = await loginAs(unwiredBase, 'admin@hospital.local', 'AdminPassword!');
  assert.equal((await fetch(`${unwiredBase}/api/v1/folders`, { headers: { cookie: cookieHeader(unwiredAdmin.jar) } })).status, 503);
  assert.equal((await fetch(`${unwiredBase}/api/v1/folders`, {
    method: 'POST',
    headers: { cookie: cookieHeader(unwiredAdmin.jar), 'x-csrf-token': unwiredAdmin.csrfToken },
  })).status, 403);
});

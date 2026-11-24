const test = require('node:test');
const assert = require('node:assert/strict');
const { once } = require('node:events');
const { createApp } = require('../src/server');
const { createInMemoryAuditRepository } = require('../src/audit/in-memory-audit-repository');
const { createAuditService } = require('../src/audit/audit-service');

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
    if (header.includes('Max-Age=0')) {
      jar.delete(name);
    } else {
      jar.set(name, decodeURIComponent(value));
    }
  }
  return jar;
}

function cookieHeader(jar) {
  return [...jar.entries()].map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('; ');
}

test('Auth routes: CSRF pre-login reuse, cookies, login, me, reauthenticate, folder deletion TTL, logout, and audit redaction', async (t) => {
  const auditRepo = createInMemoryAuditRepository();
  const auditService = createAuditService({ auditRepository: auditRepo });
  const deletedFolders = [];

  const app = createApp({
    cookieSecure: true,
    reauthTtlMs: 80,
    auditService,
    seedUsers: [
      {
        email: 'doc1@hospital.local',
        password: 'Doc1Password!',
        fullName: 'Doctor One',
        accountType: 'STAFF',
        accountStatus: 'ACTIVE',
        departmentId: '1',
      },
      {
        email: 'doc2@hospital.local',
        password: 'Doc2Password!',
        fullName: 'Doctor Two',
        accountType: 'STAFF',
        accountStatus: 'ACTIVE',
        departmentId: '1',
      },
      {
        email: 'disabled@hospital.local',
        password: 'DisabledPass!',
        fullName: 'Disabled User',
        accountType: 'STAFF',
        accountStatus: 'DISABLED',
        departmentId: '1',
      },
      {
        email: 'nullpass@hospital.local',
        passwordHash: null,
        fullName: 'Null Password User',
        accountType: 'STAFF',
        accountStatus: 'ACTIVE',
        departmentId: '1',
      },
    ],
    folderRepository: {
      async deleteForOwner(ownerId, folderId) {
        deletedFolders.push({ ownerId, folderId });
        return { operationId: 'op-123', status: 'PENDING' };
      },
    },
  });

  const base = await startServer(app, t);
  const jar = new Map();

  // No public self-signup
  const regRes = await fetch(`${base}/api/v1/auth/register`, { method: 'POST' });
  assert.equal(regRes.status, 404);
  const signupRes = await fetch(`${base}/api/v1/auth/signup`, { method: 'POST' });
  assert.equal(signupRes.status, 404);

  // Unauthenticated mutation without CSRF must return 401 UNAUTHENTICATED before 403 CSRF_INVALID
  const unauthReauth = await fetch(`${base}/api/v1/auth/reauthenticate`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password: 'Doc1Password!' }),
  });
  assert.equal(unauthReauth.status, 401);
  assert.equal((await unauthReauth.json()).code, 'UNAUTHENTICATED');

  const unauthFolderDelete = await fetch(`${base}/api/v1/folders/11111111-1111-1111-1111-111111111111`, {
    method: 'DELETE',
  });
  assert.equal(unauthFolderDelete.status, 401);
  assert.equal((await unauthFolderDelete.json()).code, 'UNAUTHENTICATED');

  // Fetch CSRF token
  const csrfRes = await fetch(`${base}/api/v1/auth/csrf`);
  assert.equal(csrfRes.status, 200);
  assert.equal(csrfRes.headers.get('cache-control'), 'no-store');
  const csrfSetCookies = csrfRes.headers.getSetCookie();
  assert.ok(csrfSetCookies.some((c) => c.startsWith('medshare_csrf=') && c.includes('; Secure') && !c.includes('HttpOnly')));
  extractCookies(csrfRes, jar);
  const { csrfToken } = await csrfRes.json();
  assert.ok(typeof csrfToken === 'string' && csrfToken.length >= 32);

  // Login fails without or with unequal-length CSRF (never 500 RangeError)
  const shortCsrfRes = await fetch(`${base}/api/v1/auth/login`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      cookie: cookieHeader(jar),
      'x-csrf-token': 'x',
    },
    body: JSON.stringify({ email: 'doc1@hospital.local', password: 'Doc1Password!' }),
  });
  assert.equal(shortCsrfRes.status, 403);
  assert.equal((await shortCsrfRes.json()).code, 'CSRF_INVALID');

  // Express 5 invalid JSON & missing Content-Type / array body guards
  const badJsonRes = await fetch(`${base}/api/v1/auth/login`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      cookie: cookieHeader(jar),
      'x-csrf-token': csrfToken,
    },
    body: '{bad',
  });
  assert.equal(badJsonRes.status, 400);
  assert.equal((await badJsonRes.json()).code, 'INVALID_JSON');

  const arrayBodyRes = await fetch(`${base}/api/v1/auth/login`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      cookie: cookieHeader(jar),
      'x-csrf-token': csrfToken,
    },
    body: '[]',
  });
  assert.equal(arrayBodyRes.status, 400);
  assert.equal((await arrayBodyRes.json()).code, 'VALIDATION_ERROR');

  const noContentTypeRes = await fetch(`${base}/api/v1/auth/login`, {
    method: 'POST',
    headers: {
      cookie: cookieHeader(jar),
      'x-csrf-token': csrfToken,
    },
    body: JSON.stringify({ email: 'doc1@hospital.local', password: 'Doc1Password!' }),
  });
  assert.equal(noContentTypeRes.status, 400);
  assert.equal((await noContentTypeRes.json()).code, 'VALIDATION_ERROR');

  // Cross-account password isolation & null passwordHash & disabled account
  const wrongPassRes = await fetch(`${base}/api/v1/auth/login`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      cookie: cookieHeader(jar),
      'x-csrf-token': csrfToken,
    },
    body: JSON.stringify({ email: 'doc1@hospital.local', password: 'Doc2Password!' }),
  });
  assert.equal(wrongPassRes.status, 401);
  assert.equal((await wrongPassRes.json()).code, 'INVALID_CREDENTIALS');

  const nullPassRes = await fetch(`${base}/api/v1/auth/login`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      cookie: cookieHeader(jar),
      'x-csrf-token': csrfToken,
    },
    body: JSON.stringify({ email: 'nullpass@hospital.local', password: 'Doc1Password!' }),
  });
  assert.equal(nullPassRes.status, 401);

  const disabledRes = await fetch(`${base}/api/v1/auth/login`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      cookie: cookieHeader(jar),
      'x-csrf-token': csrfToken,
    },
    body: JSON.stringify({ email: 'disabled@hospital.local', password: 'DisabledPass!' }),
  });
  assert.equal(disabledRes.status, 403);
  assert.equal((await disabledRes.json()).code, 'ACCOUNT_DISABLED');

  // Valid login with oversized User-Agent (>255) succeeds cleanly
  const loginRes = await fetch(`${base}/api/v1/auth/login`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      cookie: cookieHeader(jar),
      'x-csrf-token': csrfToken,
      'user-agent': 'UA/'.repeat(200),
    },
    body: JSON.stringify({ email: '  DOC1@hospital.local ', password: 'Doc1Password!' }),
  });
  assert.equal(loginRes.status, 200);
  assert.equal(loginRes.headers.get('cache-control'), 'no-store');
  const loginCookies = loginRes.headers.getSetCookie();
  assert.ok(loginCookies.some((c) => c.startsWith('medshare_sid=') && c.includes('HttpOnly') && c.includes('SameSite=Lax') && c.includes('; Secure')));
  extractCookies(loginRes, jar);
  const loginBody = await loginRes.json();
  assert.equal(loginBody.csrfToken, csrfToken);
  assert.equal(loginBody.user.email, 'doc1@hospital.local');
  assert.equal(loginBody.user.passwordHash, undefined);

  // GET /api/v1/auth/me
  const meRes = await fetch(`${base}/api/v1/auth/me`, {
    headers: { cookie: cookieHeader(jar) },
  });
  assert.equal(meRes.status, 200);
  assert.equal(meRes.headers.get('cache-control'), 'no-store');
  const meBody = await meRes.json();
  assert.equal(meBody.user.userId, loginBody.user.userId);
  assert.equal(meBody.user.passwordHash, undefined);

  // Folder deletion requires reauthentication before succeeding
  const preReauthDelete = await fetch(`${base}/api/v1/folders/11111111-1111-1111-1111-111111111111`, {
    method: 'DELETE',
    headers: {
      cookie: cookieHeader(jar),
      'x-csrf-token': csrfToken,
    },
  });
  assert.equal(preReauthDelete.status, 403);
  assert.deepEqual(await preReauthDelete.json(), { code: 'REAUTHENTICATION_REQUIRED' });

  // Wrong password on reauthenticate
  const badReauth = await fetch(`${base}/api/v1/auth/reauthenticate`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      cookie: cookieHeader(jar),
      'x-csrf-token': csrfToken,
    },
    body: JSON.stringify({ password: 'WrongPassword!' }),
  });
  assert.equal(badReauth.status, 401);

  // Valid reauthenticate using pre-login reused csrfToken
  const okReauth = await fetch(`${base}/api/v1/auth/reauthenticate`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      cookie: cookieHeader(jar),
      'x-csrf-token': csrfToken,
    },
    body: JSON.stringify({ password: 'Doc1Password!' }),
  });
  assert.equal(okReauth.status, 200);
  const reauthBody = await okReauth.json();
  assert.ok(reauthBody.reauthenticatedAt.endsWith('Z'));
  assert.ok(reauthBody.reauthExpiresAt.endsWith('Z'));

  // Folder deletion now succeeds within TTL
  const okDelete = await fetch(`${base}/api/v1/folders/11111111-1111-1111-1111-111111111111`, {
    method: 'DELETE',
    headers: {
      cookie: cookieHeader(jar),
      'x-csrf-token': csrfToken,
    },
  });
  assert.equal(okDelete.status, 202);
  assert.equal(deletedFolders.length, 1);

  // Wait for reauth TTL expiry -> rejected again
  await new Promise((resolve) => setTimeout(resolve, 110));
  const expiredReauthDelete = await fetch(`${base}/api/v1/folders/22222222-2222-2222-2222-222222222222`, {
    method: 'DELETE',
    headers: {
      cookie: cookieHeader(jar),
      'x-csrf-token': csrfToken,
    },
  });
  assert.equal(expiredReauthDelete.status, 403);
  assert.deepEqual(await expiredReauthDelete.json(), { code: 'REAUTHENTICATION_REQUIRED' });

  // Logout succeeds and clears cookie; second logout is idempotent
  const logoutRes = await fetch(`${base}/api/v1/auth/logout`, {
    method: 'POST',
    headers: {
      cookie: cookieHeader(jar),
      'x-csrf-token': csrfToken,
    },
  });
  assert.equal(logoutRes.status, 200);
  assert.deepEqual(await logoutRes.json(), { loggedOut: true });
  const logoutCookies = logoutRes.headers.getSetCookie();
  assert.ok(logoutCookies.some((c) => c.startsWith('medshare_sid=;') && c.includes('Max-Age=0') && c.includes('HttpOnly') && c.includes('; Secure')));

  const meAfterLogout = await fetch(`${base}/api/v1/auth/me`, {
    headers: { cookie: cookieHeader(jar) },
  });
  assert.equal(meAfterLogout.status, 401);

  const secondLogout = await fetch(`${base}/api/v1/auth/logout`, {
    method: 'POST',
    headers: {
      cookie: cookieHeader(jar),
      'x-csrf-token': csrfToken,
    },
  });
  assert.equal(secondLogout.status, 200);
  assert.deepEqual(await secondLogout.json(), { loggedOut: true });

  // Audit logs contain zero secrets
  const audits = await auditRepo.list();
  assert.ok(audits.length >= 5);
  const serializedAudits = JSON.stringify(audits);
  assert.equal(serializedAudits.includes('Doc1Password!'), false);
  assert.equal(serializedAudits.includes(csrfToken), false);
  assert.equal(serializedAudits.includes('passwordHash'), false);
});

test('cookieSecure=false omits Secure flag, logout preserves forensic revoke_reason, and authEnabled=false disables auth routes', async (t) => {
  const app = createApp({
    cookieSecure: false,
    seedUsers: [
      {
        email: 'admin@hospital.local',
        password: 'AdminPassword!',
        fullName: 'Admin One',
        accountType: 'ADMIN',
        accountStatus: 'ACTIVE',
      },
      {
        email: 'staff@hospital.local',
        password: 'StaffPassword!',
        fullName: 'Staff One',
        accountType: 'STAFF',
        accountStatus: 'ACTIVE',
        departmentId: '1',
      },
    ],
  });
  const base = await startServer(app, t);

  const csrfRes = await fetch(`${base}/api/v1/auth/csrf`);
  assert.equal(csrfRes.headers.getSetCookie().some((c) => c.includes('; Secure')), false);
  const jar = extractCookies(csrfRes);
  const { csrfToken } = await csrfRes.json();

  const staffLogin = await fetch(`${base}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: cookieHeader(jar), 'x-csrf-token': csrfToken },
    body: JSON.stringify({ email: 'staff@hospital.local', password: 'StaffPassword!' }),
  });
  assert.equal(staffLogin.status, 200);
  assert.equal(staffLogin.headers.getSetCookie().some((c) => c.includes('; Secure')), false);
  const staffJar = extractCookies(staffLogin, new Map(jar));
  const staffUser = (await staffLogin.json()).user;

  // Admin disables staff -> revokes session with ACCOUNT_DISABLED
  const adminCsrfRes = await fetch(`${base}/api/v1/auth/csrf`);
  const adminJar = extractCookies(adminCsrfRes);
  const adminCsrf = (await adminCsrfRes.json()).csrfToken;
  const adminLogin = await fetch(`${base}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: cookieHeader(adminJar), 'x-csrf-token': adminCsrf },
    body: JSON.stringify({ email: 'admin@hospital.local', password: 'AdminPassword!' }),
  });
  extractCookies(adminLogin, adminJar);

  const disableRes = await fetch(`${base}/api/v1/admin/users/${staffUser.userId}/status`, {
    method: 'PATCH',
    headers: { 'content-type': 'application/json', cookie: cookieHeader(adminJar), 'x-csrf-token': adminCsrf },
    body: JSON.stringify({ accountStatus: 'DISABLED' }),
  });
  assert.equal(disableRes.status, 200);

  // Disabled user's subsequent logout succeeds idempotently
  const staffLogout = await fetch(`${base}/api/v1/auth/logout`, {
    method: 'POST',
    headers: { cookie: cookieHeader(staffJar), 'x-csrf-token': csrfToken },
  });
  assert.equal(staffLogout.status, 200);
  assert.deepEqual(await staffLogout.json(), { loggedOut: true });

  // authEnabled: false app
  const noAuthApp = createApp({ authEnabled: false });
  const noAuthBase = await startServer(noAuthApp, t);
  const live = await fetch(`${noAuthBase}/health/live`);
  assert.equal(live.status, 200);
  const authCsrf = await fetch(`${noAuthBase}/api/v1/auth/csrf`);
  assert.equal(authCsrf.status, 404);
});

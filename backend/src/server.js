const express = require('express');
const { createFolderRouter } = require('./folders/folder-router');
const { createMysqlFolderRepository } = require('./folders/mysql-folder-repository');
const { createFolderPolicyVerifiers } = require('./folders/folder-policy-signatures');
const { queueMysqlFolderRotation } = require('./folders/mysql-folder-rotation-queue');
const { createInMemoryAuditRepository } = require('./audit/in-memory-audit-repository');
const { createMysqlAuditRepository } = require('./audit/mysql-audit-repository');
const { createAuditService } = require('./audit/audit-service');
const { createInMemorySessionRepository } = require('./auth/in-memory-session-repository');
const { createMysqlSessionRepository } = require('./auth/mysql-session-repository');
const { createAuthService } = require('./auth/auth-service');
const { createAuthMiddleware } = require('./auth/auth-middleware');
const { createAuthRouter } = require('./auth/auth-router');
const { createInMemoryUserRepository } = require('./users/in-memory-user-repository');
const { createMysqlUserRepository } = require('./users/mysql-user-repository');
const { createUserService } = require('./users/user-service');
const { createUsersRouter } = require('./users/users-router');
const { createAdminUsersRouter } = require('./users/admin-users-router');

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function adminFolderMutationGuard(request, response, next) {
  if (request.user?.accountType === 'ADMIN' && MUTATING_METHODS.has(request.method)) {
    return response.status(403).json({
      code: 'FORBIDDEN',
      message: 'Hospital Administrators cannot create or modify treatment folders.',
    });
  }
  return next();
}

function createApp({
  authenticate,
  mysqlPool,
  folderRepository,
  folderPolicyKeys,
  verifyInitialFolderPolicy,
  verifyFolderPolicy,
  queueFolderRotation,
  canReadRotationSources,
  verifyFolderDeletionReauth,
  authEnabled,
  authService,
  userService,
  auditService,
  seedUsers,
  seedDepartments,
  cookieSecure = true,
  sessionTtlMs = 8 * 60 * 60 * 1000,
  reauthTtlMs = 5 * 60 * 1000,
} = {}) {
  const app = express();
  const resolvedCookieSecure = cookieSecure ?? true;

  app.get('/health/live', (_request, response) => {
    response.status(200).json({ status: 'ok' });
  });
  app.get('/demo', (_request, response) => {
    response.type('html').send(`
      <!doctype html>
      <html lang="vi">
        <meta charset="utf-8">
        <title>Kiểm tra backend</title>
        <h1>Kiểm tra backend</h1>
        <button id="check">Kiểm tra</button>
        <pre id="result"></pre>

        <script>
          const result = document.getElementById('result');

          document.getElementById('check').onclick = async () => {
            result.textContent = 'Đang gọi API...';

            try {
              const response = await fetch('/health/live');
              const data = await response.text();
              result.textContent = 'HTTP ' + response.status + '\\n' + data;
            } catch {
              result.textContent = 'Không kết nối được với backend.';
            }
          };
        </script>
      </html>
    `);
  });

  let defaultAuthenticate;
  let defaultRequireCsrf;
  let defaultRequireAdmin;
  let defaultVerifyFolderDeletionReauth;

  if (authEnabled !== false) {
    const auditSvc = auditService ?? createAuditService({
      auditRepository: mysqlPool
        ? createMysqlAuditRepository(mysqlPool)
        : createInMemoryAuditRepository(),
    });

    let authSvc = authService;
    let userSvc = userService;

    if (!authSvc || !userSvc) {
      const userRepo = mysqlPool
        ? createMysqlUserRepository(mysqlPool)
        : createInMemoryUserRepository({ seedUsers, seedDepartments });
      const sessionRepo = mysqlPool
        ? createMysqlSessionRepository(mysqlPool)
        : createInMemorySessionRepository({ userRepository: userRepo });

      if (!mysqlPool && typeof userRepo.setRevokeUserSessionsHook === 'function') {
        userRepo.setRevokeUserSessionsHook((userId, reason) => sessionRepo.revokeUserSessions(userId, reason));
      }

      authSvc = authSvc ?? createAuthService({
        userRepository: userRepo,
        sessionRepository: sessionRepo,
        auditService: auditSvc,
        sessionTtlMs,
        reauthTtlMs,
      });
      userSvc = userSvc ?? createUserService({
        userRepository: userRepo,
        sessionRepository: sessionRepo,
        auditService: auditSvc,
      });
    }

    const authMiddleware = createAuthMiddleware({ authService: authSvc });
    defaultAuthenticate = authMiddleware.authenticate;
    defaultRequireCsrf = authMiddleware.requireCsrf;
    defaultRequireAdmin = authMiddleware.requireAdmin;
    defaultVerifyFolderDeletionReauth = authMiddleware.verifyFolderDeletionReauth;

    app.use('/api/v1/auth', createAuthRouter({
      authService: authSvc,
      authenticate: defaultAuthenticate,
      requireCsrf: defaultRequireCsrf,
      cookieSecure: resolvedCookieSecure,
    }));
    app.use('/api/v1/users', createUsersRouter({
      userService: userSvc,
      authenticate: defaultAuthenticate,
    }));
    app.use('/api/v1/admin/users', createAdminUsersRouter({
      userService: userSvc,
      authenticate: defaultAuthenticate,
      requireAdmin: defaultRequireAdmin,
      requireCsrf: defaultRequireCsrf,
    }));
  }

  const useDefaultAuth = !authenticate && authEnabled !== false;
  const routeAuth = authenticate ?? (useDefaultAuth ? defaultAuthenticate : undefined);
  const folderReauthVerifier = authenticate
    ? verifyFolderDeletionReauth
    : (useDefaultAuth ? defaultVerifyFolderDeletionReauth : verifyFolderDeletionReauth);

  const repository = folderRepository ?? (mysqlPool && createMysqlFolderRepository(mysqlPool));
  const policyVerifiers = typeof folderPolicyKeys?.lookupActiveSigningKey === 'function'
    && typeof folderPolicyKeys?.canReceiveFolderKeys === 'function'
    ? createFolderPolicyVerifiers(folderPolicyKeys)
    : {};
  const folderRouterOptions = {
    folderRepository: repository,
    verifyInitialFolderPolicy: verifyInitialFolderPolicy ?? policyVerifiers.verifyInitialFolderPolicy,
    verifyFolderPolicy: verifyFolderPolicy ?? policyVerifiers.verifyFolderPolicy,
    queueFolderRotation: queueFolderRotation ?? (mysqlPool && !folderRepository ? queueMysqlFolderRotation : undefined),
    verifyFolderDeletionReauth: folderReauthVerifier,
  };
  if (useDefaultAuth) {
    app.use(
      '/api/v1/folders',
      defaultAuthenticate,
      defaultRequireCsrf,
      adminFolderMutationGuard,
      createFolderRouter(folderRouterOptions),
    );
  } else {
    app.use('/api/v1/folders', createFolderRouter({
      authenticate,
      ...folderRouterOptions,
    }));
  }

  const dashboard = express.Router();
  if (routeAuth) dashboard.use(routeAuth);
  if (useDefaultAuth) dashboard.use(defaultRequireCsrf);
  dashboard.get('/summary', async function getDashboardSummary(request, response) {
    if (!request.user?.id) return response.status(401).json({ code: 'UNAUTHENTICATED' });
    if (typeof repository?.getDashboardSummary !== 'function') {
      return response.status(503).json({ code: 'FOLDER_SERVICE_UNAVAILABLE' });
    }
    response.json(await repository.getDashboardSummary(request.user.id));
  });
  app.use('/api/v1/dashboard', dashboard);
  const rotations = express.Router();
  if (routeAuth) rotations.use(routeAuth);
  if (useDefaultAuth) rotations.use(defaultRequireCsrf, adminFolderMutationGuard);
  rotations.use((request, response, next) => {
    response.set('Cache-Control', 'no-store');
    if (!request.user?.id) return response.status(401).json({ code: 'UNAUTHENTICATED' });
    next();
  });
  rotations.get('/', async function listRotations(request, response) {
    const page = request.query.page ?? '1';
    if (typeof page !== 'string' || !/^[1-9][0-9]{0,8}$/.test(page)) {
      return response.status(400).json({ code: 'INVALID_ROTATION_PAGE' });
    }
    if (typeof repository?.listRotationsForUser !== 'function') {
      return response.status(503).json({ code: 'ROTATION_SERVICE_UNAVAILABLE' });
    }
    const { rotations: jobs, nextPage } = await repository.listRotationsForUser(request.user.id, Number(page));
    response.json({
      rotations: typeof canReadRotationSources === 'function' ? jobs : jobs.map((job) => ({ ...job, canClaim: false })),
      nextPage,
    });
  });
  rotations.use('/:rotationId', (request, response, next) => {
    const { rotationId } = request.params;
    if (!/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(rotationId)) {
      return response.status(400).json({ code: 'INVALID_ROTATION_ID' });
    }
    next();
  });
  rotations.get('/:rotationId', async function getRotation(request, response) {
    if (typeof repository?.findRotationForUser !== 'function') {
      return response.status(503).json({ code: 'FOLDER_SERVICE_UNAVAILABLE' });
    }
    const rotation = await repository.findRotationForUser(request.user.id, request.params.rotationId);
    if (!rotation) return response.status(404).json({ code: 'ROTATION_NOT_FOUND' });
    response.json(rotation);
  });
  rotations.post('/:rotationId/claim', async function claimRotation(request, response) {
    if (typeof canReadRotationSources !== 'function' || typeof repository?.claimRotationForUser !== 'function') {
      return response.status(503).json({ code: 'ROTATION_SERVICE_UNAVAILABLE' });
    }
    const result = await repository.claimRotationForUser(request.user.id, request.params.rotationId, canReadRotationSources);
    if (result.code === 'ROTATION_NOT_FOUND') return response.status(404).json(result);
    if (result.code) return response.status(409).json(result);
    response.json(result);
  });
  rotations.post('/:rotationId/lease/renew', express.json(), async function renewRotationLease(request, response) {
    const { generation } = request.body ?? {};
    if (!Number.isInteger(generation) || generation < 1 || generation > 4294967295) {
      return response.status(400).json({ code: 'INVALID_ROTATION_GENERATION' });
    }
    if (typeof canReadRotationSources !== 'function' || typeof repository?.renewRotationLeaseForUser !== 'function') {
      return response.status(503).json({ code: 'ROTATION_SERVICE_UNAVAILABLE' });
    }
    const result = await repository.renewRotationLeaseForUser(
      request.user.id, request.params.rotationId, generation, canReadRotationSources,
    );
    if (result.code === 'ROTATION_NOT_FOUND') return response.status(404).json(result);
    if (result.code) return response.status(409).json(result);
    response.json(result);
  });
  app.use('/api/v1/key-rotations', rotations);

  const operations = express.Router();
  if (routeAuth) operations.use(routeAuth);
  if (useDefaultAuth) operations.use(defaultRequireCsrf);
  operations.get('/:operationId', async function getOperation(request, response) {
    response.set('Cache-Control', 'no-store');
    if (!request.user?.id) return response.status(401).json({ code: 'UNAUTHENTICATED' });
    if (typeof repository?.findDeletionOperationForUser !== 'function') {
      return response.status(503).json({ code: 'FOLDER_SERVICE_UNAVAILABLE' });
    }
    const operation = await repository.findDeletionOperationForUser(request.user.id, request.params.operationId);
    if (!operation) return response.status(404).json({ code: 'OPERATION_NOT_FOUND' });
    response.json(operation);
  });
  app.use('/api/v1/operations', operations);

  app.use((error, _request, response, next) => {
    if (response.headersSent) return next(error);
    if (error?.type === 'entity.parse.failed') {
      return response.status(400).json({ code: 'INVALID_JSON' });
    }
    if (error?.type === 'entity.too.large') {
      return response.status(413).json({ code: 'PAYLOAD_TOO_LARGE' });
    }
    if (Number.isInteger(error?.status) && typeof error?.code === 'string') {
      return response.status(error.status).json({ code: error.code, message: error.message });
    }
    console.error(error);
    response.status(500).json({ code: 'INTERNAL_ERROR' });
  });

  return app;
}

if (require.main === module) {
  const port = process.env.PORT || 3000;
  createApp().listen(port, () => {
    console.log(`Backend running at http://localhost:${port}`);
  });
}

module.exports = { createApp };

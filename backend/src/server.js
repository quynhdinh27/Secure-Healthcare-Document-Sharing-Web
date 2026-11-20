const express = require('express');
const { createFolderRouter } = require('./folders/folder-router');
const { createMysqlFolderRepository } = require('./folders/mysql-folder-repository');
const { createFolderPolicyVerifiers } = require('./folders/folder-policy-signatures');
const { queueMysqlFolderRotation } = require('./folders/mysql-folder-rotation-queue');

function createApp({
  authenticate, mysqlPool, folderRepository, folderPolicyKeys,
  verifyInitialFolderPolicy, verifyFolderPolicy, queueFolderRotation, canReadRotationSources,
  verifyFolderDeletionReauth,
} = {}) {
  const app = express();

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
  const repository = folderRepository ?? (mysqlPool && createMysqlFolderRepository(mysqlPool));
  const policyVerifiers = typeof folderPolicyKeys?.lookupActiveSigningKey === 'function'
    && typeof folderPolicyKeys?.canReceiveFolderKeys === 'function'
    ? createFolderPolicyVerifiers(folderPolicyKeys)
    : {};
  app.use('/api/v1/folders', createFolderRouter({
    authenticate,
    folderRepository: repository,
    verifyInitialFolderPolicy: verifyInitialFolderPolicy ?? policyVerifiers.verifyInitialFolderPolicy,
    verifyFolderPolicy: verifyFolderPolicy ?? policyVerifiers.verifyFolderPolicy,
    queueFolderRotation: queueFolderRotation ?? (mysqlPool && !folderRepository ? queueMysqlFolderRotation : undefined),
    verifyFolderDeletionReauth,
  }));
  const dashboard = express.Router();
  if (authenticate) dashboard.use(authenticate);
  dashboard.get('/summary', async function getDashboardSummary(request, response) {
    if (!request.user?.id) return response.status(401).json({ code: 'UNAUTHENTICATED' });
    if (typeof repository?.getDashboardSummary !== 'function') {
      return response.status(503).json({ code: 'FOLDER_SERVICE_UNAVAILABLE' });
    }
    response.json(await repository.getDashboardSummary(request.user.id));
  });
  app.use('/api/v1/dashboard', dashboard);
  const rotations = express.Router();
  if (authenticate) rotations.use(authenticate);
  rotations.use('/:rotationId', (request, response, next) => {
    response.set('Cache-Control', 'no-store');
    if (!request.user?.id) return response.status(401).json({ code: 'UNAUTHENTICATED' });
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
  if (authenticate) operations.use(authenticate);
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
    if (error.type === 'entity.parse.failed') {
      return response.status(400).json({ code: 'INVALID_JSON' });
    }
    if (error.type === 'entity.too.large') {
      return response.status(413).json({ code: 'PAYLOAD_TOO_LARGE' });
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

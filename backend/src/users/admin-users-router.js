const express = require('express');
const { validationError } = require('../auth/auth-errors');

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function createAdminUsersRouter({
  userService,
  authenticate,
  requireAdmin,
  requireCsrf,
}) {
  const router = express.Router();

  router.use((_request, response, next) => {
    response.set('Cache-Control', 'no-store');
    next();
  });

  if (authenticate) router.use(authenticate);
  if (requireAdmin) router.use(requireAdmin);
  if (requireCsrf) router.use(requireCsrf);

  router.get('/', async function listAdminUsers(request, response) {
    const { query, status, accountType, page, pageSize } = request.query;
    for (const [name, value] of Object.entries({ query, status, accountType, page, pageSize })) {
      if (value !== undefined && typeof value !== 'string') {
        throw validationError(`${name} must be a string.`);
      }
    }
    const result = await userService.listAdminUsers({
      query,
      status,
      accountType,
      page,
      pageSize,
    });
    response.status(200).json(result);
  });

  router.post('/', express.json(), async function createAdminUser(request, response) {
    if (!isPlainObject(request.body)) {
      throw validationError('Request body must be a JSON object.');
    }
    const result = await userService.createAdminUser({
      actorId: request.user.userId ?? request.user.id,
      body: request.body,
      ipAddress: request.ip,
    });
    response.set('Location', `/api/v1/admin/users/${result.user.userId}`);
    response.status(201).json(result);
  });

  router.get('/:userId', async function getAdminUser(request, response) {
    const result = await userService.getAdminUser(request.params.userId);
    response.status(200).json(result);
  });

  router.patch('/:userId', express.json(), async function updateAdminUser(request, response) {
    if (!isPlainObject(request.body)) {
      throw validationError('Request body must be a JSON object.');
    }
    const result = await userService.updateAdminUser({
      actorId: request.user.userId ?? request.user.id,
      userId: request.params.userId,
      body: request.body,
      ipAddress: request.ip,
    });
    response.status(200).json(result);
  });

  router.patch('/:userId/status', express.json(), async function updateAdminUserStatus(request, response) {
    if (!isPlainObject(request.body)) {
      throw validationError('Request body must be a JSON object.');
    }
    const result = await userService.updateAdminUserStatus({
      actorId: request.user.userId ?? request.user.id,
      userId: request.params.userId,
      body: request.body,
      ipAddress: request.ip,
    });
    response.status(200).json(result);
  });

  return router;
}

module.exports = { createAdminUsersRouter };

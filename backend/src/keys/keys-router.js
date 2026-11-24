const express = require('express');

const errorStatus = {
  FORBIDDEN: 403,
  INVALID_PUBLIC_KEY: 400,
  INVALID_KEY_BACKUP: 400,
  INVALID_KEY_PROOF: 400,
  KEY_NOT_FOUND: 404,
  KEY_BACKUP_NOT_FOUND: 404,
  KEY_ALREADY_REGISTERED: 409,
  KEY_ALREADY_ACTIVE: 409,
  KEY_NOT_PENDING: 409,
  KEY_BACKUP_REQUIRED: 409,
};

function sendResult(response, result, status = 200) {
  if (result.error) return response.status(errorStatus[result.error]).json({ code: result.error });
  return response.status(status).json(result);
}

function createKeysRouter({ repository, verifyReauth }) {
  const router = express.Router();
  const json = express.json({ limit: '12kb' });
  router.use((_request, response, next) => {
    response.set('Cache-Control', 'no-store');
    next();
  });

  function requireReauth(request, response, next) {
    if (!verifyReauth(request)) return response.status(403).json({ code: 'REAUTHENTICATION_REQUIRED' });
    return next();
  }

  router.param('keyId', (_request, response, next, keyId) => {
    if (!/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/.test(keyId)) {
      return response.status(400).json({ code: 'INVALID_KEY_ID' });
    }
    return next();
  });

  router.get('/', async (request, response) => {
    response.json(await repository.list(String(request.user.id)));
  });
  router.post('/', requireReauth, json, async (request, response) => {
    const { purpose, publicKey, publicKeyFingerprint } = request.body ?? {};
    return sendResult(response, await repository.register(String(request.user.id), {
      purpose, publicKey, publicKeyFingerprint,
    }), 201);
  });
  router.put('/:keyId/backup', requireReauth, json, async (request, response) => (
    sendResult(response, await repository.saveBackup(String(request.user.id), request.params.keyId, request.body?.backup))
  ));
  router.get('/:keyId/backup', requireReauth, async (request, response) => (
    sendResult(response, await repository.getBackup(String(request.user.id), request.params.keyId))
  ));
  router.post('/:keyId/activate', requireReauth, json, async (request, response) => (
    sendResult(response, await repository.activate(String(request.user.id), request.params.keyId, request.body?.response))
  ));
  return router;
}

module.exports = { createKeysRouter };

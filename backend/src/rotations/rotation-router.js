const { randomUUID } = require('node:crypto');
const express = require('express');
const multer = require('multer');
const { sha256Hex } = require('../documents/document-manifest');

const UUID = /^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const isUUID = (value) => typeof value === 'string' && UUID.test(value);
const statusByCode = {
  FORBIDDEN: 403,
  ROTATION_NOT_FOUND: 404,
  ROTATION_ITEM_NOT_FOUND: 404,
  INVALID_SIGNATURE: 422,
  MANIFEST_MISMATCH: 422,
  CIPHERTEXT_HASH_MISMATCH: 422,
  RECIPIENTS_MISMATCH: 422,
};

function sendResult(response, result, success = 200) {
  return response.status(result.code ? statusByCode[result.code] ?? 409 : success).json(result);
}

function createRotationWorkRouter({ repository, objectStorage, maxUploadBytes = 25 * 1024 * 1024 }) {
  const router = express.Router({ mergeParams: true });
  const parseCiphertext = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: maxUploadBytes, files: 1, fields: 1, parts: 2, fieldSize: 1024 * 1024 },
  }).single('ciphertext');

  function readInput(request, response, next) {
    const { rotationId, itemId } = request.params;
    const { generation } = request.query;
    if (typeof generation !== 'string' || !/^[1-9][0-9]{0,9}$/.test(generation)
        || Number(generation) > 4294967295) {
      return response.status(400).json({ code: 'INVALID_ROTATION_GENERATION' });
    }
    if (itemId !== undefined && !isUUID(itemId)) {
      return response.status(400).json({ code: 'INVALID_ROTATION_ITEM' });
    }
    request.rotationInput = { userId: String(request.user.id), rotationId, itemId, generation: Number(generation) };
    return next();
  }

  function parseMultipart(request, response, next) {
    parseCiphertext(request, response, (error) => {
      if (!error) return next();
      if (error.code === 'LIMIT_FILE_SIZE') return response.status(413).json({ code: 'PAYLOAD_TOO_LARGE' });
      return response.status(400).json({ code: 'INVALID_ROTATION_RESULT' });
    });
  }

  router.get('/items', readInput, async (request, response) => {
    const after = request.query.after ?? '';
    if (after !== '' && !isUUID(after)) return response.status(400).json({ code: 'INVALID_ROTATION_CURSOR' });
    return sendResult(response, await repository.listItems({ ...request.rotationInput, after }));
  });

  function sendEvidence(staged) {
    return async (request, response) => {
      const result = await repository.readItemEvidence(request.rotationInput, staged);
      if (result.code) return sendResult(response, result);
      const { objectKey, ...evidence } = result;
      if (request.query.content !== '1') return response.json(evidence);
      if (request.query.revisionId !== evidence.revisionId) {
        return response.status(409).json({ code: 'REVISION_CHANGED' });
      }
      const ciphertext = await objectStorage.get(objectKey);
      return response.type('application/octet-stream').send(ciphertext);
    };
  }
  router.get('/items/:itemId/source', readInput, sendEvidence(false));
  router.get('/items/:itemId/result', readInput, sendEvidence(true));

  router.put('/items/:itemId/result', readInput, parseMultipart, async (request, response) => {
    let metadata;
    try {
      metadata = JSON.parse(request.body?.metadata);
    } catch {
      return response.status(400).json({ code: 'INVALID_ROTATION_RESULT' });
    }
    const data = request.file?.buffer;
    if (!data || data.length < 16 || !isUUID(metadata?.manifest?.revisionId)
        || !Array.isArray(metadata.envelopes) || metadata.envelopes.length > 1000
        || typeof metadata.signature !== 'string') {
      return response.status(400).json({ code: 'INVALID_ROTATION_RESULT' });
    }
    const { manifest, signature, envelopes } = metadata;
    const ciphertext = { size: data.length, sha256: sha256Hex(data) };
    if (manifest.ciphertextSha256 !== ciphertext.sha256 || manifest.ciphertextSize !== ciphertext.size) {
      return sendResult(response, { code: 'CIPHERTEXT_HASH_MISMATCH' });
    }
    const objectKey = `${manifest.revisionId}/${randomUUID()}`;
    await objectStorage.put(objectKey, data);
    let persisted = false;
    try {
      const result = await repository.stageItem({
        ...request.rotationInput, manifest, signature, envelopes, ciphertext, objectKey,
      });
      persisted = !result.code;
      return sendResult(response, result, 201);
    } finally {
      if (!persisted) {
        await objectStorage.delete(objectKey).catch((error) => {
          console.error(`Could not clean unstaged ciphertext ${objectKey}: ${error.code ?? error.message}`);
        });
      }
    }
  });

  router.post('/commit', readInput, express.json({ limit: '4kb' }), async (request, response) => {
    const { signature } = request.body ?? {};
    if (typeof signature !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(signature)) {
      return response.status(400).json({ code: 'INVALID_ROTATION_COMMIT' });
    }
    return sendResult(response, await repository.commit({ ...request.rotationInput, signature }));
  });
  return router;
}

module.exports = { createRotationWorkRouter };

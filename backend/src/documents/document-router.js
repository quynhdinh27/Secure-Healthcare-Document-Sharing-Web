const { createHash, randomUUID } = require('node:crypto');
const express = require('express');
const multer = require('multer');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CATEGORIES = new Set(['MEDICAL_REPORT', 'LABORATORY_RESULT', 'PRESCRIPTION', 'MEDICAL_IMAGE', 'OTHER']);
const MIME_TYPE = /^[a-z0-9][a-z0-9!#$&^_.+-]{0,62}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,62}$/i;
const GCM_TAG_BYTES = 16;
const DEFAULT_MAX_UPLOAD_BYTES = 25 * 1024 * 1024;
const statusByCode = {
  FORBIDDEN: 403,
  DOCUMENT_NOT_FOUND: 404,
  VERSION_NOT_FOUND: 404,
  FOLDER_NOT_READY: 409,
  CONTEXT_NOT_FOUND: 409,
  CONTEXT_USED: 409,
  CONTEXT_EXPIRED: 409,
  CONTEXT_STALE: 409,
  VERSION_CONFLICT: 409,
  SIGNING_KEY_MISSING: 409,
  RECIPIENT_KEY_MISSING: 409,
  ENVELOPE_NOT_AVAILABLE: 409,
  REVISION_CHANGED: 409,
  INVALID_SIGNATURE: 422,
  MANIFEST_MISMATCH: 422,
  CIPHERTEXT_HASH_MISMATCH: 422,
  RECIPIENTS_MISMATCH: 422,
};

function isUuid(value) {
  return typeof value === 'string' && UUID.test(value);
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function cleanName(value) {
  if (typeof value !== 'string') return null;
  const name = value.trim();
  return name && Array.from(name).length <= 255 ? name : null;
}

function sendResult(response, result, successStatus = 200) {
  if (result.code) {
    const status = statusByCode[result.code];
    if (!status) throw new Error(`Unmapped document result code: ${result.code}`);
    return response.status(status).json(result);
  }
  return response.status(successStatus).json(result);
}

function parseUploadMetadata(raw, purpose) {
  if (typeof raw !== 'string') return null;
  let metadata;
  try {
    metadata = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!isPlainObject(metadata) || !isUuid(metadata.contextId) || !isPlainObject(metadata.manifest)
      || typeof metadata.signature !== 'string' || !Array.isArray(metadata.envelopes)
      || metadata.envelopes.length > 1000 || typeof metadata.mimeType !== 'string'
      || metadata.mimeType.length > 127 || !MIME_TYPE.test(metadata.mimeType)) {
    return null;
  }
  const upload = {
    contextId: metadata.contextId,
    manifest: metadata.manifest,
    signature: metadata.signature,
    envelopes: metadata.envelopes,
    mimeType: metadata.mimeType.toLowerCase(),
  };
  if (purpose === 'NEW_VERSION') return upload;
  const documentName = cleanName(metadata.documentName);
  if (!documentName || !CATEGORIES.has(metadata.category)) return null;
  return { ...upload, documentName, category: metadata.category };
}

function createDocumentRouter({
  authenticate, documentRepository, objectStorage, maxUploadBytes = DEFAULT_MAX_UPLOAD_BYTES,
} = {}) {
  const router = express.Router();

  // Guards run per route, so requests for other /api/v1 modules pass through untouched.
  function requireService(request, response, next) {
    response.set('Cache-Control', 'no-store');
    if (!request.user?.id) return response.status(401).json({ code: 'UNAUTHENTICATED' });
    if (!documentRepository || !objectStorage) {
      return response.status(503).json({ code: 'DOCUMENT_SERVICE_UNAVAILABLE' });
    }
    next();
  }
  const guard = authenticate ? [authenticate, requireService] : [requireService];
  const checkFolderId = (request, response, next) => (
    isUuid(request.params.folderId) ? next() : response.status(403).json({ code: 'FORBIDDEN' }));
  const checkDocumentId = (request, response, next) => (
    isUuid(request.params.documentId) ? next() : response.status(400).json({ code: 'INVALID_DOCUMENT_ID' }));
  const checkVersionId = (request, response, next) => (
    isUuid(request.params.versionId) ? next() : response.status(400).json({ code: 'INVALID_VERSION_ID' }));
  const smallJson = express.json({ limit: '16kb' });

  const parseCiphertext = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: maxUploadBytes, files: 1, fields: 1, parts: 2, fieldSize: 1024 * 1024 },
  }).single('ciphertext');
  function parseMultipart(request, response, next) {
    parseCiphertext(request, response, (error) => {
      if (!error) return next();
      if (error.code === 'LIMIT_FILE_SIZE') return response.status(413).json({ code: 'PAYLOAD_TOO_LARGE' });
      return response.status(400).json({ code: 'INVALID_DOCUMENT_INPUT' });
    });
  }

  async function discardObject(objectKey) {
    try {
      await objectStorage.delete(objectKey);
    } catch (error) {
      console.error(`Could not delete unpublished object ${objectKey}: ${error.code ?? error.message}`);
    }
  }

  function publish(purpose) {
    return async (request, response) => {
      const upload = parseUploadMetadata(request.body?.metadata, purpose);
      const ciphertext = request.file?.buffer;
      if (!upload || !ciphertext || ciphertext.length < GCM_TAG_BYTES) {
        return response.status(400).json({ code: 'INVALID_DOCUMENT_INPUT' });
      }
      const ciphertextSha256 = createHash('sha256').update(ciphertext).digest('hex');
      if (upload.manifest.ciphertextSha256 !== ciphertextSha256 || upload.manifest.ciphertextSize !== ciphertext.length) {
        return response.status(422).json({ code: 'CIPHERTEXT_HASH_MISMATCH' });
      }
      if (!isUuid(upload.manifest.revisionId)) return response.status(422).json({ code: 'MANIFEST_MISMATCH' });
      // A fresh suffix per request: a repeated or concurrent submission never
      // overwrites or deletes another request's object.
      const objectKey = `${upload.manifest.revisionId}/${randomUUID()}`;
      await objectStorage.put(objectKey, ciphertext);
      const scope = purpose === 'NEW_DOCUMENT'
        ? { folderId: request.params.folderId }
        : { documentId: request.params.documentId };
      let result;
      try {
        result = await documentRepository.publishUpload({
          ...upload, ...scope, purpose, userId: request.user.id,
          objectKey, ciphertextSize: ciphertext.length, ciphertextSha256,
        });
      } catch (error) {
        await discardObject(objectKey);
        throw error;
      }
      if (result.code) {
        await discardObject(objectKey);
        return sendResult(response, result);
      }
      response.location('/api/v1/documents/' + result.documentId);
      return sendResult(response, result, 201);
    };
  }
  const uploadDocument = publish('NEW_DOCUMENT');
  const createDocumentVersion = publish('NEW_VERSION');

  router.get('/folders/:folderId/documents', guard, checkFolderId, async function listFolderDocuments(request, response) {
    const { query = '', category, page = '1' } = request.query;
    if (typeof page !== 'string' || !/^[1-9][0-9]{0,8}$/.test(page)) {
      return response.status(400).json({ code: 'INVALID_DOCUMENT_PAGE' });
    }
    if (typeof query !== 'string' || Array.from(query).length > 100
        || (category !== undefined && !CATEGORIES.has(category))) {
      return response.status(400).json({ code: 'INVALID_DOCUMENT_INPUT' });
    }
    const result = await documentRepository.listDocumentsForUser(request.user.id, request.params.folderId, {
      query: query.trim(), category, page: Number(page),
    });
    return sendResult(response, result);
  });

  router.post('/folders/:folderId/upload-contexts', guard, checkFolderId, smallJson, async function createUploadContext(request, response) {
    const body = request.body;
    const keys = isPlainObject(body) ? Object.keys(body) : [];
    const valid = isPlainObject(body) && (
      (body.purpose === 'NEW_DOCUMENT' && keys.length === 1)
      || (body.purpose === 'NEW_VERSION' && keys.length === 3 && isUuid(body.documentId) && isUuid(body.baseVersionId)));
    if (!valid) return response.status(400).json({ code: 'INVALID_UPLOAD_CONTEXT_INPUT' });
    const contextRequest = body.purpose === 'NEW_DOCUMENT'
      ? { purpose: 'NEW_DOCUMENT' }
      : { purpose: 'NEW_VERSION', documentId: body.documentId, baseVersionId: body.baseVersionId };
    const result = await documentRepository.createUploadContext(request.user.id, request.params.folderId, contextRequest);
    return sendResult(response, result, 201);
  });

  router.post('/folders/:folderId/documents', guard, checkFolderId, parseMultipart, uploadDocument);

  router.get('/documents/:documentId', guard, checkDocumentId, async function getDocument(request, response) {
    const document = await documentRepository.findDocumentForUser(request.user.id, request.params.documentId);
    if (!document) return response.status(404).json({ code: 'DOCUMENT_NOT_FOUND' });
    return response.json(document);
  });

  router.patch('/documents/:documentId', guard, checkDocumentId, smallJson, async function updateDocumentMetadata(request, response) {
    const body = request.body;
    const keys = isPlainObject(body) ? Object.keys(body) : [];
    const changes = {};
    let valid = keys.length > 0 && keys.every((key) => key === 'documentName' || key === 'category');
    if (valid && Object.hasOwn(body, 'documentName')) {
      changes.documentName = cleanName(body.documentName);
      valid = Boolean(changes.documentName);
    }
    if (valid && Object.hasOwn(body, 'category')) {
      changes.category = body.category;
      valid = CATEGORIES.has(body.category);
    }
    if (!valid) return response.status(400).json({ code: 'INVALID_DOCUMENT_INPUT' });
    const result = await documentRepository.updateDocumentMetadata(request.user.id, request.params.documentId, changes);
    return sendResult(response, result);
  });

  router.delete('/documents/:documentId', guard, checkDocumentId, async function deleteDocument(request, response) {
    const result = await documentRepository.deleteDocument(request.user.id, request.params.documentId);
    if (result.code) return sendResult(response, result);
    // Rows are gone; ciphertext objects are removed after the commit (best effort).
    for (const objectKey of result.objectKeys) await discardObject(objectKey);
    return response.status(204).end();
  });

  router.get('/documents/:documentId/versions', guard, checkDocumentId, async function listDocumentVersions(request, response) {
    const result = await documentRepository.listVersionsForUser(request.user.id, request.params.documentId);
    if (!result) return response.status(404).json({ code: 'DOCUMENT_NOT_FOUND' });
    return response.json(result);
  });

  router.post('/documents/:documentId/versions', guard, checkDocumentId, parseMultipart, createDocumentVersion);

  router.get('/versions/:versionId/manifest', guard, checkVersionId, async function getVersionManifest(request, response) {
    const result = await documentRepository.getVersionManifestForUser(request.user.id, request.params.versionId);
    return sendResult(response, result);
  });

  router.get('/versions/:versionId/content', guard, checkVersionId, async function downloadVersionCiphertext(request, response) {
    const { revisionId } = request.query;
    if (revisionId !== undefined && !isUuid(revisionId)) {
      return response.status(400).json({ code: 'INVALID_DOCUMENT_INPUT' });
    }
    const result = await documentRepository.getVersionContentForUser(request.user.id, request.params.versionId, revisionId);
    if (result.code) return sendResult(response, result);
    const ciphertext = await objectStorage.get(result.objectKey);
    response.set({ 'Content-Type': 'application/octet-stream', 'X-Crypto-Revision-Id': result.revisionId });
    return response.send(ciphertext);
  });

  return router;
}

module.exports = { createDocumentRouter };

const express = require('express');

const rolesByAction = {
  read: new Set(['OWNER', 'EDITOR', 'VIEWER']),
  renameFolder: new Set(['OWNER', 'EDITOR']),
  upload: new Set(['OWNER', 'EDITOR']),
  updateDocument: new Set(['OWNER', 'EDITOR']),
  deleteDocument: new Set(['OWNER']),
  deleteFolder: new Set(['OWNER']),
  manageMembers: new Set(['OWNER']),
};

function hasFolderPermission(membership, action) {
  return membership?.status === 'ACTIVE'
    && Object.hasOwn(rolesByAction, action)
    && rolesByAction[action].has(membership.role);
}

function createFolderRouter({
  authenticate, folderRepository, verifyInitialFolderPolicy, verifyFolderPolicy, queueFolderRotation,
} = {}) {
  const router = express.Router();

  if (authenticate) router.use(authenticate);
  router.use((request, response, next) => {
    if (!request.user?.id) return response.status(401).json({ code: 'UNAUTHENTICATED' });
    if (!folderRepository) return response.status(503).json({ code: 'FOLDER_SERVICE_UNAVAILABLE' });
    next();
  });

  router.get('/', async function listFolders(request, response) {
    const entries = await folderRepository.listForUser(request.user.id);
    const folders = entries
      .filter(({ membership }) => hasFolderPermission(membership, 'read'))
      .map(({ folder, membership }) => ({ ...folder, role: membership.role }));
    response.json({ folders });
  });

  router.post('/', express.json(), async function createFolder(request, response) {
    const { folderId, name, patientRef, treatmentReference, signedPolicy } = request.body ?? {};
    const metadata = [name, patientRef, treatmentReference];
    if (typeof folderId !== 'string'
        || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(folderId)
        || !metadata.every((value) => typeof value === 'string' && value.trim() && value.trim().length <= 255)
        || !signedPolicy || typeof signedPolicy !== 'object' || Array.isArray(signedPolicy)) {
      return response.status(400).json({ code: 'INVALID_FOLDER_INPUT' });
    }
    if (typeof verifyInitialFolderPolicy !== 'function' || typeof folderRepository.createForOwner !== 'function') {
      return response.status(503).json({ code: 'FOLDER_SERVICE_UNAVAILABLE' });
    }

    const result = await folderRepository.createForOwner({
      folder: { folderId, name: name.trim(), patientRef: patientRef.trim(), treatmentReference: treatmentReference.trim() },
      ownerId: request.user.id,
      signedPolicy,
      verifyInitialFolderPolicy,
    });
    if (result.code === 'INVALID_SIGNATURE') return response.status(422).json(result);
    if (result.code === 'FOLDER_ALREADY_EXISTS') return response.status(409).json(result);
    response.status(201).location('/api/v1/folders/' + folderId).json(result.folder);
  });

  router.get('/:folderId', async function getFolder(request, response) {
    const entry = await folderRepository.findForUser(request.user.id, request.params.folderId);
    if (!hasFolderPermission(entry?.membership, 'read')) {
      return response.status(403).json({ code: 'FORBIDDEN' });
    }
    response.json({ ...entry.folder, role: entry.membership.role });
  });

  router.get('/:folderId/members', async function listFolderMembers(request, response) {
    if (typeof folderRepository.listMembersForUser !== 'function') {
      return response.status(503).json({ code: 'FOLDER_SERVICE_UNAVAILABLE' });
    }
    const members = await folderRepository.listMembersForUser(request.user.id, request.params.folderId);
    if (!members) return response.status(403).json({ code: 'FORBIDDEN' });
    response.json({ members });
  });

  router.post('/:folderId/policy-contexts', express.json(), async function createPolicyContext(request, response) {
    const { action, userId, membershipId, role } = request.body ?? {};
    const idPattern = /^[1-9][0-9]{0,19}$/;
    const validId = (id) => typeof id === 'string' && idPattern.test(id) && BigInt(id) <= 18446744073709551615n;
    const validRole = role === 'EDITOR' || role === 'VIEWER';
    const target = action === 'ADD_MEMBER' && validId(userId) && validRole
      ? { userId, role }
      : action === 'CHANGE_ROLE' && validId(membershipId) && validRole
        ? { membershipId, role }
        : action === 'REVOKE_MEMBER' && validId(membershipId)
          ? { membershipId }
          : null;
    if (!target) return response.status(400).json({ code: 'INVALID_POLICY_CONTEXT_INPUT' });
    if (typeof folderRepository.createPolicyContext !== 'function') {
      return response.status(503).json({ code: 'FOLDER_SERVICE_UNAVAILABLE' });
    }

    const result = await folderRepository.createPolicyContext(request.user.id, request.params.folderId, action, target);
    if (result.code === 'FORBIDDEN') return response.status(403).json(result);
    if (result.code) return response.status(409).json(result);
    response.status(201).json(result);
  });

  router.patch('/:folderId', express.json(), async function updateFolder(request, response) {
    const body = request.body ?? {};
    const fields = Object.keys(body);
    const { name, description } = body;
    if (!fields.length || fields.some((field) => field !== 'name' && field !== 'description')) {
      return response.status(400).json({ code: 'INVALID_FOLDER_NAME' });
    }
    if (Object.hasOwn(body, 'name') && (typeof name !== 'string' || !name.trim() || Array.from(name.trim()).length > 255)) {
      return response.status(400).json({ code: 'INVALID_FOLDER_NAME' });
    }
    const editsDescription = Object.hasOwn(body, 'description');
    if (editsDescription && description !== null
        && (typeof description !== 'string' || Array.from(description.trim()).length > 1000)) {
      return response.status(400).json({ code: 'INVALID_FOLDER_DESCRIPTION' });
    }

    const userId = request.user.id;
    const { folderId } = request.params;
    const entry = await folderRepository.findForUser(userId, folderId);
    if (!hasFolderPermission(entry?.membership, 'renameFolder')) {
      return response.status(403).json({ code: 'FORBIDDEN' });
    }
    const method = editsDescription ? 'updateForUser' : 'renameForUser';
    if (typeof folderRepository[method] !== 'function') {
      return response.status(503).json({ code: 'FOLDER_SERVICE_UNAVAILABLE' });
    }

    // The repository must check active membership and role in the same operation as the write.
    const change = editsDescription
      ? { name: name?.trim(), description: description?.trim() || null }
      : name.trim();
    const updated = await folderRepository[method](userId, folderId, change, [...rolesByAction.renameFolder]);
    if (!updated) {
      return response.status(403).json({ code: 'FORBIDDEN' });
    }
    response.json({ ...updated.folder, role: updated.membership.role });
  });

  function applyMemberChange(action) {
    return async (request, response) => {
      const isRevoke = action === 'REVOKE_MEMBER';
      const policyContextId = isRevoke ? request.get('X-Policy-Context-Id') : request.body?.policyContextId;
      const ownerSignature = isRevoke ? request.get('X-Policy-Signature') : request.body?.ownerSignature;
      if (typeof policyContextId !== 'string' || !/^[a-f0-9-]{36}$/.test(policyContextId)
          || typeof ownerSignature !== 'string' || !ownerSignature.trim()) {
        return response.status(400).json({ code: 'INVALID_POLICY_MUTATION_INPUT' });
      }
      if (typeof folderRepository.applyMemberChange !== 'function'
          || typeof verifyFolderPolicy !== 'function' || typeof queueFolderRotation !== 'function') {
        return response.status(503).json({ code: 'FOLDER_SERVICE_UNAVAILABLE' });
      }
      const result = await folderRepository.applyMemberChange({
        ownerId: request.user.id, folderId: request.params.folderId,
        membershipId: request.params.membershipId, action, policyContextId, ownerSignature,
        verifyFolderPolicy, queueFolderRotation,
      });
      if (result.code === 'FORBIDDEN') return response.status(403).json(result);
      if (result.code === 'INVALID_SIGNATURE') return response.status(422).json(result);
      if (result.code) return response.status(409).json(result);
      response.status(202).json(result);
    };
  }

  router.post('/:folderId/members', express.json(), applyMemberChange('ADD_MEMBER'));
  router.patch('/:folderId/members/:membershipId', express.json(), applyMemberChange('CHANGE_ROLE'));
  router.delete('/:folderId/members/:membershipId', applyMemberChange('REVOKE_MEMBER'));

  return router;
}

module.exports = { createFolderRouter, hasFolderPermission };

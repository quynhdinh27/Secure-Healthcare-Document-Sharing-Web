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

function createFolderRouter({ authenticate, folderRepository } = {}) {
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

  router.get('/:folderId', async function getFolder(request, response) {
    const entry = await folderRepository.findForUser(request.user.id, request.params.folderId);
    if (!hasFolderPermission(entry?.membership, 'read')) {
      return response.status(403).json({ code: 'FORBIDDEN' });
    }
    response.json({ ...entry.folder, role: entry.membership.role });
  });

  router.patch('/:folderId', express.json(), async function updateFolder(request, response) {
    const { name } = request.body ?? {};
    if (typeof name !== 'string' || !name.trim() || Object.keys(request.body).length !== 1) {
      return response.status(400).json({ code: 'INVALID_FOLDER_NAME' });
    }

    const userId = request.user.id;
    const { folderId } = request.params;
    const entry = await folderRepository.findForUser(userId, folderId);
    if (!hasFolderPermission(entry?.membership, 'renameFolder')) {
      return response.status(403).json({ code: 'FORBIDDEN' });
    }
    if (typeof folderRepository.renameForUser !== 'function') {
      return response.status(503).json({ code: 'FOLDER_SERVICE_UNAVAILABLE' });
    }

    // The repository must check active membership and role in the same operation as the write.
    const updated = await folderRepository.renameForUser(
      userId, folderId, name.trim(), [...rolesByAction.renameFolder],
    );
    if (!updated) {
      return response.status(403).json({ code: 'FORBIDDEN' });
    }
    response.json({ ...updated.folder, role: updated.membership.role });
  });

  return router;
}

module.exports = { createFolderRouter, hasFolderPermission };

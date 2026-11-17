const express = require('express');

const rolesByAction = {
  read: new Set(['OWNER', 'EDITOR', 'VIEWER']),
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

  return router;
}

module.exports = { createFolderRouter, hasFolderPermission };

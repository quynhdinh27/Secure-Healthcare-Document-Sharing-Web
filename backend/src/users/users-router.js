const express = require('express');
const { validationError } = require('../auth/auth-errors');

function createUsersRouter({ userService, authenticate }) {
  const router = express.Router();

  router.use((_request, response, next) => {
    response.set('Cache-Control', 'no-store');
    next();
  });

  if (authenticate) {
    router.use(authenticate);
  }

  router.get('/', async function searchStaff(request, response) {
    const { query, limit } = request.query;
    if (query !== undefined && typeof query !== 'string') {
      throw validationError('query must be a string.');
    }
    if (limit !== undefined && typeof limit !== 'string') {
      throw validationError('limit must be a string.');
    }
    const result = await userService.searchStaff({ query, limit });
    response.status(200).json(result);
  });

  return router;
}

module.exports = { createUsersRouter };

const express = require('express');
const {
  SESSION_COOKIE_NAME,
  parseCookies,
  serializeSessionCookie,
  serializeClearSessionCookie,
  serializeCsrfCookie,
} = require('./cookies');
const { MAX_LOGIN_PASSWORD_LENGTH } = require('./password');
const { validationError } = require('./auth-errors');

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function createAuthRouter({
  authService,
  authenticate,
  requireCsrf,
  cookieSecure = true,
}) {
  const router = express.Router();
  const maxAgeSeconds = Math.floor((authService.sessionTtlMs ?? 8 * 60 * 60 * 1000) / 1000);

  router.use((_request, response, next) => {
    response.set('Cache-Control', 'no-store');
    next();
  });

  router.get('/csrf', async function getCsrfToken(request, response) {
    const cookies = parseCookies(request.get('cookie'));
    const sessionToken = cookies[SESSION_COOKIE_NAME] ?? null;
    const { csrfToken } = await authService.issueCsrfToken({ sessionToken });
    response.append('Set-Cookie', serializeCsrfCookie(csrfToken, { maxAgeSeconds, cookieSecure }));
    response.status(200).json({ csrfToken });
  });

  router.post('/login', requireCsrf, express.json(), async function login(request, response) {
    if (!isPlainObject(request.body)) {
      throw validationError('Request body must be a JSON object.');
    }
    const { email, password } = request.body;
    if (
      typeof email !== 'string'
      || email.trim().length === 0
      || email.trim().length > 255
      || typeof password !== 'string'
      || password.length === 0
      || password.length > MAX_LOGIN_PASSWORD_LENGTH
    ) {
      throw validationError('Valid email and password are required.');
    }

    const csrfToken = request.get('x-csrf-token');
    const result = await authService.login({
      email,
      password,
      csrfToken,
      ipAddress: request.ip,
      userAgent: request.get('user-agent'),
    });

    response.append('Set-Cookie', serializeSessionCookie(result.sessionToken, { maxAgeSeconds, cookieSecure }));
    response.append('Set-Cookie', serializeCsrfCookie(result.csrfToken, { maxAgeSeconds, cookieSecure }));
    response.status(200).json({
      user: result.user,
      csrfToken: result.csrfToken,
    });
  });

  router.get('/me', authenticate, async function getCurrentUser(request, response) {
    const result = await authService.getCurrentUser(request.user.userId);
    response.status(200).json(result);
  });

  router.post('/logout', requireCsrf, async function logout(request, response) {
    const cookies = parseCookies(request.get('cookie'));
    const sessionToken = cookies[SESSION_COOKIE_NAME] ?? null;
    const result = await authService.logout({
      sessionToken,
      ipAddress: request.ip,
    });
    response.append('Set-Cookie', serializeClearSessionCookie({ cookieSecure }));
    response.status(200).json(result);
  });

  router.post('/reauthenticate', authenticate, requireCsrf, express.json(), async function reauthenticate(request, response) {
    if (!isPlainObject(request.body)) {
      throw validationError('Request body must be a JSON object.');
    }
    const { password } = request.body;
    if (
      typeof password !== 'string'
      || password.length === 0
      || password.length > MAX_LOGIN_PASSWORD_LENGTH
    ) {
      throw validationError('Password is required.');
    }

    const result = await authService.reauthenticate({
      userId: request.user.userId,
      sessionId: request.user.sessionId,
      password,
      ipAddress: request.ip,
    });
    response.status(200).json(result);
  });

  return router;
}

module.exports = { createAuthRouter };

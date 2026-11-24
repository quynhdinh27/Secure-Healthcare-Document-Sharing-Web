const { createHash, timingSafeEqual } = require('node:crypto');
const {
  SESSION_COOKIE_NAME,
  CSRF_COOKIE_NAME,
  parseCookies,
} = require('./cookies');
const { csrfInvalid, forbidden, unauthenticated } = require('./auth-errors');

const AUTH_SESSION_SYMBOL = Symbol('medshareAuthSession');
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function sha256Buffer(value) {
  return createHash('sha256').update(value, 'utf8').digest();
}

function sha256Hex(value) {
  return sha256Buffer(value).toString('hex');
}

function timingSafeEqualNonEmptyStrings(a, b) {
  if (typeof a !== 'string' || a.length === 0 || typeof b !== 'string' || b.length === 0) {
    return false;
  }
  const digestA = sha256Buffer(a);
  const digestB = sha256Buffer(b);
  return timingSafeEqual(digestA, digestB);
}

function timingSafeEqualHex(hexA, hexB) {
  if (typeof hexA !== 'string' || hexA.length === 0 || typeof hexB !== 'string' || hexB.length === 0) {
    return false;
  }
  const bufA = Buffer.from(hexA, 'utf8');
  const bufB = Buffer.from(hexB, 'utf8');
  if (bufA.length !== bufB.length) {
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}

function createAuthMiddleware({ authService }) {
  async function authenticate(request, _response, next) {
    const cookies = parseCookies(request.get('cookie'));
    const sessionToken = cookies[SESSION_COOKIE_NAME];
    const verified = await authService.verifySession(sessionToken);
    if (!verified) {
      return next(unauthenticated());
    }
    request.user = verified.user;
    request[AUTH_SESSION_SYMBOL] = {
      csrfTokenHash: verified.session.csrfTokenHash,
      safeUser: verified.safeUser,
    };
    return next();
  }

  function requireCsrf(request, _response, next) {
    if (SAFE_METHODS.has(request.method)) {
      return next();
    }
    const cookies = parseCookies(request.get('cookie'));
    const cookieToken = cookies[CSRF_COOKIE_NAME];
    const headerToken = request.get('x-csrf-token');
    if (!timingSafeEqualNonEmptyStrings(cookieToken, headerToken)) {
      return next(csrfInvalid());
    }

    const sessionMeta = request[AUTH_SESSION_SYMBOL];
    if (sessionMeta?.csrfTokenHash) {
      const headerHash = sha256Hex(headerToken);
      if (!timingSafeEqualHex(headerHash, sessionMeta.csrfTokenHash)) {
        return next(csrfInvalid());
      }
    }
    return next();
  }

  function requireAdmin(request, _response, next) {
    if (request.user?.accountType !== 'ADMIN' || request.user?.accountStatus !== 'ACTIVE') {
      return next(forbidden('Hospital Administrator role is required.'));
    }
    return next();
  }

  function verifyFolderDeletionReauth(request) {
    return authService.verifyFolderDeletionReauth(request);
  }

  return {
    authenticate,
    requireCsrf,
    requireAdmin,
    verifyFolderDeletionReauth,
  };
}

module.exports = {
  AUTH_SESSION_SYMBOL,
  createAuthMiddleware,
  timingSafeEqualNonEmptyStrings,
  timingSafeEqualHex,
};

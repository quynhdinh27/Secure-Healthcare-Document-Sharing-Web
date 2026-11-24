const SESSION_COOKIE_NAME = 'medshare_sid';
const CSRF_COOKIE_NAME = 'medshare_csrf';

function parseCookies(header) {
  const cookies = Object.create(null);
  if (typeof header !== 'string' || header.length === 0) {
    return cookies;
  }
  const parts = header.split(';');
  for (const part of parts) {
    const eqIndex = part.indexOf('=');
    if (eqIndex <= 0) continue;
    const name = part.slice(0, eqIndex).trim();
    if (!name || name === '__proto__' || name === 'constructor' || name === 'prototype') continue;
    if (Object.prototype.hasOwnProperty.call(cookies, name)) continue;
    const rawValue = part.slice(eqIndex + 1).trim();
    try {
      cookies[name] = decodeURIComponent(rawValue);
    } catch {
      cookies[name] = rawValue;
    }
  }
  return cookies;
}

function serializeSessionCookie(token, { maxAgeSeconds, cookieSecure = true } = {}) {
  const maxAge = Math.max(0, Math.floor(Number(maxAgeSeconds) || 0));
  const secureFlag = cookieSecure === true ? '; Secure' : '';
  return `${SESSION_COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secureFlag}`;
}

function serializeClearSessionCookie({ cookieSecure = true } = {}) {
  const secureFlag = cookieSecure === true ? '; Secure' : '';
  return `${SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secureFlag}`;
}

function serializeCsrfCookie(token, { maxAgeSeconds, cookieSecure = true } = {}) {
  const maxAge = Math.max(0, Math.floor(Number(maxAgeSeconds) || 0));
  const secureFlag = cookieSecure === true ? '; Secure' : '';
  return `${CSRF_COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; SameSite=Lax; Max-Age=${maxAge}${secureFlag}`;
}

module.exports = {
  SESSION_COOKIE_NAME,
  CSRF_COOKIE_NAME,
  parseCookies,
  serializeSessionCookie,
  serializeClearSessionCookie,
  serializeCsrfCookie,
};

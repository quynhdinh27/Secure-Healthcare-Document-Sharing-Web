import { ApiError } from './errors';

export const USE_MOCK = import.meta.env.VITE_USE_MOCK === 'true';
const BASE = import.meta.env.VITE_API_BASE || '/api/v1';
// CONTRACT: tên header CSRF cần chốt với nhóm Auth
const CSRF_HEADER = import.meta.env.VITE_CSRF_HEADER || 'X-CSRF-Token';

let csrfToken = null;
let onUnauthorized = () => {};
export const setUnauthorizedHandler = (fn) => { onUnauthorized = fn; };

async function loadCsrf(force = false) {
  if (csrfToken && !force) return csrfToken;
  const res = await fetch(`${BASE}/auth/csrf`, { credentials: 'include' });
  const body = await res.json().catch(() => ({}));
  csrfToken = body.csrfToken ?? body.token ?? null; // CONTRACT: tên field token
  return csrfToken;
}

/**
 * request(method, path, { query, body, raw })
 *  - body: object (JSON) hoặc FormData (multipart)
 *  - raw: 'blob' | 'response' để lấy dữ liệu nhị phân / multipart
 */
export async function request(method, path, { query, body, raw, headers } = {}) {
  if (USE_MOCK) {
    const { mockHandle } = await import('./mock.js');
    return mockHandle(method, path, { query, body, headers });
  }
  return doFetch(method, path, { query, body, raw, headers }, true);
}

async function doFetch(method, path, { query, body, raw, headers: extra }, canRetry) {
  const qs = query ? '?' + new URLSearchParams(Object.entries(query).filter(([, v]) => v != null && v !== '')) : '';
  const headers = { ...extra };
  const init = { method, credentials: 'include', headers };
  if (method !== 'GET' && method !== 'HEAD') {
    const token = await loadCsrf();
    if (token) headers[CSRF_HEADER] = token;
  }
  if (body instanceof FormData) init.body = body;
  else if (body !== undefined) { headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(body); }

  const res = await fetch(`${BASE}${path}${qs}`, init);
  if (res.ok) {
    if (raw === 'response') return res;
    if (raw === 'blob') return res.blob();
    if (res.status === 204) return null;
    return (res.headers.get('content-type') || '').includes('json') ? res.json() : res.text();
  }
  const err = new ApiError(res.status, await res.json().catch(() => ({})));
  if (res.status === 403 && /csrf/i.test(err.code || err.message) && canRetry) {
    await loadCsrf(true);
    return doFetch(method, path, { query, body, raw, headers: extra }, false);
  }
  if (res.status === 401 && !path.startsWith('/auth/login')) onUnauthorized();
  throw err;
}

/** Health nằm ở root, không có prefix /api/v1 */
export async function rootGet(path) {
  if (USE_MOCK) return { status: 'ok' };
  const res = await fetch(path, { credentials: 'include' });
  if (!res.ok) throw new ApiError(res.status, await res.json().catch(() => ({})));
  return res.json();
}

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  parseCookies,
  serializeSessionCookie,
  serializeClearSessionCookie,
  serializeCsrfCookie,
} = require('../src/auth/cookies');

test('parseCookies handles values containing =, malformed percent encoding, duplicates, and prototype keys', () => {
  assert.deepEqual({ ...parseCookies(undefined) }, {});
  assert.deepEqual({ ...parseCookies('') }, {});

  const parsed = parseCookies(
    'a=1=2; bad=%E0%A4%A; medshare_sid=firstToken; medshare_sid=smuggled; __proto__=evil; constructor=evil; medshare_csrf=csrf%2Bval',
  );
  assert.equal(Object.getPrototypeOf(parsed), null);
  assert.equal(parsed.a, '1=2');
  assert.equal(parsed.bad, '%E0%A4%A');
  assert.equal(parsed.medshare_sid, 'firstToken');
  assert.equal(parsed.medshare_csrf, 'csrf+val');
  assert.equal(parsed.__proto__, undefined);
  assert.equal(parsed.constructor, undefined);
});

test('Set-Cookie serializers apply Secure by default and omit Secure when cookieSecure=false', () => {
  const sidSecure = serializeSessionCookie('tok123', { maxAgeSeconds: 3600 });
  assert.equal(sidSecure, 'medshare_sid=tok123; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600; Secure');

  const sidInsecure = serializeSessionCookie('tok123', { maxAgeSeconds: 3600, cookieSecure: false });
  assert.equal(sidInsecure, 'medshare_sid=tok123; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600');

  const csrfSecure = serializeCsrfCookie('csrf123', { maxAgeSeconds: 3600, cookieSecure: true });
  assert.equal(csrfSecure, 'medshare_csrf=csrf123; Path=/; SameSite=Lax; Max-Age=3600; Secure');
  assert.equal(csrfSecure.includes('HttpOnly'), false);

  const clearSecure = serializeClearSessionCookie({ cookieSecure: true });
  assert.equal(clearSecure, 'medshare_sid=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Secure');

  const clearInsecure = serializeClearSessionCookie({ cookieSecure: false });
  assert.equal(clearInsecure, 'medshare_sid=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
});

const assert = require('node:assert/strict');
const { test } = require('node:test');
const { devHeaderAuth } = require('../src/auth/dev-header-auth');

function authenticate(value) {
  const request = { get: (name) => (name === 'x-dev-user-id' ? value : undefined) };
  let nextCalls = 0;
  devHeaderAuth(request, {}, () => { nextCalls += 1; });
  assert.equal(nextCalls, 1);
  return request.user;
}

test('dev header auth accepts only a positive decimal user id', () => {
  assert.deepEqual(authenticate('12'), { id: '12' });
  for (const value of [undefined, '', '0', '01', 'abc', '-1', '12 ', '1'.repeat(21)]) {
    assert.equal(authenticate(value), undefined, String(value));
  }
});

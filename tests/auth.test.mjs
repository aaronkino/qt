import test from 'node:test';
import assert from 'node:assert/strict';
import worker from '../cloud-sync/src/index.js';

const token = 'test-unregistered-token-0123456789';
function environment(session) {
  const calls = [];
  return {
    ALLOWED_ORIGINS: 'https://aaronkino.github.io',
    calls,
    DB: { prepare(sql) {
      const statement = { bind(...args) { calls.push({ sql, args }); return statement; }, async first() { return session; }, async all() { return { results: [] }; } };
      return statement;
    } }
  };
}
for (const name of ['unknown token', 'expired or revoked Google session']) {
  test(`${name} cannot access API`, async () => {
    const env = environment(null);
    const response = await worker.fetch(new Request('https://api.test/api/auth/me', { headers: { Authorization: `Bearer ${token}` } }), env);
    assert.equal(response.status, 401);
    assert.match(env.calls[0].sql, /expires_at > \?2/);
    assert.ok(env.calls.every(call => !/INSERT|UPDATE|DELETE/.test(call.sql)));
  });
}
test('existing Google session retains identity and workspace', async () => {
  const session = { user_id: 'usr_existing', email: 'owner@example.test', expires_at: '2099-01-01T00:00:00Z' };
  const env = environment(session);
  const headers = { Authorization: `Bearer ${token}` };
  const me = await worker.fetch(new Request('https://api.test/api/auth/me', { headers }), env);
  assert.equal(me.status, 200);
  assert.equal((await me.json()).user.id, session.user_id);
  const stamps = await worker.fetch(new Request('https://api.test/api/stamps', { headers }), env);
  assert.equal(stamps.status, 200);
  assert.ok(env.calls.some(call => call.args[0] === 'user:usr_existing'));
  assert.ok(env.calls.every(call => !/INSERT|UPDATE|DELETE/.test(call.sql)));
});
test('missing bearer token is rejected', async () => {
  const env = environment(null);
  const response = await worker.fetch(new Request('https://api.test/api/stamps'), env);
  assert.equal(response.status, 401);
  assert.equal(env.calls.length, 0);
});

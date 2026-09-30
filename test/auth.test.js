const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Database = require('better-sqlite3');
const { createApp } = require('../server');
const redirectUri = 'https://lion-ruby.exe.xyz/api/auth/google/callback';

async function setup(t, overrides = {}) {
  const { app, db } = createApp({
    dbPath: ':memory:', clientId: 'test-client-id', clientSecret: 'test-secret', redirectUri,
    exchangeCode: async (code) => ({ id_token: code === 'valid-code' ? 'test-id-token' : null }),
    verifyCredential: async (_token, nonce) => ({
      sub: 'google-user-123', email: 'test@example.com', name: 'Test User',
      picture: 'https://example.com/avatar.png', email_verified: true, nonce,
    }),
    ...overrides,
  });
  const server = app.listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  t.after(() => { server.close(); db.close(); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const request = (route, options = {}) => fetch(`${base}${route}`, { redirect: 'manual', ...options });
  const start = async () => {
    const response = await request('/api/auth/google/start');
    const stateCookie = response.headers.get('set-cookie')?.split(';')[0];
    const authUrl = new URL(response.headers.get('location'));
    return { response, stateCookie, authUrl, state: authUrl.searchParams.get('state') };
  };
  const callback = (state, stateCookie, code = 'valid-code') => request(
    `/api/auth/google/callback?state=${encodeURIComponent(state)}&code=${encodeURIComponent(code)}`,
    { headers: { cookie: stateCookie } },
  );
  return { request, start, callback, db, base };
}

test('private routes reject unauthenticated users', async (t) => {
  const { request } = await setup(t);
  assert.equal((await request('/api/me')).status, 401);
  assert.equal((await request('/api/dashboard')).status, 401);
  const dashboard = await request('/dashboard');
  assert.equal(dashboard.status, 302);
  assert.equal(dashboard.headers.get('location'), '/');
});

test('web OAuth redirects with CSRF state, PKCE, nonce and account chooser', async (t) => {
  const { start, db } = await setup(t);
  const { response, authUrl, stateCookie, state } = await start();
  assert.equal(response.status, 302);
  assert.equal(authUrl.origin, 'https://accounts.google.com');
  assert.equal(authUrl.searchParams.get('redirect_uri'), redirectUri);
  assert.equal(authUrl.searchParams.get('prompt'), 'select_account');
  assert.equal(authUrl.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(authUrl.searchParams.get('scope'), 'openid email profile');
  assert.equal(stateCookie, `oauth_state=${state}`);
  assert.match(response.headers.get('set-cookie'), /HttpOnly/);
  assert.match(response.headers.get('set-cookie'), /Secure/);
  const flow = db.prepare('SELECT state_hash, nonce, code_verifier FROM oauth_flows').get();
  assert.equal(flow.state_hash, createHash('sha256').update(state).digest('hex'));
  assert.equal(authUrl.searchParams.get('nonce'), flow.nonce);
  assert.equal(authUrl.searchParams.get('code_challenge'),
    createHash('sha256').update(flow.code_verifier).digest('base64url'));
});

test('callback persists verified profile and session; logout revokes cookie', async (t) => {
  const { request, start, callback, db, base } = await setup(t);
  const { state, stateCookie } = await start();
  const login = await callback(state, stateCookie);
  assert.equal(login.status, 302);
  assert.equal(login.headers.get('location'), '/dashboard');
  assert.match(login.headers.get('set-cookie'), /HttpOnly/);
  assert.match(login.headers.get('set-cookie'), /SameSite=Lax/);
  const cookie = login.headers.get('set-cookie').split(', ').find((part) => part.startsWith('sid='))?.split(';')[0];
  assert.ok(cookie, 'session cookie set');
  const secret = cookie.split('=')[1];
  assert.equal(db.prepare('SELECT token_hash FROM sessions').get().token_hash,
    createHash('sha256').update(secret).digest('hex'));
  assert.equal(db.prepare('SELECT google_sub FROM users').get().google_sub, 'google-user-123');
  const profile = await (await request('/api/me', { headers: { cookie } })).json();
  assert.deepEqual(profile.user, {
    id: 1, name: 'Test User', email: 'test@example.com', picture: 'https://example.com/avatar.png',
  });
  assert.equal((await request('/api/dashboard', { headers: { cookie } })).status, 200);
  const dashboard = await request('/dashboard', { headers: { cookie } });
  assert.equal(dashboard.status, 200);
  assert.match(await dashboard.text(), /src="\/app\.js"/);
  assert.equal((await request('/api/logout', {
    method: 'POST', headers: { cookie, origin: base },
  })).status, 200);
  assert.equal((await request('/api/me', { headers: { cookie } })).status, 401);
});

test('callback rejects missing, mismatched, replayed and expired state', async (t) => {
  const { request, start, callback, db } = await setup(t);
  const { state, stateCookie } = await start();
  assert.equal((await callback(state, '')).status, 400);
  assert.equal((await callback('f'.repeat(64), stateCookie)).status, 400);
  assert.equal((await callback(state, stateCookie)).status, 302);
  assert.equal((await callback(state, stateCookie)).status, 400);
  const next = await start();
  db.prepare('UPDATE oauth_flows SET expires_at = 1').run();
  assert.equal((await callback(next.state, next.stateCookie)).status, 400);
  assert.equal((await request('/api/me')).status, 401);
});

test('rejects bad ID token or nonce before creating a session', async (t) => {
  const { start, callback, db } = await setup(t, {
    verifyCredential: async () => ({ sub: 's', email: 'e@example.com', email_verified: true, nonce: 'wrong' }),
  });
  const flow = await start();
  assert.equal((await callback(flow.state, flow.stateCookie)).headers.get('location'), '/?error=google');
  assert.equal(db.prepare('SELECT count(*) AS n FROM sessions').get().n, 0);
  assert.equal(db.prepare('SELECT count(*) AS n FROM users').get().n, 0);
});

test('migration keeps previous users and adds picture', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gis-login-'));
  const dbPath = path.join(dir, 'legacy.db');
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const legacy = new Database(dbPath);
  legacy.exec(`CREATE TABLE users (id INTEGER PRIMARY KEY, google_sub TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL, name TEXT NOT NULL);
    INSERT INTO users (google_sub, email, name) VALUES ('prior-user', 'prior@example.com', 'Prior User');`);
  legacy.close();
  const { db } = createApp({ dbPath, clientId: 'test-client-id' });
  t.after(() => db.close());
  assert.deepEqual(db.prepare('SELECT google_sub, picture FROM users').get(),
    { google_sub: 'prior-user', picture: null });
});

test('when secret is absent no login redirect is issued', async (t) => {
  const { request } = await setup(t, { clientSecret: '' });
  assert.equal((await request('/api/auth/google/start')).status, 503);
  assert.deepEqual(await (await request('/api/config')).json(), { configured: false });
});

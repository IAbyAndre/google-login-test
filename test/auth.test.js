const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Database = require('better-sqlite3');
const { createApp } = require('../server');

async function setup(t, verifyCredential = async () => ({
  sub: 'google-user-123', email: 'test@example.com', name: 'Test User',
  picture: 'https://example.com/avatar.png', email_verified: true,
})) {
  const { app, db } = createApp({ dbPath: ':memory:', clientId: 'test-client-id', verifyCredential });
  const server = app.listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  t.after(() => { server.close(); db.close(); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const request = (path, options = {}) => fetch(`${base}${path}`, { redirect: 'manual', ...options });
  const post = (path, body, options = {}) => request(path, {
    ...options, method: 'POST',
    headers: { origin: base, 'content-type': 'application/json', ...options.headers },
    body: JSON.stringify(body),
  });
  return { request, post, db, base };
}

test('private routes reject unauthenticated users', async (t) => {
  const { request } = await setup(t);
  assert.equal((await request('/api/me')).status, 401);
  assert.equal((await request('/api/dashboard')).status, 401);
  const dashboard = await request('/dashboard');
  assert.equal(dashboard.status, 302);
  assert.equal(dashboard.headers.get('location'), '/');
});

test('login stores user and opaque session, then logout revokes it', async (t) => {
  const { request, post, db } = await setup(t);
  const login = await post('/api/auth/google', { credential: 'verified-by-test-stub' });
  assert.equal(login.status, 200);
  const setCookie = login.headers.get('set-cookie');
  assert.match(setCookie, /HttpOnly/i);
  assert.match(setCookie, /SameSite=Lax/i);
  const cookie = setCookie.split(';')[0];
  const secret = cookie.split('=')[1];
  assert.equal(db.prepare('SELECT token_hash FROM sessions').get().token_hash,
    createHash('sha256').update(secret).digest('hex'));
  assert.equal(db.prepare('SELECT google_sub FROM users').get().google_sub, 'google-user-123');
  assert.equal(db.prepare('SELECT picture FROM users').get().picture, 'https://example.com/avatar.png');
  const profile = await (await request('/api/me', { headers: { cookie } })).json();
  assert.deepEqual(profile.user, {
    id: 1, name: 'Test User', email: 'test@example.com', picture: 'https://example.com/avatar.png',
  });
  assert.equal((await request('/api/dashboard', { headers: { cookie } })).status, 200);
  const dashboard = await request('/dashboard', { headers: { cookie } });
  assert.equal(dashboard.status, 200);
  assert.match(await dashboard.text(), /src="\/app\.js"/);
  assert.equal((await post('/api/logout', {}, { headers: { cookie } })).status, 200);
  assert.equal((await request('/api/me', { headers: { cookie } })).status, 401);
});

test('migrates an existing user database without losing accounts', (t) => {
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

test('bad origins and unverified tokens never create a session', async (t) => {
  const { post, db } = await setup(t, async () => { throw new Error('invalid signature'); });
  assert.equal((await post('/api/auth/google', { credential: 'bogus' },
    { headers: { origin: 'https://attacker.example' } })).status, 403);
  assert.equal((await post('/api/auth/google', { credential: 'bogus' })).status, 401);
  assert.equal((await post('/api/auth/google', {})).status, 400);
  assert.equal(db.prepare('SELECT count(*) AS n FROM sessions').get().n, 0);
});

test('HTTPS origin produces Secure cookie and expired sessions are rejected', async (t) => {
  const { post, request, db, base } = await setup(t);
  const login = await post('/api/auth/google', { credential: 'test' },
    { headers: { origin: `https://${new URL(base).host}` } });
  assert.match(login.headers.get('set-cookie'), /Secure/);
  const cookie = login.headers.get('set-cookie').split(';')[0];
  db.prepare('UPDATE sessions SET expires_at = 1').run();
  assert.equal((await request('/api/me', { headers: { cookie } })).status, 401);
});

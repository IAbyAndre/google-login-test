require('dotenv').config();
const crypto = require('node:crypto');
const path = require('node:path');
const express = require('express');
const Database = require('better-sqlite3');
const { OAuth2Client } = require('google-auth-library');
const SESSION_AGE = 7 * 24 * 60 * 60 * 1000;

function createApp({ dbPath = process.env.DB_PATH || path.join(__dirname, 'app.db'), clientId = process.env.GOOGLE_CLIENT_ID || '', verifyCredential } = {}) {
  const db = new Database(dbPath);
  db.pragma('foreign_keys = ON');
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY, google_sub TEXT NOT NULL UNIQUE,
      email TEXT NOT NULL, name TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at INTEGER NOT NULL
    );
  `);
  const googleClient = new OAuth2Client(clientId);
  const verify = verifyCredential || (async (credential) => {
    const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: clientId });
    return ticket.getPayload();
  });
  const findSession = db.prepare(`SELECT users.id, users.email, users.name, sessions.expires_at
    FROM sessions JOIN users ON users.id = sessions.user_id WHERE sessions.token_hash = ?`);
  const upsertUser = db.prepare(`INSERT INTO users (google_sub, email, name) VALUES (?, ?, ?)
    ON CONFLICT(google_sub) DO UPDATE SET email = excluded.email, name = excluded.name RETURNING id`);
  const insertSession = db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)');
  const deleteSession = db.prepare('DELETE FROM sessions WHERE token_hash = ?');
  const deleteExpired = db.prepare('DELETE FROM sessions WHERE expires_at <= ?');
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '16kb' }));

  function cookieOptions(req) {
    // TLS terminates at the exe.dev proxy; the browser's Origin carries the public scheme.
    const origin = req.get('origin') || '';
    return { httpOnly: true, secure: origin.startsWith('https://') || req.secure,
      sameSite: 'lax', path: '/', maxAge: SESSION_AGE };
  }
  function sameOrigin(req, res, next) {
    let origin;
    try { origin = new URL(req.get('origin')); }
    catch { return res.status(403).json({ error: 'Origin no permitido.' }); }
    if (origin.host !== req.get('host') ||
      (origin.protocol !== 'https:' && !(origin.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(origin.hostname)))) {
      return res.status(403).json({ error: 'Origin no permitido.' });
    }
    next();
  }
  function sessionToken(req) {
    return (req.get('cookie') || '').match(/(?:^|;\s*)sid=([a-f0-9]{64})(?:;|$)/)?.[1];
  }
  function requireSession(req, res, next) {
    const token = sessionToken(req);
    const session = token && findSession.get(crypto.createHash('sha256').update(token).digest('hex'));
    if (!session || session.expires_at <= Date.now()) {
      if (req.path === '/dashboard') return res.redirect('/');
      return res.status(401).json({ error: 'No autenticado.' });
    }
    req.user = { id: session.id, email: session.email, name: session.name };
    next();
  }

  app.get('/api/config', (_req, res) => res.json({ clientId }));
  app.post('/api/auth/google', sameOrigin, async (req, res) => {
    if (!clientId) return res.status(503).json({ error: 'Configura GOOGLE_CLIENT_ID en .env.' });
    const credential = req.body?.credential;
    if (typeof credential !== 'string' || credential.length > 10000 || !credential) {
      return res.status(400).json({ error: 'Falta el ID token de Google.' });
    }
    let profile;
    try { profile = await verify(credential); }
    catch { return res.status(401).json({ error: 'ID token inválido.' }); }
    if (!profile?.sub || !profile?.email || profile.email_verified !== true) {
      return res.status(401).json({ error: 'Cuenta de Google no verificada.' });
    }
    const userId = upsertUser.get(profile.sub, profile.email, profile.name || profile.email).id;
    const token = crypto.randomBytes(32).toString('hex');
    const hash = crypto.createHash('sha256').update(token).digest('hex');
    deleteExpired.run(Date.now());
    insertSession.run(hash, userId, Date.now() + SESSION_AGE);
    res.cookie('sid', token, cookieOptions(req));
    res.json({ ok: true });
  });
  app.get('/api/me', requireSession, (req, res) => {
    res.set('Cache-Control', 'no-store'); res.json({ user: req.user });
  });
  app.get('/api/dashboard', requireSession, (req, res) => {
    res.set('Cache-Control', 'no-store');
    res.json({ message: 'Sesión activa y dashboard protegido.', user: req.user });
  });
  app.post('/api/logout', sameOrigin, (req, res) => {
    const token = sessionToken(req);
    if (token) deleteSession.run(crypto.createHash('sha256').update(token).digest('hex'));
    const { maxAge: _maxAge, ...options } = cookieOptions(req);
    res.clearCookie('sid', options);
    res.json({ ok: true });
  });
  app.get('/dashboard', requireSession, (_req, res) => {
    res.set('Cache-Control', 'no-store');
    const fs = require('node:fs');
    const built = path.join(__dirname, 'dist', 'dashboard.html');
    res.sendFile(fs.existsSync(built) ? built : path.join(__dirname, 'public', 'dashboard.html'));
  });
  app.use(express.static(path.join(__dirname, 'dist')));
  app.use((err, _req, res, _next) => {
    res.status(err.status || 500).json({ error: err.status === 400 ? 'JSON inválido.' : 'Error interno.' });
  });
  return { app, db };
}
if (require.main === module) {
  const { app } = createApp();
  const port = Number(process.env.PORT || 3001);
  app.listen(port, '127.0.0.1', () => console.log(`API: http://127.0.0.1:${port}`));
}
module.exports = { createApp };

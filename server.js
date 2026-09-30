require('dotenv').config();
const crypto = require('node:crypto');
const path = require('node:path');
const express = require('express');
const Database = require('better-sqlite3');
const { OAuth2Client } = require('google-auth-library');
const SESSION_AGE = 7 * 24 * 60 * 60 * 1000;
const LOGIN_AGE = 10 * 60 * 1000;

function createApp({
  dbPath = process.env.DB_PATH || path.join(__dirname, 'app.db'),
  clientId = process.env.GOOGLE_CLIENT_ID || '',
  clientSecret = process.env.GOOGLE_CLIENT_SECRET || '',
  redirectUri = process.env.GOOGLE_REDIRECT_URI || '',
  exchangeCode,
  verifyCredential,
  serveBuiltDashboard = process.env.NODE_ENV === 'production',
} = {}) {
  const db = new Database(dbPath);
  db.pragma('foreign_keys = ON');
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY, google_sub TEXT NOT NULL UNIQUE,
      email TEXT NOT NULL, name TEXT NOT NULL, picture TEXT
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS oauth_flows (
      state_hash TEXT PRIMARY KEY,
      code_verifier TEXT NOT NULL,
      nonce TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    );
  `);
  // Existing installations already have a users table without a profile photo.
  if (!db.pragma('table_info(users)').some((column) => column.name === 'picture')) {
    db.exec('ALTER TABLE users ADD COLUMN picture TEXT');
  }
  const googleClient = new OAuth2Client(clientId, clientSecret, redirectUri);
  const exchange = exchangeCode || (async (code, codeVerifier) => {
    const { tokens } = await googleClient.getToken({ code, codeVerifier });
    return tokens;
  });
  const verify = verifyCredential || (async (credential) => {
    const ticket = await googleClient.verifyIdToken({ idToken: credential, audience: clientId });
    return ticket.getPayload();
  });
  const findSession = db.prepare(`SELECT users.id, users.email, users.name, users.picture, sessions.expires_at
    FROM sessions JOIN users ON users.id = sessions.user_id WHERE sessions.token_hash = ?`);
  const upsertUser = db.prepare(`INSERT INTO users (google_sub, email, name, picture) VALUES (?, ?, ?, ?)
    ON CONFLICT(google_sub) DO UPDATE SET email = excluded.email, name = excluded.name,
    picture = excluded.picture RETURNING id`);
  const insertSession = db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)');
  const deleteSession = db.prepare('DELETE FROM sessions WHERE token_hash = ?');
  const deleteExpired = db.prepare('DELETE FROM sessions WHERE expires_at <= ?');
  const insertFlow = db.prepare('INSERT INTO oauth_flows (state_hash, code_verifier, nonce, expires_at) VALUES (?, ?, ?, ?)');
  const findFlow = db.prepare('SELECT code_verifier, nonce, expires_at FROM oauth_flows WHERE state_hash = ?');
  const deleteFlow = db.prepare('DELETE FROM oauth_flows WHERE state_hash = ?');
  const deleteExpiredFlows = db.prepare('DELETE FROM oauth_flows WHERE expires_at <= ?');
  const app = express();
  app.disable('x-powered-by');
  const configured = Boolean(clientId && clientSecret && redirectUri);

  function cookieOptions(req) {
    // OAuth navigation/callback has no Origin header; the configured public URI is HTTPS.
    const origin = req.get('origin') || '';
    return { httpOnly: true, secure: origin.startsWith('https://') || redirectUri.startsWith('https://') || req.secure,
      sameSite: 'lax', path: '/', maxAge: SESSION_AGE };
  }
  function clearCookie(req, res, name) {
    const { maxAge: _maxAge, ...options } = cookieOptions(req);
    res.clearCookie(name, options);
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
    req.user = { id: session.id, email: session.email, name: session.name, picture: session.picture };
    next();
  }

  app.get('/api/config', (_req, res) => res.json({ configured }));
  app.get('/api/auth/google/start', (req, res) => {
    if (!configured) return res.status(503).send('Configura GOOGLE_CLIENT_SECRET y GOOGLE_REDIRECT_URI en .env.');
    const state = crypto.randomBytes(32).toString('hex');
    const nonce = crypto.randomBytes(32).toString('hex');
    const codeVerifier = crypto.randomBytes(32).toString('base64url');
    const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
    deleteExpiredFlows.run(Date.now());
    insertFlow.run(crypto.createHash('sha256').update(state).digest('hex'), codeVerifier, nonce, Date.now() + LOGIN_AGE);
    res.cookie('oauth_state', state, { ...cookieOptions(req), maxAge: LOGIN_AGE });
    res.set('Cache-Control', 'no-store');
    res.redirect(googleClient.generateAuthUrl({
      scope: ['openid', 'email', 'profile'],
      state, nonce, prompt: 'select_account',
      code_challenge: codeChallenge, code_challenge_method: 'S256',
    }));
  });
  app.get('/api/auth/google/callback', async (req, res) => {
    const state = req.query.state;
    const cookieState = (req.get('cookie') || '').match(/(?:^|;\s*)oauth_state=([a-f0-9]{64})(?:;|$)/)?.[1];
    if (typeof state !== 'string' || !/^[a-f0-9]{64}$/.test(state) || !cookieState ||
      !crypto.timingSafeEqual(Buffer.from(state), Buffer.from(cookieState))) {
      return res.status(400).send('Estado OAuth inválido. Vuelve a iniciar sesión.');
    }
    clearCookie(req, res, 'oauth_state');
    const stateHash = crypto.createHash('sha256').update(state).digest('hex');
    const flow = findFlow.get(stateHash);
    deleteFlow.run(stateHash); // Each authorization attempt can only be used once.
    if (!flow || flow.expires_at <= Date.now()) return res.status(400).send('Inicio de sesión caducado.');
    const code = req.query.code;
    if (req.query.error || typeof code !== 'string' || !code || code.length > 4096) {
      return res.redirect('/?error=google');
    }
    let profile;
    try {
      const tokens = await exchange(code, flow.code_verifier);
      if (!tokens?.id_token) throw new Error('Missing ID token');
      profile = await verify(tokens.id_token, flow.nonce);
    } catch {
      return res.redirect('/?error=google');
    }
    if (!profile?.sub || !profile?.email || profile.email_verified !== true || profile.nonce !== flow.nonce) {
      return res.redirect('/?error=google');
    }
    const picture = typeof profile.picture === 'string' && profile.picture.startsWith('https://')
      ? profile.picture : null;
    const userId = upsertUser.get(profile.sub, profile.email, profile.name || profile.email, picture).id;
    const token = crypto.randomBytes(32).toString('hex');
    const hash = crypto.createHash('sha256').update(token).digest('hex');
    deleteExpired.run(Date.now());
    insertSession.run(hash, userId, Date.now() + SESSION_AGE);
    res.cookie('sid', token, cookieOptions(req));
    res.redirect('/dashboard');
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
    clearCookie(req, res, 'sid');
    res.json({ ok: true });
  });
  app.get('/dashboard', requireSession, (_req, res) => {
    res.set('Cache-Control', 'no-store');
    // Vite serves /app.js and /style.css in dev; only production uses hashed dist assets.
    const folder = serveBuiltDashboard ? 'dist' : 'public';
    res.sendFile(path.join(__dirname, folder, 'dashboard.html'));
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

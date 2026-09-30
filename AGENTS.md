# Project conventions

- Minimal Google web login test. HTML, vanilla JS/CSS, Vite for development/build, Express API, SQLite (`better-sqlite3`).
- No frontend framework, ORM, JWT session, Redis, or auth provider SDK. Keep UI and dependencies small.
- `public/` is Vite's root. `/api/*` and `/dashboard` are proxied to Express in development. Express authorizes `/dashboard` and all private API data.
- The login is a **plain CSS link** to an Express OAuth authorization-code redirect, not a GIS button/iframe. Google redirects back to `/api/auth/google/callback`; Express exchanges the code using its secret + PKCE and verifies the signed ID token, audience and nonce. Keep client secret server-only; don't add GIS `renderButton` back.
- OAuth state is bound to a short-lived HttpOnly SameSite=Lax cookie, stored hashed in SQLite and consumed exactly once. Session cookie `sid` is an opaque random secret; only its SHA-256 hash is stored in SQLite. Never commit credentials or the DB.

## Setup

1. `npm ci`
2. Copy `.env.example` to `.env` and set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` from the same OAuth **Web application** credential. Set `GOOGLE_REDIRECT_URI=https://lion-ruby.exe.xyz/api/auth/google/callback`. Add this **exact URI** to Google Cloud's *Authorized redirect URIs*. Unlike the old GIS callback login, this flow needs a redirect URI and client secret. Do not put the secret in frontend files.
3. `npm run server` (API at `127.0.0.1:3001`), then `npm run dev` (Vite at `0.0.0.0:8000`). Access `https://lion-ruby.exe.xyz/`.
4. `npm run build` builds `dist/`. For standalone production serving, run `NODE_ENV=production PORT=8000 npm run server` **without Vite running**; Express serves `dist/` and the protected route. In development Express serves `public/dashboard.html` so Vite resolves `/app.js` and `/style.css`.
5. `npm test` runs Node's built-in integration tests (Google code exchange and ID token verifier mocked; no external credentials required).

After changing `.env`, restart the API (`sudo systemctl restart google-login-api`). Never use the test verifier in the running app. The web redirect login will not start until the client secret and redirect URI are configured.

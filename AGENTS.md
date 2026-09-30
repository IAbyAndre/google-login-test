# Project conventions

- Minimal end-to-end GIS login test. HTML, vanilla JS/CSS, Vite for development/build, Express API, SQLite (`better-sqlite3`).
- No frontend framework, ORM, JWT session, or additional authentication provider. Keep the UI and dependencies small.
- `public/` is Vite's root. `/api/*` and `/dashboard` are proxied to Express in development. Express authorizes `/dashboard` and all private API data; frontend display checks alone are not access control.
- Login styles are inline in `public/index.html` so the page does not flash or shift on reload. A local CSS placeholder occupies the exact GIS button slot until the real Google control renders; keep the GIS button for the ID-token callback.
- Google ID tokens must be verified on the server with `google-auth-library` and the configured audience. Session cookie `sid` is an opaque random secret; only its SHA-256 hash is stored in SQLite. Never commit credentials or the DB.

## Setup

1. `npm ci`
2. Copy `.env.example` to `.env` and set `GOOGLE_CLIENT_ID` (OAuth **Web application** client ID). In Google Cloud, add `https://lion-ruby.exe.xyz` as an authorized JavaScript origin (also `http://localhost:8000` for local browser testing). The GIS button uses a callback, not an OAuth redirect URI.
3. `npm run server` (API at `127.0.0.1:3001`), then `npm run dev` (Vite at `0.0.0.0:8000`). Access `https://lion-ruby.exe.xyz/`.
4. `npm run build` builds `dist/`. For standalone production serving, run `NODE_ENV=production PORT=8000 npm run server` **without Vite running**; Express serves `dist/` and the protected route. In development Express serves `public/dashboard.html` so Vite resolves `/app.js` and `/style.css`.
5. `npm test` runs Node's built-in integration tests (Google verifier mocked, no external credentials required).

After changing `.env`, restart the API. Never use the test verifier in the running app. The actual Google login requires a valid Client ID and its authorized origin.

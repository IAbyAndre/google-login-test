const status = document.querySelector('#status');

async function jsonRequest(url, options) {
  const response = await fetch(url, { credentials: 'same-origin', ...options });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Error de red.');
  return data;
}

async function showLogin() {
  try {
    const session = await fetch('/api/me', { credentials: 'same-origin' });
    if (session.ok) {
      window.location.replace('/dashboard');
      return;
    }
    const { clientId } = await jsonRequest('/api/config');
    if (!clientId) {
      status.textContent = 'Configura GOOGLE_CLIENT_ID en .env y reinicia el servidor.';
      return;
    }
    // GIS is loaded asynchronously; stop waiting if the network blocks the script.
    for (let attempt = 0; !window.google?.accounts?.id; attempt++) {
      if (attempt >= 100) throw new Error('No se pudo cargar Google Identity Services.');
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    google.accounts.id.initialize({
      client_id: clientId,
      callback: async ({ credential }) => {
        status.textContent = 'Verificando identidad…';
        try {
          await jsonRequest('/api/auth/google', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ credential }),
          });
          window.location.assign('/dashboard');
        } catch (error) { status.textContent = error.message; }
      },
    });
    google.accounts.id.renderButton(document.querySelector('#google-button'), {
      theme: 'outline', size: 'large', text: 'signin_with',
    });
    status.textContent = '';
  } catch (error) { status.textContent = error.message || 'No se pudo conectar con el servidor.'; }
}

async function showDashboard() {
  try {
    const { user } = await jsonRequest('/api/dashboard');
    document.querySelector('#identity').textContent = `${user.name} · ${user.email}`;
    status.textContent = 'Sesión activa y dashboard protegido.';
    const logout = document.querySelector('#logout');
    logout.hidden = false;
    logout.addEventListener('click', async () => {
      logout.disabled = true;
      try {
        await jsonRequest('/api/logout', { method: 'POST' });
        window.location.replace('/');
      } catch (error) {
        status.textContent = error.message;
        logout.disabled = false;
      }
    });
  } catch { window.location.replace('/'); }
}

if (window.location.pathname === '/dashboard') showDashboard();
else showLogin();

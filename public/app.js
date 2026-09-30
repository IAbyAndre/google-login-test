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
    const { configured } = await jsonRequest('/api/config');
    if (!configured) {
      status.textContent = 'Configura GOOGLE_CLIENT_SECRET en .env para activar el login web.';
      const link = document.querySelector('.google-login');
      link.removeAttribute('href');
      link.setAttribute('aria-disabled', 'true');
    } else if (new URLSearchParams(window.location.search).has('error')) {
      status.textContent = 'No se pudo iniciar sesión con Google. Inténtalo de nuevo.';
    }
  } catch (error) { status.textContent = error.message || 'No se pudo conectar con el servidor.'; }
}

async function showDashboard() {
  try {
    const { user } = await jsonRequest('/api/dashboard');
    document.querySelector('#profile-name').textContent = user.name;
    document.querySelector('#profile-email').textContent = user.email;
    const avatar = document.querySelector('#avatar');
    const initials = document.querySelector('#initials');
    initials.textContent = (user.name || user.email).trim().slice(0, 1).toUpperCase();
    if (user.picture) {
      avatar.addEventListener('load', () => { avatar.hidden = false; initials.hidden = true; });
      avatar.addEventListener('error', () => { avatar.hidden = true; initials.hidden = false; });
      avatar.src = user.picture;
    }
    document.querySelector('#profile').hidden = false;
    status.textContent = 'Sesión activa.';
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

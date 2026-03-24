const form = document.getElementById('admin-login-form');
const errorMsg = document.getElementById('error-msg');

async function getCsrfToken() {
  const res = await fetch('/csrf-token', {
    credentials: 'include'
  });

  if (!res.ok) {
    throw new Error('Impossibile ottenere il token CSRF');
  }

  const data = await res.json();
  return data.csrfToken;
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();

  errorMsg.style.display = 'none';
  errorMsg.textContent = '';

  try {
    const csrfToken = await getCsrfToken();

    const formData = new FormData(form);
    const body = new URLSearchParams(formData);

    const res = await fetch('/impianto/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'CSRF-Token': csrfToken
      },
      credentials: 'include',
      body
    });

    const text = await res.text();

    if (res.ok && text.toLowerCase().includes('successo')) {
      const username = formData.get('username');
      localStorage.setItem('adminUser', username);
      window.location.href = '/impianto/dashboard.html';
    } else {
      errorMsg.style.display = 'block';
      errorMsg.textContent = text || 'Errore login';
    }
  } catch (err) {
    console.error('Errore login admin:', err);
    errorMsg.style.display = 'block';
    errorMsg.textContent = 'Errore di connessione o sicurezza richiesta';
  }
});
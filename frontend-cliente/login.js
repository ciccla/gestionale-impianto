document.addEventListener('DOMContentLoaded', async () => {
  const form = document.getElementById('login-form');
  const errorMsg = document.getElementById('error-msg');

  let csrfToken = '';

  function mostraErrore(testo) {
    errorMsg.textContent = testo;
    errorMsg.style.display = 'block';
  }

  async function caricaCsrfToken() {
    const res = await fetch('/csrf-token', {
      credentials: 'include'
    });

    if (!res.ok) {
      throw new Error('Impossibile ottenere il token CSRF');
    }

    const data = await res.json();
    csrfToken = data.csrfToken;

    let tokenInput = form.querySelector('input[name="_csrf"]');
    if (!tokenInput) {
      tokenInput = document.createElement('input');
      tokenInput.type = 'hidden';
      tokenInput.name = '_csrf';
      form.appendChild(tokenInput);
    }

    tokenInput.value = csrfToken;
  }

  try {
    await caricaCsrfToken();
  } catch (err) {
    console.error(err);
    mostraErrore('Errore di sicurezza. Ricarica la pagina.');
    return;
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();

    errorMsg.style.display = 'none';
    errorMsg.textContent = '';

    try {
      const formData = new FormData(form);
      const body = new URLSearchParams(formData);

      const res = await fetch(form.action, {
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
        window.location.href = '/cliente/dashboard.html';
        return;
      }

      mostraErrore(text || 'Login non riuscito');
    } catch (err) {
      console.error(err);
      mostraErrore('Errore di rete. Riprova.');
    }
  });
});
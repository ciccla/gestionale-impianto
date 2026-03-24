document.addEventListener('DOMContentLoaded', async () => {
  const form = document.getElementById('login-form');
  const notifica = document.getElementById('notifica');

  let csrfToken = '';

  function mostraMessaggio(testo, tipo = 'error') {
    notifica.textContent = testo;
    notifica.className = 'notifica';
    notifica.classList.add(tipo);
    notifica.style.display = 'block';
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
    console.log('✅ CSRF token login impostato correttamente');
  }

  try {
    await caricaCsrfToken();
  } catch (err) {
    console.error('❌ Errore ottenendo CSRF token:', err);
    mostraMessaggio('Errore di sicurezza. Ricarica la pagina.');
    return;
  }

    form.addEventListener('submit', async (e) => {
  e.preventDefault();

  notifica.style.display = 'none';
  notifica.className = 'notifica';

  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value.trim();

  if (!username || !password) {
    mostraMessaggio('⚠️ Compila tutti i campi.');
    return;
  }

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

    if (res.redirected) {
      window.location.href = res.url;
      return;
    }

    const contentType = res.headers.get('content-type') || '';

    if (contentType.includes('text/html')) {
      window.location.href = '/cliente/dashboard.html';
      return;
    }

    const text = await res.text();

    if (res.ok && text.toLowerCase().includes('successo')) {
      mostraMessaggio('✅ Accesso effettuato con successo', 'success');
      setTimeout(() => {
        window.location.href = '/cliente/dashboard.html';
      }, 800);
      return;
    }

    mostraMessaggio(text || '❌ Credenziali errate.');
  } catch (err) {
    console.error(err);
    mostraMessaggio('❌ Errore di rete. Riprova.');
  }
    }); 
    })
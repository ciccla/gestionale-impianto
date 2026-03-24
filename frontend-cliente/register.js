document.addEventListener('DOMContentLoaded', async () => {
  const form = document.getElementById('register-form');
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
    console.log('✅ CSRF token impostato correttamente');
  }

  try {
    await caricaCsrfToken();
  } catch (err) {
    console.error('❌ Errore ottenendo CSRF token:', err);
    mostraMessaggio('Errore di sicurezza: ricarica la pagina e riprova.');
    return;
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();

    notifica.style.display = 'none';
    notifica.className = 'notifica';

    const password = document.getElementById('password').value;
    const confirm = document.getElementById('confirm_password').value;

    if (password !== confirm) {
      mostraMessaggio('❌ Le password non coincidono');
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
        body,
        credentials: 'include'
      });

      const text = await res.text();

      if (res.ok && text.toLowerCase().includes('successo')) {
        mostraMessaggio(text, 'success');
        setTimeout(() => {
          window.location.href = '/cliente/login.html';
        }, 1000);
      } else {
        mostraMessaggio(text || 'Registrazione non riuscita');
      }
    } catch (err) {
      console.error(err);
      mostraMessaggio('Errore di rete. Riprova.');
    }
  });
});
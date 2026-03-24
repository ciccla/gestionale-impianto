document.addEventListener('DOMContentLoaded', async () => {
  const form = document.getElementById('register-form');
  const notifica = document.getElementById('notifica');

  function mostraMessaggio(testo, tipo = 'error') {
    notifica.textContent = testo;
    notifica.className = 'notifica';
    notifica.classList.add(tipo);
    notifica.style.display = 'block';
  }

  async function impostaCsrfToken() {
    const res = await fetch('/csrf-token', {
      credentials: 'include'
    });

    if (!res.ok) {
      throw new Error('Impossibile ottenere il token CSRF');
    }

    const data = await res.json();

    let tokenInput = form.querySelector('input[name="_csrf"]');
    if (!tokenInput) {
      tokenInput = document.createElement('input');
      tokenInput.type = 'hidden';
      tokenInput.name = '_csrf';
      form.appendChild(tokenInput);
    }

    tokenInput.value = data.csrfToken;
    console.log('✅ CSRF token impostato correttamente');
  }

  try {
    await impostaCsrfToken();
  } catch (err) {
    console.error('❌ Errore ottenendo CSRF token:', err);
    mostraMessaggio('Errore di sicurezza: ricarica la pagina e riprova.');
    return;
  }

  form.addEventListener('submit', async function (e) {
    e.preventDefault();

    notifica.style.display = 'none';
    notifica.className = 'notifica';

    const password = document.getElementById('password').value;
    const confirm = document.getElementById('confirm_password').value;

    if (password !== confirm) {
      mostraMessaggio('❌ Le password non coincidono');
      return;
    }

    const formData = new FormData(form);

    try {
      const res = await fetch(form.action, {
        method: 'POST',
        body: formData,
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
// backend/server.js — versione sicura per Render
require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const multer = require('multer');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const csurf = require('csurf');

const db = require('./db'); // deve esportare almeno db.query. Se espone anche pool, lo riuso sotto.

// ------------------ App & porta ------------------
const app = express();
const PORT = process.env.PORT || 3000;
const isProd = process.env.NODE_ENV === 'production';

// Render/Proxy: necessario per cookie "secure"
app.set('trust proxy', 1);

// ------------------ Security headers ------------------
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
}));

// ------------------ Body parsers (limit) ------------------
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// ------------------ CORS (separa domini solo se serve) ------------------
const allowed = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

app.use(cors({
  origin: function (origin, cb) {
    console.log('🌍 Richiesta CORS da:', origin);
    console.log('✅ Allowed origins:', allowed);

    // ✅ consenti richieste:
    // - senza origin (undefined)
    // - con origin "null" (form HTML)
    // - provenienti da domini autorizzati
    if (!origin || origin === 'null' || allowed.includes(origin)) {
      console.log('✅ Autorizzato:', origin);
      return cb(null, true);
    }

    console.warn('🚫 Bloccato da CORS:', origin);
    return cb(new Error('Not allowed by CORS'));
  },
  credentials: true,
}));



// ------------------ Sessione (PG store, non Memory) ------------------
if (!process.env.SESSION_SECRET) {
  console.error('FATAL: SESSION_SECRET mancante. Impostalo nelle variabili di Render.');
  process.exit(1);
}

// Provo a riusare il pool definito in db.js, altrimenti creo un nuovo Pool.
let pgPool = db.pool;
if (!pgPool) {
  const { Pool } = require('pg');
  pgPool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: isProd ? { rejectUnauthorized: false } : undefined, // su Render in genere è ok
  });
}

app.use(session({
  store: new pgSession({
    pool: pgPool,
    tableName: 'session',
    createTableIfMissing: true,
  }),
  name: 'sid',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    secure: isProd, // true in prod (HTTPS su Render)
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 8, // 8 ore
  },
}));

// ------------------ Rate limit ------------------
const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300, // richieste totali
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(strictLimiter);

// limiter più severo per auth
const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10, // 10 tentativi/10 min
  standardHeaders: true,
  legacyHeaders: false,
});

// ------------------ Upload (limiti + whitelist) ------------------
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const upload = multer({
  dest: uploadDir,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10 MB
  fileFilter: (req, file, cb) => {
    const ok = ['application/pdf'].includes(file.mimetype);
    cb(ok ? null : new Error('Tipo file non consentito (solo PDF).'), ok);
  },
});

// ------------------ Statiche ------------------
app.use('/cliente', express.static(path.join(__dirname, '../frontend-cliente')));
app.use('/impianto', express.static(path.join(__dirname, '../frontend-impianto')));
app.use(express.static(path.join(__dirname, '../public')));

// ------------------ Redirect comodi ------------------
app.get('/', (req, res) => res.redirect('/cliente/login.html'));
app.get('/impianto/dashboard.html', (req, res) => res.redirect('/impianto/dashboard-trasporti.html')); // alias

// ------------------ Mailer (no-op se manca API key) ------------------
let transporter;
if (process.env.SENDGRID_API_KEY) {
  transporter = nodemailer.createTransport({
    service: 'SendGrid',
    auth: { user: 'apikey', pass: process.env.SENDGRID_API_KEY },
  });
} else {
  transporter = { sendMail: async () => ({ accepted: [], rejected: [] }) }; // finto per staging
}

// ------------------ CSRF (session-based) ------------------
// Usiamo CSRF solo per metodi mutativi; esponiamo un endpoint per ottenere il token.
const csrfProtection = csurf(); // session-based

// ⚠️ QUI aggiungo il middleware sulla rotta /csrf-token
app.get('/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Applica CSRF SOLO a POST/PUT/PATCH/DELETE
app.use((req, res, next) => {
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method)) {
    return csrfProtection(req, res, next);
  }
  return next();
});

// ------------------ Rotte ------------------

// ----------- CLIENTE -----------
app.post('/cliente/register', authLimiter, async (req, res) => {
  try {
    const { email, username, password } = req.body;
    if (!email || !username || !password) return res.status(400).send('Compila tutti i campi');

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) return res.status(400).send('Email non valida');

    const exists = await db.query('SELECT id FROM utenti WHERE username = $1 OR email = $2', [username, email]);
    if (exists.rows.length > 0) return res.status(409).send('Username o email già registrati');

    const hash = await bcrypt.hash(password, 12);
    const ins = await db.query(
      `INSERT INTO utenti (username, password, email, ruolo)
       VALUES ($1, $2, $3, $4) RETURNING id, username, ruolo`,
      [username, hash, email, 'cliente']
    );

    req.session.regenerate(err => {
      if (err) console.error('Errore rigenerazione sessione:', err);
      req.session.utente = ins.rows[0];
      return res.redirect('/cliente/dashboard.html');
    });
  } catch (err) {
    console.error('❌ Errore registrazione:', err);
    res.status(500).send('Errore nella registrazione');
  }
});

app.post('/cliente/login', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body; // email o username
    if (!username || !password) return res.status(400).send('Compila tutti i campi');

    const q = await db.query(
      `SELECT * FROM utenti
       WHERE (username = $1 OR email = $1) AND ruolo = 'cliente'
       LIMIT 1`,
      [username]
    );
    const user = q.rows[0];
    if (!user) return res.status(404).send('Utente non trovato');
    if (user.bloccato) return res.status(403).send('Account bloccato');

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).send('Password errata');

    req.session.regenerate(err => {
      if (err) console.error('Errore rigenerazione sessione:', err);
      req.session.utente = { id: user.id, username: user.username, ruolo: user.ruolo };
      return res.redirect('/cliente/dashboard.html');
    });
  } catch (err) {
    console.error('❌ Login cliente:', err);
    res.status(500).send('Errore durante il login');
  }
});

app.get('/cliente/logout', (req, res) => {
  req.session?.destroy?.(() => res.redirect('/cliente/login.html'));
});

app.get('/cliente/info', (req, res) => {
  if (!req.session.utente) return res.status(401).json({ error: 'Non autenticato' });
  res.json({ username: req.session.utente.username });
});

app.get('/cliente/prenotazioni', async (req, res) => {
  if (!req.session.utente) return res.status(403).send([]);
  try {
    const r = await db.query(
      'SELECT * FROM prenotazioni WHERE cliente_id = $1 ORDER BY id DESC',
      [req.session.utente.id]
    );
    res.json(r.rows);
  } catch (err) {
    console.error('Errore caricamento prenotazioni:', err);
    res.send([]);
  }
});

app.post('/cliente/prenotazione', upload.single('certificato_analitico'), async (req, res) => {
  if (!req.session.utente) return res.status(403).send('Devi essere loggato');

  const {
    ragione_sociale, produttore, codice_cer, caratteristiche_pericolo,
    tipo_imballo, tipo_imballo_altro, stato_fisico,
    quantita, giorno_conferimento
  } = req.body;

  const caratteristiche = Array.isArray(caratteristiche_pericolo)
    ? caratteristiche_pericolo.join(',')
    : (caratteristiche_pericolo || '');
  const imballo_finale = (tipo_imballo === 'Altro' && tipo_imballo_altro) ? tipo_imballo_altro : tipo_imballo;
  const certificato = req.file ? req.file.filename : null;

  try {
    await db.query(`
      INSERT INTO prenotazioni
        (cliente_id, ragione_sociale, produttore, codice_cer, caratteristiche_pericolo,
         tipo_imballo, stato_fisico, certificato_analitico, quantita, giorno_conferimento)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
    `,
    [req.session.utente.id, ragione_sociale, produttore, codice_cer, caratteristiche,
     imballo_finale, stato_fisico, certificato, quantita, giorno_conferimento]);

    res.send('Prenotazione inserita correttamente ✅');
  } catch (err) {
    console.error('❌ Errore inserimento:', err);
    res.status(500).send("Errore durante l'inserimento");
  }
});

app.post('/cliente/richieste-trasporto', async (req, res) => {
  if (!req.session.utente) return res.status(403).send('Accesso negato');

  const {
    richiedente, produttore, codice_cer, tipo_automezzo,
    tipo_trasporto, data_trasporto, orario_preferito,
    numero_referente, prezzo_pattuito
  } = req.body;

  try {
    await db.query(`
      INSERT INTO richieste_trasporto
        (cliente_id, richiedente, produttore, codice_cer, tipo_automezzo,
         data_trasporto, orario_preferito, numero_referente, prezzo_pattuito)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
    `,
    [req.session.utente.id, richiedente, produttore, codice_cer, tipo_automezzo,
     data_trasporto, orario_preferito, numero_referente, prezzo_pattuito]);

    res.send('Richiesta trasporto inviata ✅');
  } catch (err) {
    console.error('❌ Errore richiesta trasporto:', err);
    res.status(500).send('Errore richiesta trasporto');
  }
});

app.get('/cliente/richieste-trasporto', async (req, res) => {
  if (!req.session.utente) return res.status(403).send('Non autorizzato');
  try {
    const r = await db.query(
      'SELECT * FROM richieste_trasporto WHERE cliente_id = $1 ORDER BY data_trasporto DESC',
      [req.session.utente.id]
    );
    res.json(r.rows);
  } catch (err) {
    console.error('❌ Errore fetch richieste trasporto cliente:', err);
    res.status(500).send('Errore server');
  }
});

app.get('/cliente/notifiche-stato', async (req, res) => {
  if (!req.session.utente) return res.status(401).json({ errore: 'Non autenticato' });
  try {
    const pren = await db.query(
      'SELECT id, stato FROM prenotazioni WHERE cliente_id = $1',
      [req.session.utente.id]
    );
    const tras = await db.query(
      'SELECT id, stato FROM richieste_trasporto WHERE cliente_id = $1',
      [req.session.utente.id]
    );
    res.json({ prenotazioni: pren.rows, trasporti: tras.rows });
  } catch (err) {
    console.error('❌ Errore polling stato:', err);
    res.status(500).send('Errore');
  }
});

// ----------- CHAT -----------
app.get('/chat/prenotazione/:id', async (req, res) => {
  try {
    const r = await db.query(
      'SELECT * FROM messaggi WHERE prenotazione_id = $1 ORDER BY timestamp ASC',
      [req.params.id]
    );
    res.json(r.rows);
  } catch {
    res.status(500).send('Errore');
  }
});

app.post('/chat/prenotazione', async (req, res) => {
  const { prenotazione_id, mittente, messaggio } = req.body;
  if (!prenotazione_id || !mittente || !messaggio) return res.status(400).send('Dati mancanti');
  try {
    await db.query(
      'INSERT INTO messaggi (prenotazione_id, mittente, messaggio) VALUES ($1, $2, $3)',
      [prenotazione_id, mittente, messaggio]
    );
    res.send('Messaggio inviato ✅');
  } catch {
    res.status(500).send('Errore');
  }
});

app.get('/chat/trasporto/:id', async (req, res) => {
  try {
    const r = await db.query(
      'SELECT * FROM messaggi_trasporto WHERE trasporto_id = $1 ORDER BY timestamp ASC',
      [req.params.id]
    );
    res.json(r.rows);
  } catch {
    res.status(500).send('Errore');
  }
});

app.post('/chat/trasporto', async (req, res) => {
  const { trasporto_id, mittente, messaggio } = req.body;
  if (!trasporto_id || !mittente || !messaggio) return res.status(400).send('Dati mancanti');
  try {
    await db.query(
      'INSERT INTO messaggi_trasporto (trasporto_id, mittente, messaggio) VALUES ($1, $2, $3)',
      [trasporto_id, mittente, messaggio]
    );
    res.send('Messaggio inviato ✅');
  } catch {
    res.status(500).send('Errore');
  }
});

// ----------- IMPIANTO (Admin) -----------
app.post('/impianto/login', authLimiter, async (req, res) => {
  const { username, password } = req.body; // email o username
  if (!username || !password) return res.status(400).send('Compila tutti i campi');
  try {
    const q = await db.query(
      `SELECT * FROM utenti
       WHERE (email = $1 OR username = $1) AND ruolo = 'admin'
       LIMIT 1`,
      [username]
    );
    const user = q.rows[0];
    if (!user) return res.status(404).send('Admin non trovato');

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).send('Password errata');

    req.session.regenerate(err => {
      if (err) console.error('Errore rigenerazione sessione:', err);
      req.session.admin = { id: user.id, username: user.username, ruolo: user.ruolo };
      return res.send('Login impianto effettuato con successo ✅');
    });
  } catch (err) {
    console.error('❌ Errore login impianto:', err);
    res.status(500).send('Errore login impianto');
  }
});

// Password policy forte
function passwordStrongEnough(pwd = '') {
  if (typeof pwd !== 'string') return false;
  if (pwd.length < 12) return false;
  if (!/[a-z]/.test(pwd) || !/[A-Z]/.test(pwd)) return false;
  if (!/\d/.test(pwd)) return false;
  if (!/[^A-Za-z0-9]/.test(pwd)) return false; // simboli
  const low = pwd.toLowerCase();
  const banned = ['password', 'qwerty', '1234', 'abcd', 'admin', 'ecodrin'];
  if (banned.some(w => low.includes(w))) return false;
  return true;
}

app.post(['/api/users/change-password', '/impianto/cambia-password'], async (req, res) => {
  try {
    if (!req.session.admin) return res.status(403).json({ ok: false, message: 'Accesso negato' });

    const { currentPassword, newPassword } = req.body || {};
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ ok: false, message: 'Compila tutti i campi' });
    }

    if (!passwordStrongEnough(newPassword)) {
      return res.status(400).json({
        ok: false,
        message: 'Password troppo debole (>=12 caratteri, maiuscola, minuscola, numero, simbolo; evita parole comuni)'
      });
    }

    const { rows } = await db.query(
      'SELECT id, username, password FROM utenti WHERE id = $1 AND ruolo = $2 LIMIT 1',
      [req.session.admin.id, 'admin']
    );
    if (!rows.length) return res.status(404).json({ ok: false, message: 'Admin non trovato' });

    const valid = await bcrypt.compare(currentPassword, rows[0].password);
    if (!valid) return res.status(401).json({ ok: false, message: 'Password attuale errata' });

    const hash = await bcrypt.hash(newPassword, 12);
    await db.query('UPDATE utenti SET password = $1 WHERE id = $2', [hash, rows[0].id]);

    req.session.regenerate(err => {
      if (err) console.error('Errore rigenerazione sessione:', err);
      req.session.admin = { id: rows[0].id, username: rows[0].username, ruolo: 'admin' };
      return res.json({ ok: true, message: 'Password aggiornata con successo' });
    });
  } catch (err) {
    console.error('❌ Errore cambio password:', err);
    res.status(500).json({ ok: false, message: 'Errore interno' });
  }
});

app.get('/impianto/logout', (req, res) => {
  req.session?.destroy?.(() => res.redirect('/impianto/login.html'));
});

app.get('/impianto/prenotazioni', async (req, res) => {
  if (!req.session.admin) return res.status(403).send('Accesso negato');
  try {
    const r = await db.query(`
      SELECT p.*, u.email AS email_cliente
      FROM prenotazioni p
      JOIN utenti u ON p.cliente_id = u.id
      ORDER BY p.id DESC
    `);
    res.json(r.rows);
  } catch (err) {
    console.error('❌ Errore caricamento prenotazioni impianto:', err);
    res.status(500).send('Errore');
  }
});

app.get('/impianto/trasporti', async (req, res) => {
  if (!req.session.admin) return res.status(403).send('Accesso negato');
  try {
    const r = await db.query(`
      SELECT r.*, u.email AS email_cliente
      FROM richieste_trasporto r
      JOIN utenti u ON r.cliente_id = u.id
      ORDER BY r.id DESC
    `);
    res.json(r.rows);
  } catch (err) {
    console.error('❌ Errore caricamento trasporti impianto:', err);
    res.status(500).send('Errore');
  }
});

app.post('/impianto/cambia-stato', async (req, res) => {
  if (!req.session.admin) return res.status(403).send('Accesso negato');

  const { id, nuovo_stato, richiesta } = req.body;
  try {
    await db.query('UPDATE prenotazioni SET stato = $1 WHERE id = $2', [nuovo_stato, id]);

    // mail al cliente
    const { rows } = await db.query(
      `SELECT u.email, p.giorno_conferimento
       FROM prenotazioni p
       JOIN utenti u ON p.cliente_id = u.id
       WHERE p.id = $1`,
      [id]
    );
    if (rows.length > 0) {
      const email = rows[0].email;
      const testo = `Gentile cliente,
La tua prenotazione n°${id} del ${rows[0].giorno_conferimento} è stata aggiornata a: ${nuovo_stato.toUpperCase()}
${richiesta ? '\nRichiesta dell’impianto:\n' + richiesta : ''}

Cordiali saluti,
Impianto`;
      await transporter.sendMail({
        from: `"Ecodrin" <${process.env.EMAIL_USER || 'no-reply@ecodrin.local'}>`,
        to: email,
        subject: `Prenotazione #${id} aggiornata`,
        text: testo
      });
    }
    res.send('Stato aggiornato ✅');
  } catch (err) {
    console.error('❌ Errore aggiornamento stato:', err);
    res.status(500).send('Errore aggiornamento');
  }
});

app.post('/impianto/aggiorna-trasporto', async (req, res) => {
  if (!req.session.admin) return res.status(403).send('Accesso negato');

  const { id, nuovo_stato, nota } = req.body;
  try {
    await db.query('UPDATE richieste_trasporto SET stato = $1, nota = $2 WHERE id = $3', [nuovo_stato, nota, id]);

    // mail al cliente
    const { rows } = await db.query(
      `SELECT u.email, r.data_trasporto
       FROM richieste_trasporto r
       JOIN utenti u ON r.cliente_id = u.id
       WHERE r.id = $1`,
      [id]
    );
    if (rows.length > 0) {
      const email = rows[0].email;
      const testo = `Gentile cliente,
La tua richiesta di trasporto n°${id} del ${rows[0].data_trasporto} è stata aggiornata a: ${nuovo_stato.toUpperCase()}
${nota ? '\nNota dell’impianto:\n' + nota : ''}

Cordiali saluti,
Impianto`;
      await transporter.sendMail({
        from: `"Ecodrin" <${process.env.EMAIL_USER || 'no-reply@ecodrin.local'}>`,
        to: email,
        subject: `Richiesta Trasporto #${id} aggiornata`,
        text: testo
      });
    }
    res.send('Stato trasporto aggiornato ✅');
  } catch (err) {
    console.error('❌ Errore aggiornamento trasporto:', err);
    res.status(500).send('Errore aggiornamento');
  }
});

// ----------- DOWNLOAD CERTIFICATI -----------
function safeJoinUpload(filename) {
  // impedisce traversal; accetta solo basename
  const safeName = path.basename(filename);
  return path.join(__dirname, 'uploads', safeName);
}

app.get('/impianto/download-certificato/:filename', (req, res) => {
  if (!req.session.admin) return res.status(403).send('Non autorizzato');
  const filePath = safeJoinUpload(req.params.filename);
  if (fs.existsSync(filePath)) return res.download(filePath);
  return res.status(404).send('File non trovato');
});

app.get('/cliente/download-certificato/:filename', (req, res) => {
  if (!req.session.utente) return res.status(403).send('Non autorizzato');
  const filePath = safeJoinUpload(req.params.filename);
  if (fs.existsSync(filePath)) return res.download(filePath);
  return res.status(404).send('File non trovato');
});

// ----------- UTENTI (pannello impianto) -----------
app.get('/check-utenti', async (req, res) => {
  if (!req.session.admin) return res.status(403).send('Accesso negato');
  try {
    const { rows } = await db.query(`
      SELECT id, username, email, ruolo, COALESCE(bloccato, false) AS bloccato
      FROM utenti
      ORDER BY id
    `);
    res.json(rows);
  } catch (err) {
    console.error('❌ Errore caricamento utenti:', err);
    res.status(500).send('Errore caricamento utenti');
  }
});

app.post('/admin/blocco-utente', async (req, res) => {
  if (!req.session.admin) return res.status(403).send('Accesso negato');
  const { id, azione } = req.body; // 'blocca' o 'sblocca'
  try {
    const valore = azione === 'blocca';
    await db.query('UPDATE utenti SET bloccato = $1 WHERE id = $2', [valore, id]);
    res.send(valore ? 'Utente bloccato' : 'Utente sbloccato');
  } catch (err) {
    console.error('❌ Errore blocco/sblocco utente:', err);
    res.status(500).send('Errore in gestione utente');
  }
});

app.post('/admin/elimina-utente', async (req, res) => {
  if (!req.session.admin) return res.status(403).send('Accesso negato');
  const { id } = req.body;
  try {
    await db.query('DELETE FROM utenti WHERE id = $1', [id]);
    res.send('Utente eliminato');
  } catch (err) {
    console.error('❌ Errore eliminazione utente:', err);
    res.status(500).send('Errore eliminazione utente');
  }
});

// ------------------ Error handlers ------------------
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'CSRF token mancante o non valido' });
  }
  if (err.message && /Tipo file non consentito/.test(err.message)) {
    return res.status(400).send(err.message);
  }
  console.error(err);
  res.status(500).json({ error: 'Errore server' });
});

// ------------------ Avvio ------------------
app.listen(PORT, () => {
  console.log(`🚀 Server avviato in ambiente: ${process.env.NODE_ENV || 'sviluppo'}`);
  console.log(`🌐 In ascolto sulla porta: ${PORT}`);
});

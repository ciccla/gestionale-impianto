require('dotenv').config();
const { Pool } = require('pg');
const bcrypt = require('bcrypt');

const isProduction = process.env.NODE_ENV === 'production';

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: isProduction ? { rejectUnauthorized: false } : false,
    })
  : new Pool({
      host: process.env.PG_HOST,
      port: Number(process.env.PG_PORT || 5432),
      database: process.env.PG_DATABASE,
      user: process.env.PG_USER,
      password: process.env.PG_PASSWORD,
      ssl: false,
    });

console.log('📦 Connessione PostgreSQL…');
console.log(`🔗 Host: ${process.env.PG_HOST || '[DATABASE_URL]'}`);
console.log(`🗄️ DB: ${process.env.PG_DATABASE || '[DATABASE_URL]'}`);
console.log(`👤 User: ${process.env.PG_USER || '[DATABASE_URL]'}`);

async function creaTabelle() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS utenti (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE,
      password TEXT,
      email TEXT UNIQUE,
      ruolo TEXT CHECK(ruolo IN ('cliente','admin')) NOT NULL,
      bloccato BOOLEAN DEFAULT FALSE
    );

    CREATE TABLE IF NOT EXISTS prenotazioni (
      id SERIAL PRIMARY KEY,
      cliente_id INTEGER REFERENCES utenti(id),
      ragione_sociale TEXT,
      produttore TEXT,
      codice_cer TEXT,
      caratteristiche_pericolo TEXT,
      tipo_imballo TEXT,
      stato_fisico TEXT,
      certificato_analitico TEXT,
      quantita REAL,
      giorno_conferimento TEXT,
      stato TEXT DEFAULT 'in attesa'
    );

    CREATE TABLE IF NOT EXISTS richieste_trasporto (
      id SERIAL PRIMARY KEY,
      cliente_id INTEGER REFERENCES utenti(id),
      richiedente TEXT NOT NULL,
      produttore TEXT NOT NULL,
      codice_cer TEXT NOT NULL,
      tipo_automezzo TEXT NOT NULL,
      data_trasporto TEXT NOT NULL,
      orario_preferito TEXT NOT NULL,
      numero_referente TEXT NOT NULL,
      prezzo_pattuito REAL NOT NULL,
      stato TEXT DEFAULT 'in attesa',
      nota TEXT
    );

    CREATE TABLE IF NOT EXISTS notifiche_admin (
      id SERIAL PRIMARY KEY,
      tipo TEXT NOT NULL,
      riferimento_id INTEGER NOT NULL,
      messaggio TEXT NOT NULL,
      letto BOOLEAN DEFAULT FALSE,
      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS messaggi (
      id SERIAL PRIMARY KEY,
      prenotazione_id INTEGER REFERENCES prenotazioni(id) ON DELETE CASCADE,
      mittente TEXT NOT NULL,
      messaggio TEXT NOT NULL,
      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS messaggi_trasporto (
      id SERIAL PRIMARY KEY,
      trasporto_id INTEGER REFERENCES richieste_trasporto(id) ON DELETE CASCADE,
      mittente TEXT NOT NULL,
      messaggio TEXT NOT NULL,
      timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await pool.query(`CREATE INDEX IF NOT EXISTS idx_prenotazioni_cliente ON prenotazioni(cliente_id);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_msg_prenotazione ON messaggi(prenotazione_id, timestamp);`);
  await pool.query(`CREATE INDEX IF NOT EXISTS idx_msg_trasporto ON messaggi_trasporto(trasporto_id, timestamp);`);

  console.log('✅ Schema PostgreSQL creato/aggiornato');
}

async function creaAdminDefault() {
  const adminEmail = process.env.DEFAULT_ADMIN_EMAIL || 'admin@example.com';
  const adminUser = process.env.DEFAULT_ADMIN_USERNAME || 'admin';
  const adminPassword = process.env.DEFAULT_ADMIN_PASSWORD;

  if (!adminPassword) {
    console.log('ℹ️ DEFAULT_ADMIN_PASSWORD non impostata: admin automatico non creato');
    return;
  }

  const { rows } = await pool.query(
    'SELECT 1 FROM utenti WHERE email = $1 OR username = $2 LIMIT 1',
    [adminEmail, adminUser]
  );

  if (rows.length) {
    console.log('ℹ️ Admin già presente');
    return;
  }

  const passwordHash = await bcrypt.hash(adminPassword, 12);

  await pool.query(
    `INSERT INTO utenti (username, password, email, ruolo)
     VALUES ($1, $2, $3, $4)`,
    [adminUser, passwordHash, adminEmail, 'admin']
  );

  console.log(`✅ Admin creato (${adminUser} / ${adminEmail})`);
}

(async () => {
  try {
    await creaTabelle();
    await creaAdminDefault();
  } catch (err) {
    console.error('❌ Errore inizializzazione DB:', err.stack || err);
  }
})();

module.exports = {
  query: (text, params) => pool.query(text, params),
  pool,
};
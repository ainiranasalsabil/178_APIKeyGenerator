const express = require('express');
const crypto = require('crypto');
const path = require('path');
const mysql = require('mysql2');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ===============================
// 🔗 KONFIGURASI DATABASE
// ===============================
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Asdfghjkl123*',
  database: 'api_key_db',
  port: 3309,
});

// Cek koneksi ke MySQL
db.connect((err) => {
  if (err) {
    console.error('❌ Koneksi ke MySQL gagal:', err);
  } else {
    console.log('✅ Terkoneksi ke MySQL (api_key_db)');
  }
});

// ===============================
// 🔑 FUNGSI GENERATE API KEY
// ===============================
function generateApiKey() {
  const randomBytes = crypto.randomBytes(8).toString('hex'); // 16 karakter hex
  return `sk-sm-v1-${randomBytes}`;
}

// ===============================
// 📦 ENDPOINT BUAT API KEY
// ===============================
app.post('/create', (req, res) => {
  const apiKey = generateApiKey();

  db.query(
    'INSERT INTO api_keys (api_key, created_at) VALUES (?,NOW())',
    [apiKey],
    (err, result) => {
      if (err) {
        console.error('❌ Gagal menyimpan API key:', err);
        return res.status(500).json({ success: false, message: 'Gagal menyimpan API key' });
      }

      console.log(`✅ API Key baru disimpan ke DB: ${apiKey}`);
      res.status(200).json({ success: true, apiKey });
    }
  );
});



// ===============================
// 🔍 ENDPOINT CEK API KEY
// ===============================
app.post('/cekapi', (req, res) => {
  const { apiKey } = req.body;

  if (!apiKey) {
    return res.status(400).json({ success: false, message: 'API key tidak boleh kosong!' });
  }

  db.query('SELECT * FROM api_keys WHERE api_key = ?', [apiKey], (err, results) => {
    if (err) {
      console.error('❌ Error saat cek API key:', err);
      return res.status(500).json({ success: false, message: 'Kesalahan server' });
    }

    if (results.length > 0) {
      res.json({ success: true, message: 'API key valid ✅' });
    } else {
      res.status(401).json({ success: false, message: 'API key tidak valid ❌' });
    }
  });
});

// ===============================
// 🚀 JALANKAN SERVER
// ===============================
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server berjalan di http://localhost:${PORT}`);
});
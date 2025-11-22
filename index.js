// server.js (ganti file lama dengan ini)
const express = require("express");
const crypto = require("crypto");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

// ---------------------------
// Database connection (sesuaikan jika perlu)
// ---------------------------
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "Asdfghjkl123*",
  database: "api_key_db",
  port: 3309,
});

db.connect((err) => {
  if (err) {
    console.error("❌ MySQL gagal:", err);
    process.exit(1);
  } else {
    console.log("✅ MySQL Connected (api_key_db)");
  }
});

// ---------------------------
// Konfigurasi (tanpa .env)
// ---------------------------
const JWT_SECRET = "INI_SECRET_JWT_FIX"; // ganti kalau perlu

// ---------------------------
// Utils
// ---------------------------
function generateApiKey() {
  return "sk-sm-v1-" + crypto.randomBytes(16).toString("hex");
}

function sendServerError(res, err) {
  console.error(err);
  return res.status(500).json({ success: false, message: "Server error" });
}

// ---------------------------
// MIDDLEWARE: admin auth
// ---------------------------
function adminAuth(req, res, next) {
  const auth = req.headers["authorization"] || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : auth;

  if (!token) return res.status(401).json({ success: false, message: "Token dibutuhkan" });

  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) return res.status(403).json({ success: false, message: "Token tidak valid" });
    req.admin = payload;
    next();
  });
}

// ---------------------------
// MIDDLEWARE: verify API key (pakai di route user.create jika mau header x-api-key)
// ---------------------------
async function verifyApiKeyMiddleware(req, res, next) {
  try {
    const apiKeyFromHeader = req.headers["x-api-key"] || req.body.api_key || req.query.api_key;
    if (!apiKeyFromHeader) return res.status(400).json({ success: false, message: "API key required" });

    const [rows] = await new Promise((resolve, reject) =>
      db.query("SELECT * FROM api_keys WHERE api_key = ?", [apiKeyFromHeader], (err, r) => (err ? reject(err) : resolve([r])))
    );

    if (!rows || rows.length === 0) return res.status(401).json({ success: false, message: "Invalid API key" });

    const key = rows[0];
    // cek expired_at & status
    const now = new Date();
    const expiredAt = key.expired_at ? new Date(key.expired_at) : null;
    const computedStatus = expiredAt && expiredAt < now ? "off" : "on";

    if (computedStatus !== key.status) {
      // update DB agar sinkron
      await new Promise((resolve, reject) =>
        db.query("UPDATE api_keys SET status = ? WHERE id = ?", [computedStatus, key.id], (err) => (err ? reject(err) : resolve()))
      );
      key.status = computedStatus;
    }

    if (key.status === "off") return res.status(403).json({ success: false, message: "API key expired or disabled" });

    req.apiKeyRecord = key;
    next();
  } catch (err) {
    return sendServerError(res, err);
  }
}

// ---------------------------
// ROUTES
// ---------------------------

// 1) Generate API key (frontend calls)
// - menyimpan api_key, created_at, expired_at = NOW() + 1 MONTH, status = 'on'
app.post("/api-keys/generate", (req, res) => {
  try {
    const apiKey = generateApiKey();

    // Simpan dengan expired 1 month
    db.query(
      "INSERT INTO api_keys (api_key, created_at, expired_at, status) VALUES (?, NOW(), DATE_ADD(NOW(), INTERVAL 1 MONTH), 'on')",
      [apiKey],
      (err, result) => {
        if (err) return sendServerError(res, err);

        // Ambil record lengkap untuk response
        db.query("SELECT * FROM api_keys WHERE id = ?", [result.insertId], (err2, rows) => {
          if (err2) return sendServerError(res, err2);
          return res.status(201).json({ success: true, apiKey: rows[0] });
        });
      }
    );
  } catch (err) {
    return sendServerError(res, err);
  }
});

// 2) Public cek api key (bisa dipakai frontend untuk validasi)
app.post("/api-keys/check", (req, res) => {
  const { api_key } = req.body;
  if (!api_key) return res.status(400).json({ success: false, message: "api_key required in body" });

  db.query("SELECT * FROM api_keys WHERE api_key = ?", [api_key], (err, rows) => {
    if (err) return sendServerError(res, err);
    if (!rows.length) return res.status(404).json({ success: false, message: "API key not found" });

    const key = rows[0];
    const now = new Date();
    const expiredAt = key.expired_at ? new Date(key.expired_at) : null;
    const status = expiredAt && expiredAt < now ? "off" : "on";

    // sync status if mismatch
    if (status !== key.status) {
      db.query("UPDATE api_keys SET status = ? WHERE id = ?", [status, key.id], (err2) => {
        if (err2) console.error("Failed to update status sync:", err2);
      });
      key.status = status;
    }

    return res.json({ success: true, key: { api_key: key.api_key, expired_at: key.expired_at, status: key.status } });
  });
});

// 3) Create user (frontend)
// - menerima first_name, last_name, email_address, api_key (body)
// - validasi api_key, cek belum dipakai (one-to-one), cek expired/status
app.post("/user/create", verifyApiKeyMiddleware, (req, res) => {
  const { first_name, last_name, email_address } = req.body;
  const apiKeyRecord = req.apiKeyRecord;

  if (!first_name || !last_name || !email_address)
    return res.status(400).json({ success: false, message: "first_name, last_name, email_address required" });

  // Pastikan api_key belum dipakai (users.api_key_id unique)
  db.query("SELECT id FROM users WHERE api_key_id = ?", [apiKeyRecord.id], (err, usedRows) => {
    if (err) return sendServerError(res, err);
    if (usedRows.length) return res.status(409).json({ success: false, message: "API key already used" });

    db.query(
      "INSERT INTO users (first_name, last_name, email_address, api_key_id, created_at) VALUES (?,?,?,?,NOW())",
      [first_name, last_name, email_address, apiKeyRecord.id],
      (err2) => {
        if (err2) return sendServerError(res, err2);
        return res.status(201).json({ success: true, message: "User created successfully" });
      }
    );
  });
});

// 4) ADMIN REGISTER
app.post("/admin/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: "email & password required" });

    const hashed = await bcrypt.hash(password, 10);
    db.query("INSERT INTO admins (email, password, created_at) VALUES (?, ?, NOW())", [email, hashed], (err) => {
      if (err) {
        console.error(err);
        // kemungkinan duplicate, kirim pesan generik
        return res.status(400).json({ success: false, message: "Gagal register (kemungkinan email sudah ada)" });
      }
      return res.json({ success: true, message: "Admin registered" });
    });
  } catch (err) {
    return sendServerError(res, err);
  }
});

// 5) ADMIN LOGIN
app.post("/admin/login", (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: "email & password required" });

    db.query("SELECT * FROM admins WHERE email = ?", [email], async (err, rows) => {
      if (err) return sendServerError(res, err);
      if (!rows.length) return res.status(401).json({ success: false, message: "Admin not found" });

      const admin = rows[0];
      const match = await bcrypt.compare(password, admin.password);
      if (!match) return res.status(401).json({ success: false, message: "Wrong password" });

      const token = jwt.sign({ id: admin.id, email: admin.email }, JWT_SECRET, { expiresIn: "1d" });
      return res.json({ success: true, token });
    });
  } catch (err) {
    return sendServerError(res, err);
  }
});

// 6) ADMIN: list api_keys & users (dashboard) — protected
app.get("/admin/data", adminAuth, (req, res) => {
  // ambil api_keys + left join users to show owner
  const sql =
    `SELECT a.id AS api_id, a.api_key, a.created_at AS api_created_at, a.expired_at, a.status AS api_status,
            u.id AS user_id, u.first_name, u.last_name, u.email_address
     FROM api_keys a
     LEFT JOIN users u ON u.api_key_id = a.id
     ORDER BY a.created_at DESC`;

  db.query(sql, (err, rows) => {
    if (err) return sendServerError(res, err);

    // Pastikan status sinkron (expired_at check)
    const now = new Date();
    const updates = [];

    rows.forEach((r) => {
      if (r.expired_at) {
        const expiredAt = new Date(r.expired_at);
        const computed = expiredAt < now ? "off" : "on";
        if (r.api_status !== computed) {
          updates.push({ id: r.api_id, status: computed });
        }
      }
    });

    // Jika ada update status, jalankan update batch lalu kirim data terbarunya
    if (updates.length > 0) {
      const tasks = updates.map(u => new Promise((resolve, reject) =>
        db.query("UPDATE api_keys SET status = ? WHERE id = ?", [u.status, u.id], (e) => (e ? reject(e) : resolve()))
      ));

      Promise.all(tasks)
        .then(() => {
          // reload rows
          db.query(sql, (err2, latestRows) => {
            if (err2) return sendServerError(res, err2);
            res.json({ success: true, data: latestRows });
          });
        })
        .catch(e => sendServerError(res, e));
    } else {
      res.json({ success: true, data: rows });
    }
  });
});

// 7) Optional: admin can deactivate an api key
app.post("/admin/apikeys/:id/toggle", adminAuth, (req, res) => {
  const id = req.params.id;
  const { status } = req.body; // 'on' or 'off'
  if (!["on", "off"].includes(status)) return res.status(400).json({ success: false, message: "status must be on/off" });

  db.query("UPDATE api_keys SET status = ? WHERE id = ?", [status, id], (err) => {
    if (err) return sendServerError(res, err);
    res.json({ success: true, message: `API key ${status}` });
  });
});

// ---------------------------
// Start server
// ---------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});

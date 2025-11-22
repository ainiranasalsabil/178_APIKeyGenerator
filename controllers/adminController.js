const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2");

// Connect DB sama seperti server.js
const db = require("../api_key_db");
const JWT_SECRET = "INI_SECRET_JWT_FIX";

// REGISTER
exports.register = async (req, res) => {
  const { email, password } = req.body;

  try {
    const hashed = await bcrypt.hash(password, 10);

    db.query(
      "INSERT INTO admins (email, password, created_at) VALUES (?, ?, NOW())",
      [email, hashed],
      (err) => {
        if (err) {
          return res.status(400).json({
            success: false,
            message: "Gagal register (email mungkin sudah ada)",
          });
        }
        res.json({ success: true, message: "Admin registered" });
      }
    );
  } catch (err) {
    res.status(500).json({ success: false });
  }
};

// LOGIN
exports.login = (req, res) => {
  const { email, password } = req.body;

  db.query("SELECT * FROM admins WHERE email = ?", [email], async (err, rows) => {
    if (!rows.length)
      return res.status(401).json({ success: false, message: "Admin tidak ditemukan" });

    const admin = rows[0];
    const match = await bcrypt.compare(password, admin.password);

    if (!match) return res.status(401).json({ success: false, message: "Password salah" });

    const token = jwt.sign({ id: admin.id, email: admin.email }, JWT_SECRET, {
      expiresIn: "1d",
    });

    res.json({ success: true, token });
  });
};

// GET DASHBOARD DATA
exports.getDashboardData = (req, res) => {
  const sql = `
    SELECT a.id AS api_id, a.api_key, a.created_at AS api_created_at, a.expired_at, a.status AS api_status,
           u.id AS user_id, u.first_name, u.last_name, u.email_address
    FROM api_keys a
    LEFT JOIN users u ON u.api_key_id = a.id
    ORDER BY a.created_at DESC
  `;

  db.query(sql, (err, rows) => {
    if (err) return res.status(500).json({ success: false });

    res.json({ success: true, data: rows });
  });
};

// TOGGLE ON/OFF
exports.toggleApiKey = (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  db.query("UPDATE api_keys SET status = ? WHERE id = ?", [status, id], (err) => {
    if (err) return res.status(500).json({ success: false });

    res.json({ success: true, message: `API key ${status}` });
  });
};

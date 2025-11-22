const crypto = require("crypto");
const db = require("../api_key_db");

function generateApiKey() {
  return "sk-sm-v1-" + crypto.randomBytes(16).toString("hex");
}

exports.generate = (req, res) => {
  const apiKey = generateApiKey();

  db.query(
    "INSERT INTO api_keys (api_key, created_at, expired_at, status) VALUES (?, NOW(), DATE_ADD(NOW(), INTERVAL 1 MONTH), 'on')",
    [apiKey],
    (err, result) => {
      if (err) return res.status(500).json({ success: false });

      db.query("SELECT * FROM api_keys WHERE id = ?", [result.insertId], (err2, rows) => {
        res.json({ success: true, apiKey: rows[0] });
      });
    }
  );
};

exports.check = (req, res) => {
  const { api_key } = req.body;

  db.query("SELECT * FROM api_keys WHERE api_key = ?", [api_key], (err, rows) => {
    if (!rows.length)
      return res.status(404).json({ success: false, message: "API key tidak ditemukan" });

    const key = rows[0];
    res.json({ success: true, key });
  });
};

const db = require("../api_key_db");

exports.createUser = (req, res) => {
  const { first_name, last_name, email_address } = req.body;
  const apiKeyRecord = req.apiKeyRecord;

  db.query(
    "INSERT INTO users (first_name, last_name, email_address, api_key_id, created_at) VALUES (?,?,?,?,NOW())",
    [first_name, last_name, email_address, apiKeyRecord.id],
    (err) => {
      if (err) return res.status(500).json({ success: false });

      res.json({ success: true, message: "User created" });
    }
  );
};

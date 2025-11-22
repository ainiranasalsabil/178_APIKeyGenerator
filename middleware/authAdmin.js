const jwt = require("jsonwebtoken");
const JWT_SECRET = "INI_SECRET_JWT_FIX";

module.exports = function (req, res, next) {
  const token = req.headers["authorization"]?.replace("Bearer ", "");

  if (!token)
    return res.status(401).json({ success: false, message: "Token dibutuhkan" });

  jwt.verify(token, JWT_SECRET, (err, data) => {
    if (err)
      return res.status(403).json({ success: false, message: "Token tidak valid" });

    req.admin = data;
    next();
  });
};

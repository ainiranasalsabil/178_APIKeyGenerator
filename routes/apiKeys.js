const express = require("express");
const router = express.Router();
const apiKeyController = require("../controllers/apiKeyController");

// Generate API Key
router.post("/create", apiKeyController.createApiKey);

// Cek API Key
router.post("/cekapi", apiKeyController.checkApiKey);

module.exports = router;

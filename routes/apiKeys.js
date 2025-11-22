const express = require("express");
const router = express.Router();
const apiKeyController = require("../controllers/apiKeyController");

// Generate API Key (for public frontend)
router.post("/generate", apiKeyController.generate);

// Check API Key validity
router.post("/check", apiKeyController.check);

module.exports = router;

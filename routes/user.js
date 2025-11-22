const express = require("express");
const router = express.Router();
const userController = require("../controllers/userController");
const verifyApiKey = require("../middleware/verifyApiKey");

// Create user (require API key)
router.post("/create", verifyApiKey, userController.createUser);

module.exports = router;

const express = require("express");
const router = express.Router();
const adminController = require("../controllers/adminController");
const adminAuth = require("../middleware/authAdmin");

// REGISTER
router.post("/register", adminController.register);

// LOGIN
router.post("/login", adminController.login);

// GET DASHBOARD DATA (PROTECTED)
router.get("/data", adminAuth, adminController.getDashboardData);

// TOGGLE API KEY STATUS (PROTECTED)
router.post("/apikeys/:id/toggle", adminAuth, adminController.toggleApiKey);

module.exports = router;

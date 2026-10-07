const express = require("express");
const router = express.Router();

const {
  scanUrl,
  scanUpi,
  scanUrlRateLimit,
} = require("../controllers/scan.controller");

router.post("/url", scanUrlRateLimit, scanUrl);
router.post("/upi", scanUpi);

module.exports = router;

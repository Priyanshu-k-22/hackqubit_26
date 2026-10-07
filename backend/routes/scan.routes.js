const express = require("express");
const router = express.Router();

const {
  scanUrl,
  scanUpi,
  scanQr,
  scanUrlRateLimit,
} = require("../controllers/scan.controller");

router.post("/url", scanUrlRateLimit, scanUrl);
router.post("/upi", scanUpi);
router.post("/qr", scanQr);

module.exports = router;

const express = require("express");

const router = express.Router();

const {
  scanUrl,
  scanUpi,
  scanQr,
  scanUrlRateLimit,
} = require("../controllers/scan.controller");

// Test route
router.get("/test", (req, res) => {
  res.json({
    success: true,
    message: "Scan routes are working",
  });
});

// URL
router.post(
  "/url",
  scanUrlRateLimit,
  scanUrl
);

// UPI
router.post(
  "/upi",
  scanUpi
);

// QR
router.post(
  "/qr",
  scanQr
);

module.exports = router;
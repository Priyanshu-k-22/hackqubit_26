const { analyzeUrl } = require("../services/urlAnalyzer");
const { analyzeUpi } = require("../services/upiAnalyzer");
const scanQr = async (req, res) => {
  const payload = req.body?.payload;
  if (typeof payload !== "string" || !payload.trim()) {
    return res.status(400).json({ message: "QR payload is required and must be a string" });
  }

  try {
    const { analyzeQrPayload } = await import("../../shared/qrAnalyzer.mjs");
    return res.status(201).json(analyzeQrPayload(payload));
  } catch (error) {
    console.error("QR scan error:", error);
    return res.status(500).json({ message: "QR scanning failed" });
  }
};

const scanUrl = (req, res) => {
  try {
    const url = req.body?.url;

    if (typeof url !== "string" || !url.trim()) {
      return res.status(400).json({
        message: "URL is required and must be a string",
      });
    }

    const result = analyzeUrl(url);
    result.paymentAssessment = {
      outcome: result.status === "AUTHORIZED" ? "authorized" : "unverified",
      message: result.reason,
    };
    return res.status(201).json(result);
  } catch (error) {
    if (error.statusCode === 400) {
      return res.status(400).json({ message: error.message });
    }
    console.error("URL scan error:", error);

    return res.status(500).json({
      message: "URL scanning failed",
    });
  }
};

const scanUpi = (req, res) => {
  try {
    const { upi } = req.body;

    if (!upi) {
      return res.status(400).json({
        message: "UPI ID is required",
      });
    }

    const result = analyzeUpi(upi);

    // Return result directly
    res.json(result);
  } catch (error) {
    console.error("UPI scan error:", error);

    res.status(500).json({
      message: "UPI scanning failed",
    });
  }
};

const urlScanWindows = new Map();
const scanUrlRateLimit = (req, res, next) => {
  const now = Date.now();
  const key = req.ip || req.socket.remoteAddress || "unknown";
  const window = urlScanWindows.get(key);
  if (!window || now - window.startedAt >= 60_000) {
    if (urlScanWindows.size >= 10_000) {
      for (const [client, entry] of urlScanWindows) {
        if (now - entry.startedAt >= 60_000) urlScanWindows.delete(client);
      }
      if (urlScanWindows.size >= 10_000) urlScanWindows.delete(urlScanWindows.keys().next().value);
    }
    urlScanWindows.set(key, { startedAt: now, count: 1 });
    return next();
  }
  if (window.count >= 30) {
    return res.status(429).json({ message: "URL scan limit reached. Try again in one minute." });
  }
  window.count += 1;
  return next();
};

module.exports = {
  scanUrl,
  scanUpi,
  scanQr,
  scanUrlRateLimit,
};

const {
  analyzeUrl,
} = require("../services/urlAnalyzer");

const {
  analyzeUpi,
} = require("../services/upiAnalyzer");

const {
  recordThreat,
} = require("../services/threatStore");

// ==================================================
// QR SCAN
// ==================================================

const scanQr = async (req, res) => {
  const payload = req.body?.payload;

  if (
    typeof payload !== "string" ||
    !payload.trim()
  ) {
    return res.status(400).json({
      message:
        "QR payload is required and must be a string",
    });
  }

  try {
    const {
      analyzeQrPayload,
    } = await import(
      "../../shared/qrAnalyzer.mjs"
    );

    const result =
      analyzeQrPayload(payload);

    // Store QR scan
    const threat = await recordThreat(
      payload,
      {
        type: "QR",

        input: payload,

        target:
          result.target ||
          result.merchant ||
          payload,

        domain:
          result.domain || "",

        score:
          Number(result.score) || 0,

        riskLevel:
          result.riskLevel ||
          result.risk ||
          "LOW",

        status:
          result.status ||
          "UNVERIFIED",

        reason:
          result.reason ||
          "QR payload analyzed",

        brand:
          result.brand || "",

        campaign:
          result.campaign || "",

        evidence:
          Array.isArray(result.evidence)
            ? result.evidence
            : [],

        breakdown:
          result.breakdown || {},

        metadata: {
          source: "qr",
        },

        analysis: result,
      }
    );

    return res.status(201).json({
      ...result,

      threatId: threat.id,
      reportId: threat.reportId,

      reports: threat.reports,
      users: threat.users,

      first: threat.first,
      last: threat.last,

      campaign: threat.campaign,
    });
  } catch (error) {
    console.error(
      "QR scan error:",
      error
    );

    return res.status(500).json({
      message: "QR scanning failed",
      error:
        process.env.NODE_ENV === "development"
          ? error.message
          : undefined,
    });
  }
};

// ==================================================
// URL SCAN
// ==================================================

const scanUrl = async (req, res) => {
  try {
    const url = req.body?.url;

    if (
      typeof url !== "string" ||
      !url.trim()
    ) {
      return res.status(400).json({
        message:
          "URL is required and must be a string",
      });
    }

    const result =
      await analyzeUrl(url);

    result.paymentAssessment = {
      outcome:
        result.status === "AUTHORIZED"
          ? "authorized"
          : "unverified",

      message: result.reason,
    };

    return res.status(201).json(result);
  } catch (error) {
  console.error("=================================");
  console.error("URL SCAN ERROR");
  console.error("message:", error.message);
  console.error("name:", error.name);
  console.error("stack:", error.stack);
  console.error("full error:", error);
  console.error("=================================");

  return res.status(500).json({
    success: false,
    message: "URL scanning failed",
    error: error.message,
    name: error.name,
    stack: error.stack,
  });
}
};

// ==================================================
// UPI SCAN
// ==================================================

const scanUpi = async (req, res) => {
  try {
    const { upi } = req.body;

    if (
      typeof upi !== "string" ||
      !upi.trim()
    ) {
      return res.status(400).json({
        message:
          "UPI ID is required",
      });
    }

    const result =
      await analyzeUpi(upi);

    return res.status(201).json(result);
  } catch (error) {
    console.error(
      "UPI scan error:",
      error
    );

    return res.status(500).json({
      message: "UPI scanning failed",
      error:
        process.env.NODE_ENV === "development"
          ? error.message
          : undefined,
    });
  }
};

// ==================================================
// URL RATE LIMITER
// ==================================================

const urlScanWindows =
  new Map();

const scanUrlRateLimit = (
  req,
  res,
  next
) => {
  const now = Date.now();

  const key =
    req.ip ||
    req.socket.remoteAddress ||
    "unknown";

  const window =
    urlScanWindows.get(key);

  // New window
  if (
    !window ||
    now - window.startedAt >= 60_000
  ) {
    if (
      urlScanWindows.size >= 10_000
    ) {
      for (
        const [
          client,
          entry,
        ] of urlScanWindows
      ) {
        if (
          now - entry.startedAt >=
          60_000
        ) {
          urlScanWindows.delete(
            client
          );
        }
      }

      if (
        urlScanWindows.size >=
        10_000
      ) {
        const firstKey =
          urlScanWindows.keys().next()
            .value;

        urlScanWindows.delete(
          firstKey
        );
      }
    }

    urlScanWindows.set(
      key,
      {
        startedAt: now,
        count: 1,
      }
    );

    return next();
  }

  // Limit = 30 requests/minute
  if (window.count >= 30) {
    return res.status(429).json({
      message:
        "URL scan limit reached. Try again in one minute.",
    });
  }

  window.count += 1;

  return next();
};

// ==================================================
// EXPORTS
// ==================================================

module.exports = {
  scanUrl,
  scanUpi,
  scanQr,
  scanUrlRateLimit,
};
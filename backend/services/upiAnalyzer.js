const { recordThreat } = require("./threatStore");

const analyzeUpi = (upi) => {
  const value = upi.trim().toLowerCase();

  let score = 0;
  const evidence = [];

  // -------------------------
  // 1. Validate UPI format
  // -------------------------
  const upiPattern = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+$/;

  if (!upiPattern.test(value)) {
    score += 50;
    evidence.push("Invalid UPI ID format");
  }

  // -------------------------
  // 2. Suspicious keywords
  // -------------------------
  const suspiciousKeywords = [
    "refund",
    "reward",
    "cashback",
    "claim",
    "winner",
    "prize",
    "support",
    "verify",
    "secure",
    "payment",
    "kyc",
    "bank",
  ];

  const foundKeywords = suspiciousKeywords.filter((keyword) =>
    value.includes(keyword)
  );

  if (foundKeywords.length > 0) {
    score += Math.min(foundKeywords.length * 15, 45);

    evidence.push(
      `Suspicious keywords detected: ${foundKeywords.join(", ")}`
    );
  }

  // -------------------------
  // 3. Username length
  // -------------------------
  const username = value.split("@")[0];

  if (username.length > 30) {
    score += 20;
    evidence.push("Unusually long UPI username");
  }

  // -------------------------
  // 4. Suspicious UPI handles
  // -------------------------
  const suspiciousHandles = [
    "support",
    "verify",
    "refund",
    "reward",
    "cashback",
    "claim",
  ];

  const handle = value.includes("@")
    ? value.split("@")[1]
    : "";

  const suspiciousHandle = suspiciousHandles.some((word) =>
    username.includes(word)
  );

  if (suspiciousHandle) {
    score += 20;
    evidence.push("UPI username resembles a support or payment-related account");
  }

  // Keep score within 0–100
  score = Math.min(score, 100);

  // -------------------------
  // Risk level
  // -------------------------
  let riskLevel = "LOW";

  if (score >= 70) {
    riskLevel = "HIGH";
  } else if (score >= 40) {
    riskLevel = "MEDIUM";
  }

  const today = new Date().toISOString().split("T")[0];

  if (evidence.length === 0) {
    evidence.push("No major suspicious indicators detected");
  }


  const intelligence = recordThreat(value, {
  status:
    riskLevel === "HIGH"
      ? "Under Review"
      : "Analyzed",
});

  // -------------------------
  // Frontend-compatible result
  // -------------------------
  return {
    id: `TH-${Date.now()}`,

    kind: "upi",

    input: value,

    score,

    breakdown: {
      "UPI Format": upiPattern.test(value) ? 0 : 80,
      "Suspicious Keywords":
        foundKeywords.length > 0
          ? Math.min(foundKeywords.length * 20, 100)
          : 0,
      "Username Risk": username.length > 30 ? 80 : 0,
      "Handle Risk": suspiciousHandle ? 80 : 0,
    },

    evidence,

    domain: handle || "-",

    protocol: "HTTPS",

    upi: value,

    payee: "-",

    redirects: 0,

    brand: "Unknown",

   reports: intelligence.reports,
users: intelligence.users,

first: intelligence.first,
last: intelligence.last,

campaign: intelligence.campaign,

status: intelligence.status,

    demo: false,
  };
};

module.exports = {
  analyzeUpi,
};
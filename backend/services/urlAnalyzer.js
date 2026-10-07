const { recordThreat } = require("./threatStore");
const { URL } = require("url");
const { calculateRisk } = require("./riskEngine");

const analyzeUrl = (inputUrl) => {
  const value = inputUrl.trim();

  let parsedUrl;

  try {
    parsedUrl = new URL(
      value.startsWith("http://") || value.startsWith("https://")
        ? value
        : `https://${value}`
    );
  } catch (error) {
    return {
      id: `TH-${Date.now()}`,
      kind: "url",
      input: value,
      score: 100,
      riskLevel: "HIGH",
      breakdown: {
        "HTTPS Security": 100,
        "URL Length": 100,
        "IP Address": 0,
        "Suspicious Keywords": 100,
        "Subdomain Structure": 100,
      },
      evidence: ["Invalid URL format"],
      domain: "-",
      protocol: "-",
      upi: "-",
      payee: "-",
      redirects: 0,
      brand: "Unknown",
      reports: 0,
      users: 0,
      first: new Date().toISOString().split("T")[0],
      last: new Date().toISOString().split("T")[0],
      campaign: "CAM-NEW",
      status: "Under Review",
      demo: false,
    };
  }

  const domain = parsedUrl.hostname;
  const protocol = parsedUrl.protocol.replace(":", "");

  let httpsRisk = 0;
  let lengthRisk = 0;
  let ipRisk = 0;
  let keywordRisk = 0;
  let subdomainRisk = 0;

  const evidence = [];

  // 1. HTTPS
  if (protocol !== "https") {
    httpsRisk = 80;
    evidence.push("Website does not use HTTPS");
  }

  // 2. URL length
  if (value.length > 100) {
    lengthRisk = 70;
    evidence.push("Unusually long URL");
  } else if (value.length > 70) {
    lengthRisk = 40;
    evidence.push("Long URL structure detected");
  }

  // 3. Raw IP address
  const ipPattern =
    /^(?:\d{1,3}\.){3}\d{1,3}$/;

  if (ipPattern.test(domain)) {
    ipRisk = 90;
    evidence.push("URL uses a raw IP address instead of a domain name");
  }

  // 4. Suspicious keywords
  const suspiciousKeywords = [
    "login",
    "verify",
    "verification",
    "kyc",
    "refund",
    "cashback",
    "reward",
    "winner",
    "claim",
    "payment",
    "secure",
    "support",
    "update",
  ];

  const foundKeywords = suspiciousKeywords.filter((keyword) =>
    value.toLowerCase().includes(keyword)
  );

  if (foundKeywords.length > 0) {
    keywordRisk = Math.min(foundKeywords.length * 20, 100);

    evidence.push(
      `Suspicious keywords detected: ${foundKeywords.join(", ")}`
    );
  }

  // 5. Subdomains
  const parts = domain.split(".");

  if (parts.length >= 4) {
    subdomainRisk = 70;
    evidence.push("Unusually deep subdomain structure");
  } else if (parts.length === 3) {
    subdomainRisk = 30;
  }

  const risk = calculateRisk({
    httpsRisk,
    lengthRisk,
    ipRisk,
    keywordRisk,
    subdomainRisk,
  });

  if (evidence.length === 0) {
    evidence.push("No major suspicious URL indicators detected");
  }

  const intelligence = recordThreat(value, {
    status:
      risk.riskLevel === "HIGH"
        ? "Under Review"
        : "Analyzed",
  });

  return {
    id: `TH-${Date.now()}`,
    kind: "url",
    input: value,
    score: risk.score,
    riskLevel: risk.riskLevel,
    breakdown: risk.breakdown,
    evidence,
    domain,
    protocol: protocol.toUpperCase(),
    upi: "-",
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
  analyzeUrl,
};
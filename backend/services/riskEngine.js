const calculateRisk = ({
  httpsRisk,
  lengthRisk,
  ipRisk,
  keywordRisk,
  subdomainRisk,
  punycodeRisk = 0,
  portRisk = 0,
  sensitiveQueryRisk = 0,
  brandRisk = 0,
  baselineRisk = 15,
}) => {
  const breakdown = {
    "HTTPS Security": httpsRisk,
    "URL Length": lengthRisk,
    "IP Address": ipRisk,
    "Suspicious Keywords": keywordRisk,
    "Subdomain Structure": subdomainRisk,
    Punycode: punycodeRisk,
    "Non-standard Port": portRisk,
    "Sensitive Query Parameters": sensitiveQueryRisk,
    "Brand Impersonation": brandRisk,
    "Baseline Uncertainty": baselineRisk,
  };

  // Weighted score
  const score =
    httpsRisk * 0.16 +
    lengthRisk * 0.08 +
    ipRisk * 0.16 +
    keywordRisk * 0.20 +
    subdomainRisk * 0.12 +
    punycodeRisk * 0.08 +
    portRisk * 0.05 +
    sensitiveQueryRisk * 0.10 +
    brandRisk * 0.05;

  const weightedScore = baselineRisk + score * (1 - baselineRisk / 100);
  const brandMismatchFloor = brandRisk >= 80 ? 70 : 0;
  const finalScore = Math.min(100, Math.round(Math.max(weightedScore, brandMismatchFloor)));

  let riskLevel = "LOW";

  if (finalScore >= 85) {
    riskLevel = "CRITICAL";
  } else if (finalScore >= 65) {
    riskLevel = "HIGH";
  } else if (finalScore >= 40) {
    riskLevel = "MEDIUM";
  }

  return {
    score: finalScore,
    riskLevel,
    breakdown,
  };
};

module.exports = {
  calculateRisk,
};

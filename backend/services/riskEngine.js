const clamp = (value, min = 0, max = 100) =>
  Math.min(max, Math.max(min, Number(value) || 0));

const calculateRisk = ({
  trustedDomain = false,
  httpsRisk = 0,
  lengthRisk = 0,
  ipRisk = 0,
  keywordRisk = 0,
  subdomainRisk = 0,
  punycodeRisk = 0,
  portRisk = 0,
  sensitiveQueryRisk = 0,
  brandRisk = 0,
  suspiciousPathRisk = 0,
}) => {
  const breakdown = {
    "HTTPS Security": clamp(httpsRisk),
    "URL Length": clamp(lengthRisk),
    "IP Address": clamp(ipRisk),
    "Suspicious Keywords": clamp(keywordRisk),
    "Subdomain Structure": clamp(subdomainRisk),
    Punycode: clamp(punycodeRisk),
    "Non-standard Port": clamp(portRisk),
    "Sensitive Query Parameters": clamp(sensitiveQueryRisk),
    "Brand Impersonation": clamp(brandRisk),
    "Suspicious Path": clamp(suspiciousPathRisk),
  };

  const weights = {
    "HTTPS Security": 0.08,
    "URL Length": 0.06,
    "IP Address": 0.16,
    "Suspicious Keywords": 0.14,
    "Subdomain Structure": 0.08,
    Punycode: 0.12,
    "Non-standard Port": 0.05,
    "Sensitive Query Parameters": 0.08,
    "Brand Impersonation": 0.17,
    "Suspicious Path": 0.06,
  };

  let score = Object.entries(breakdown).reduce(
    (total, [key, value]) => total + value * weights[key],
    12
  );

  // Trusted domains are evidence, not an absolute safety verdict.
  if (trustedDomain) {
    score -= 18;
  }

  // Strong indicators should not be hidden by HTTPS or a low baseline.
  if (brandRisk >= 80) {
    score = Math.max(score, 70);
  }

  if (ipRisk >= 80) {
    score = Math.max(score, 62);
  }

  if (punycodeRisk >= 70) {
    score = Math.max(score, 45);
  }

  if (sensitiveQueryRisk >= 80 && brandRisk >= 70) {
    score = Math.max(score, 72);
  }

  const finalScore = Math.round(clamp(score));

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
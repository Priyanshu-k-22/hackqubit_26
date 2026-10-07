const calculateRisk = ({
  httpsRisk,
  lengthRisk,
  ipRisk,
  keywordRisk,
  subdomainRisk,
}) => {
  const breakdown = {
    "HTTPS Security": httpsRisk,
    "URL Length": lengthRisk,
    "IP Address": ipRisk,
    "Suspicious Keywords": keywordRisk,
    "Subdomain Structure": subdomainRisk,
  };

  // Weighted score
  const score =
    httpsRisk * 0.20 +
    lengthRisk * 0.10 +
    ipRisk * 0.25 +
    keywordRisk * 0.30 +
    subdomainRisk * 0.15;

  const finalScore = Math.round(score);

  let riskLevel = "LOW";

  if (finalScore >= 70) {
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
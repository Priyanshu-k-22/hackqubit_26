const crypto = require("node:crypto");
const { isIP } = require("node:net");
const { calculateRisk } = require("./riskEngine");

const trustedDomains = [
  "google.com", "youtube.com", "microsoft.com", "amazon.in", "flipkart.com", "npci.org.in", "sbi.co.in",
  "hdfcbank.com", "icicibank.com", "axisbank.com",
];

const brandHosts = [
  { label: "SBI", token: "sbi", official: ["sbi.co.in"] },
  { label: "Paytm", token: "paytm", official: ["paytm.com"] },
  { label: "PhonePe", token: "phonepe", official: ["phonepe.com"] },
  { label: "Google Pay", token: "googlepay", official: ["google.com"] },
  { label: "HDFC", token: "hdfc", official: ["hdfcbank.com"] },
  { label: "ICICI", token: "icici", official: ["icicibank.com"] },
  { label: "Zomato", token: "zomato", official: ["zomato.com"] },
];

function parseUrl(input) {
  const trimmed = input.trim();
  try {
    const normalized = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
    const parsed = new URL(normalized);
    if (!/^https?:$/.test(parsed.protocol) || !parsed.hostname || parsed.username || parsed.password) return null;
    return parsed;
  } catch {
    return null;
  }
}

function getSafeDisplayUrl(parsed) {
  const safePath = parsed.pathname.split("/").map((segment) =>
    segment.length > 40 || /^[a-f\d]{24,}$/i.test(segment) ? "[redacted]" : segment
  ).join("/");
  const safeQuery = [...parsed.searchParams.keys()]
    .map((key) => `${encodeURIComponent(key)}=[redacted]`)
    .join("&");
  return `${parsed.origin}${safePath}${safeQuery ? `?${safeQuery}` : ""}`;
}

function analyzeUrl(inputUrl) {
  if (typeof inputUrl !== "string") {
    return { input: String(inputUrl ?? ""), domain: "", score: 90, riskLevel: "HIGH", status: "INVALID URL", reason: "The entered value is not a valid URL", matchedDomain: null, evidence: ["The entered value is not a valid URL"] };
  }

  const value = inputUrl.trim();
  const parsedUrl = parseUrl(value);
  if (!parsedUrl || value.length > 2048) {
    return { input: value, domain: "", score: 90, riskLevel: "HIGH", status: "INVALID URL", reason: "The entered value is not a valid URL", matchedDomain: null, evidence: ["The entered value is not a valid URL"] };
  }
  const hostname = parsedUrl.hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  const protocol = parsedUrl.protocol.slice(0, -1).toUpperCase();
  const ipVersion = isIP(hostname);
  const labels = hostname.split(".").filter(Boolean);
  const subdomainCount = ipVersion ? 0 : Math.max(0, labels.length - 2);
  const isPunycode = labels.some((label) => label.startsWith("xn--"));
  const expectedPort = protocol === "HTTPS" ? "443" : "80";
  const hasNonStandardPort = Boolean(parsedUrl.port && parsedUrl.port !== expectedPort);
  const matchedDomain = trustedDomains.find((domain) => hostname === domain || hostname.endsWith(`.${domain}`)) || null;
  const mentionedBrand = brandHosts.find(({ token }) => hostname.includes(token));
  const recognizedBrand = mentionedBrand && mentionedBrand.official.some((domain) =>
    hostname === domain || hostname.endsWith(`.${domain}`)
  ) ? mentionedBrand : null;
  const suspiciousBrand = mentionedBrand && !recognizedBrand ? mentionedBrand : null;
  const sensitiveQueryKeys = [...parsedUrl.searchParams.keys()].filter((key) =>
    /^(?:token|access_token|auth|authorization|session|password|passwd|pin|otp|secret|key)$/i.test(key)
  );
  const httpsRisk = protocol === "HTTPS" ? 0 : 80;
  const lengthRisk = value.length > 120 ? 70 : value.length > 80 ? 40 : 0;
  const ipRisk = ipVersion ? 90 : 0;
  const keywordRisk = 0;
  const subdomainRisk = subdomainCount >= 4 ? 80 : subdomainCount === 3 ? 55 : subdomainCount === 2 ? 25 : 0;
  const punycodeRisk = isPunycode ? 70 : 0;
  const portRisk = hasNonStandardPort ? 40 : 0;
  const sensitiveQueryRisk = sensitiveQueryKeys.length ? 80 : 0;
  const brandRisk = suspiciousBrand ? 85 : 0;

  const risk = calculateRisk({
    httpsRisk,
    lengthRisk,
    ipRisk,
    keywordRisk,
    subdomainRisk,
    punycodeRisk,
    portRisk,
    sensitiveQueryRisk,
    brandRisk,
  });
  if (matchedDomain) {
    risk.score = 10;
    risk.riskLevel = "LOW";
    risk.breakdown["Trusted Domain Match"] = 0;
  } else {
    risk.score = 75;
    risk.riskLevel = "HIGH";
  }

  const evidence = [];
  const status = matchedDomain ? "AUTHORIZED" : "UNKNOWN";
  const reason = matchedDomain ? "Domain is present in the trusted domain allowlist" : "Domain is not present in the authorized domain allowlist";
  evidence.push(reason);
  if (recognizedBrand) evidence.push(`Hostname matches the local ${recognizedBrand.label} domain rule; live ownership and reputation were not checked`);
  if (protocol === "HTTP") evidence.push("Connection uses HTTP and is not encrypted");
  if (ipVersion) evidence.push(`Hostname is a raw IPv${ipVersion} address`);
  if (lengthRisk) evidence.push(value.length > 120 ? "URL is unusually long" : "URL is longer than typical");
  if (subdomainRisk) evidence.push(`${subdomainCount} additional hostname labels were detected`);
  if (isPunycode) evidence.push("Hostname contains an internationalized (punycode) label; verify the spelling carefully");
  if (hasNonStandardPort) evidence.push(`URL uses a non-standard port (${parsedUrl.port})`);
  if (sensitiveQueryKeys.length) evidence.push("URL contains query parameter names commonly used for credentials or session tokens; values were redacted");
  if (suspiciousBrand) evidence.push(`Hostname uses ${suspiciousBrand.label} branding outside its known official domain`);
  if (!evidence.length) evidence.push("No major URL structure indicators were detected by these local checks");
  evidence.push("URL structure checks cannot confirm who operates the destination or whether a payment request is legitimate");

  const today = new Date().toISOString().slice(0, 10);
  const result = {
    id: `SCN-${crypto.randomUUID().replace(/-/g, "").slice(0, 12).toUpperCase()}`,
    kind: "url",
    input: getSafeDisplayUrl(parsedUrl),
    score: risk.score,
    riskLevel: risk.riskLevel,
    status,
    reason,
    matchedDomain,
    breakdown: risk.breakdown,
    evidence,
    domain: hostname,
    protocol,
    upi: "-",
    payee: "-",
    redirects: null,
    brand: suspiciousBrand?.label || recognizedBrand?.label || "Unknown",
    reports: 0,
    users: 0,
    first: today,
    last: today,
    campaign: "-",
    demo: false,
    ts: new Date().toISOString(),
    urlDetails: {
      hostname,
      path: getSafeDisplayUrl(parsedUrl).slice(parsedUrl.origin.length).split("?")[0],
      queryParameterCount: [...parsedUrl.searchParams.keys()].length,
      usesHttps: protocol === "HTTPS",
      ipVersion: ipVersion || null,
      subdomainCount,
      hasPunycode: isPunycode,
      hasNonStandardPort,
      sensitiveQueryParameterCount: sensitiveQueryKeys.length,
      matchedTrustedDomain: matchedDomain,
    },
  };
  return result;
}

module.exports = { analyzeUrl };

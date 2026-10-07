const crypto = require("node:crypto");
const { isIP } = require("node:net");

const { calculateRisk } = require("./riskEngine");
const { recordThreat } = require("./threatStore");

// ==================================================
// TRUSTED DOMAINS
// ==================================================

const trustedDomains = [
  "google.com",
  "youtube.com",
  "microsoft.com",
  "amazon.in",
  "flipkart.com",
  "npci.org.in",
  "sbi.co.in",
  "hdfcbank.com",
  "icicibank.com",
  "axisbank.com",
];

// ==================================================
// BRAND HOSTS
// ==================================================

const brandHosts = [
  {
    label: "SBI",
    token: "sbi",
    official: ["sbi.co.in"],
  },
  {
    label: "Paytm",
    token: "paytm",
    official: ["paytm.com"],
  },
  {
    label: "PhonePe",
    token: "phonepe",
    official: ["phonepe.com"],
  },
  {
    label: "Google Pay",
    token: "googlepay",
    official: ["google.com"],
  },
  {
    label: "HDFC",
    token: "hdfc",
    official: ["hdfcbank.com"],
  },
  {
    label: "ICICI",
    token: "icici",
    official: ["icicibank.com"],
  },
  {
    label: "Zomato",
    token: "zomato",
    official: ["zomato.com"],
  },
];

// ==================================================
// SUSPICIOUS KEYWORDS
// ==================================================

const suspiciousKeywords = [
  "verify",
  "verification",
  "kyc",
  "update",
  "login",
  "signin",
  "secure",
  "security",
  "account",
  "wallet",
  "payment",
  "refund",
  "reward",
  "cashback",
  "offer",
  "urgent",
  "suspend",
  "blocked",
  "activate",
  "claim",
  "otp",
  "password",
  "credential",
];

// ==================================================
// URL PARSER
// ==================================================

function parseUrl(input) {
  const trimmed = input.trim();

  try {
    const normalized =
      /^https?:\/\//i.test(trimmed)
        ? trimmed
        : `https://${trimmed}`;

    const parsed = new URL(normalized);

    if (
      !/^https?:$/.test(
        parsed.protocol
      )
    ) {
      return null;
    }

    if (!parsed.hostname) {
      return null;
    }

    if (
      parsed.username ||
      parsed.password
    ) {
      return null;
    }

    return parsed;
  } catch {
    return null;
  }
}

// ==================================================
// SAFE URL
// ==================================================

function getSafeDisplayUrl(parsed) {
  const safePath =
    parsed.pathname
      .split("/")
      .map((segment) =>
        segment.length > 40 ||
        /^[a-f\d]{24,}$/i.test(
          segment
        )
          ? "[redacted]"
          : segment
      )
      .join("/");

  const safeQuery = [
    ...parsed.searchParams.keys(),
  ]
    .map(
      (key) =>
        `${encodeURIComponent(
          key
        )}=[redacted]`
    )
    .join("&");

  return `${parsed.origin}${safePath}${
    safeQuery
      ? `?${safeQuery}`
      : ""
  }`;
}

// ==================================================
// MAIN ANALYZER
// ==================================================

async function analyzeUrl(
  inputUrl
) {
  // ----------------------------------------------
  // Basic validation
  // ----------------------------------------------

  if (
    typeof inputUrl !== "string"
  ) {
    throw Object.assign(
      new Error(
        "The entered value is not a valid URL"
      ),
      {
        statusCode: 400,
      }
    );
  }

  const value =
    inputUrl.trim();

  if (!value) {
    throw Object.assign(
      new Error(
        "URL is required"
      ),
      {
        statusCode: 400,
      }
    );
  }

  if (value.length > 2048) {
    throw Object.assign(
      new Error(
        "URL is too long"
      ),
      {
        statusCode: 400,
      }
    );
  }

  // ----------------------------------------------
  // Parse
  // ----------------------------------------------

  const parsedUrl =
    parseUrl(value);

  if (!parsedUrl) {
    throw Object.assign(
      new Error(
        "The entered value is not a valid URL"
      ),
      {
        statusCode: 400,
      }
    );
  }

  // ----------------------------------------------
  // Host information
  // ----------------------------------------------

  const hostname =
    parsedUrl.hostname
      .toLowerCase()
      .replace(
        /^\[|\]$/g,
        ""
      )
      .replace(/\.$/, "");

  const protocol =
    parsedUrl.protocol
      .slice(0, -1)
      .toUpperCase();

  const ipVersion =
    isIP(hostname);

  const labels =
    hostname
      .split(".")
      .filter(Boolean);

  const subdomainCount =
    ipVersion
      ? 0
      : Math.max(
          0,
          labels.length - 2
        );

  const isPunycode =
    labels.some((label) =>
      label.startsWith("xn--")
    );

  const expectedPort =
    protocol === "HTTPS"
      ? "443"
      : "80";

  const hasNonStandardPort =
    Boolean(
      parsedUrl.port &&
        parsedUrl.port !==
          expectedPort
    );

  // ----------------------------------------------
  // Trusted domain
  // ----------------------------------------------

  const matchedDomain =
    trustedDomains.find(
      (domain) =>
        hostname === domain ||
        hostname.endsWith(
          `.${domain}`
        )
    ) || null;

  // ----------------------------------------------
  // Brand detection
  // ----------------------------------------------

  const mentionedBrand =
    brandHosts.find(
      ({ token }) =>
        hostname.includes(token)
    );

  const recognizedBrand =
    mentionedBrand &&
    mentionedBrand.official.some(
      (domain) =>
        hostname === domain ||
        hostname.endsWith(
          `.${domain}`
        )
    )
      ? mentionedBrand
      : null;

  const suspiciousBrand =
    mentionedBrand &&
    !recognizedBrand
      ? mentionedBrand
      : null;

  // ----------------------------------------------
  // Suspicious keywords
  // ----------------------------------------------

  const lowerUrl =
    value.toLowerCase();

  const matchedKeywords =
    suspiciousKeywords.filter(
      (keyword) =>
        lowerUrl.includes(keyword)
    );

  // ----------------------------------------------
  // Sensitive query parameters
  // ----------------------------------------------

  const sensitiveQueryKeys = [
    ...parsedUrl.searchParams.keys(),
  ].filter((key) =>
    /^(?:token|access_token|auth|authorization|session|password|passwd|pin|otp|secret|key)$/i.test(
      key
    )
  );

  // ----------------------------------------------
  // Risk signals
  // ----------------------------------------------

  const httpsRisk =
    protocol === "HTTPS"
      ? 0
      : 80;

  const lengthRisk =
    value.length > 120
      ? 70
      : value.length > 80
      ? 40
      : 0;

  const ipRisk =
    ipVersion ? 90 : 0;

  const keywordRisk =
    matchedKeywords.length >= 4
      ? 80
      : matchedKeywords.length >= 2
      ? 50
      : matchedKeywords.length === 1
      ? 25
      : 0;

  const subdomainRisk =
    subdomainCount >= 4
      ? 80
      : subdomainCount === 3
      ? 55
      : subdomainCount === 2
      ? 25
      : 0;

  const punycodeRisk =
    isPunycode ? 70 : 0;

  const portRisk =
    hasNonStandardPort
      ? 40
      : 0;

  const sensitiveQueryRisk =
    sensitiveQueryKeys.length
      ? 80
      : 0;

  const brandRisk =
    suspiciousBrand
      ? 85
      : 0;

  // ----------------------------------------------
  // Calculate risk
  // ----------------------------------------------

  const risk =
    calculateRisk({
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

  // ----------------------------------------------
  // Trusted domains
  // ----------------------------------------------

  if (matchedDomain) {
    risk.score = 10;
    risk.riskLevel = "LOW";

    risk.breakdown[
      "Trusted Domain Match"
    ] = 0;
  }

  // ----------------------------------------------
  // Evidence
  // ----------------------------------------------

  const evidence = [];

  let status;
  let reason;

  if (matchedDomain) {
    status = "AUTHORIZED";

    reason =
      "Domain is present in the trusted domain allowlist";
  } else if (
    suspiciousBrand
  ) {
    status = "SUSPICIOUS";

    reason =
      `Domain appears to imitate ${suspiciousBrand.label}`;
  } else if (
    risk.riskLevel === "CRITICAL"
  ) {
    status = "BLOCKED";

    reason =
      "Multiple high-risk URL indicators were detected";
  } else if (
    risk.riskLevel === "HIGH"
  ) {
    status = "SUSPICIOUS";

    reason =
      "High-risk URL indicators were detected";
  } else {
    status = "UNKNOWN";

    reason =
      "Domain is not present in the authorized domain allowlist";
  }

  evidence.push(reason);

  if (recognizedBrand) {
    evidence.push(
      `Hostname matches the local ${recognizedBrand.label} domain rule; live ownership and reputation were not checked`
    );
  }

  if (protocol === "HTTP") {
    evidence.push(
      "Connection uses HTTP and is not encrypted"
    );
  }

  if (ipVersion) {
    evidence.push(
      `Hostname is a raw IPv${ipVersion} address`
    );
  }

  if (lengthRisk) {
    evidence.push(
      value.length > 120
        ? "URL is unusually long"
        : "URL is longer than typical"
    );
  }

  if (keywordRisk) {
    evidence.push(
      `Suspicious URL keywords detected: ${matchedKeywords.join(
        ", "
      )}`
    );
  }

  if (subdomainRisk) {
    evidence.push(
      `${subdomainCount} additional hostname labels were detected`
    );
  }

  if (isPunycode) {
    evidence.push(
      "Hostname contains an internationalized (punycode) label; verify the spelling carefully"
    );
  }

  if (hasNonStandardPort) {
    evidence.push(
      `URL uses a non-standard port (${parsedUrl.port})`
    );
  }

  if (
    sensitiveQueryKeys.length
  ) {
    evidence.push(
      "URL contains query parameter names commonly used for credentials or session tokens; values were redacted"
    );
  }

  if (suspiciousBrand) {
    evidence.push(
      `Hostname uses ${suspiciousBrand.label} branding outside its known official domain`
    );
  }

  evidence.push(
    "URL structure checks cannot confirm who operates the destination or whether a payment request is legitimate"
  );

  // ----------------------------------------------
  // Build result
  // ----------------------------------------------

  const safeUrl =
    getSafeDisplayUrl(
      parsedUrl
    );

  const now =
    new Date();

  const result = {
    id: `SCN-${crypto
      .randomUUID()
      .replace(/-/g, "")
      .slice(0, 12)
      .toUpperCase()}`,

    kind: "url",

    input: safeUrl,

    score: risk.score,

    riskLevel:
      risk.riskLevel,

    status,

    reason,

    matchedDomain,

    breakdown:
      risk.breakdown,

    evidence,

    domain: hostname,

    protocol,

    upi: "-",

    payee: "-",

    redirects: null,

    brand:
      suspiciousBrand?.label ||
      recognizedBrand?.label ||
      "Unknown",

    reports: 0,

    users: 0,

    first:
      now.toISOString(),

    last:
      now.toISOString(),

    campaign: "-",

    demo: false,

    ts:
      now.toISOString(),

    urlDetails: {
      hostname,

      path:
        safeUrl
          .slice(
            parsedUrl.origin.length
          )
          .split("?")[0],

      queryParameterCount:
        [
          ...parsedUrl.searchParams.keys(),
        ].length,

      usesHttps:
        protocol === "HTTPS",

      ipVersion:
        ipVersion || null,

      subdomainCount,

      hasPunycode:
        isPunycode,

      hasNonStandardPort,

      sensitiveQueryParameterCount:
        sensitiveQueryKeys.length,

      matchedTrustedDomain:
        matchedDomain,

      matchedKeywords,
    },
  };

  // ----------------------------------------------
  // SAVE REPORT TO MONGODB
  // ----------------------------------------------

  const threat =
    await recordThreat(
      hostname,
      {
        type: "URL",

        input: safeUrl,

        normalizedInput:
          hostname,

        target:
          safeUrl,

        domain:
          hostname,

        score:
          risk.score,

        riskLevel:
          risk.riskLevel,

        status,

        reason,

        brand:
          result.brand,

        campaign:
          null,

        evidence,

        breakdown:
          risk.breakdown,

        metadata: {
          source: "url",
          protocol,
          matchedDomain,
          matchedKeywords,
          urlDetails:
            result.urlDetails,
        },

        analysis:
          result,
      }
    );

  // ----------------------------------------------
  // Attach DB information
  // ----------------------------------------------

  result.threatId =
    threat.id;

  result.reportId =
    threat.reportId;

  result.reports =
    threat.reports;

  result.users =
    threat.users;

  result.first =
    threat.first;

  result.last =
    threat.last;

  result.campaign =
    threat.campaign;

  return result;
}

module.exports = {
  analyzeUrl,
};
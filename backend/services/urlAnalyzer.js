const crypto = require("node:crypto");
const { isIP } = require("node:net");

const { calculateRisk } = require("./riskEngine");
const { recordThreat } = require("./threatStore");

/*
|--------------------------------------------------------------------------
| Trusted Domains
|--------------------------------------------------------------------------
|
| These are treated as known/authorized domains.
| IMPORTANT:
| A trusted domain is NOT automatically considered universally safe.
| It only contributes positive evidence to the analysis.
|
*/

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

  "paytm.com",
  "phonepe.com",
  "zomato.com",
];

/*
|--------------------------------------------------------------------------
| Brand Intelligence
|--------------------------------------------------------------------------
|
| Used to detect:
|
|     sbi-login.com
|     paytm-verify.com
|     phonepe-kyc.com
|
| while distinguishing them from:
|
|     sbi.co.in
|     paytm.com
|     phonepe.com
|
*/

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
    label: "Axis Bank",
    token: "axis",
    official: ["axisbank.com"],
  },

  {
    label: "Zomato",
    token: "zomato",
    official: ["zomato.com"],
  },
];

/*
|--------------------------------------------------------------------------
| Suspicious URL Keywords
|--------------------------------------------------------------------------
*/

const suspiciousKeywords = [
  "login",
  "signin",
  "sign-in",

  "verify",
  "verification",

  "secure",
  "security",

  "kyc",

  "refund",
  "cashback",
  "cash-back",

  "reward",
  "rewards",

  "prize",
  "winner",

  "claim",

  "support",

  "wallet",

  "payment",
  "pay",

  "bank",

  "credential",
  "credentials",

  "otp",
  "pin",
  "password",

  "unlock",
  "suspend",
  "suspended",

  "update",
  "confirm",
];

/*
|--------------------------------------------------------------------------
| Sensitive Query Parameters
|--------------------------------------------------------------------------
|
| We only inspect parameter NAMES.
| Values are NEVER returned in the result.
|
*/

const sensitiveQueryPattern =
  /^(?:token|access_token|auth|authorization|session|session_id|password|passwd|pin|otp|secret|api_key|apikey|key|code)$/i;

/*
|--------------------------------------------------------------------------
| Suspicious Path Pattern
|--------------------------------------------------------------------------
*/

const suspiciousPathPattern =
  /(?:login|signin|sign-in|verify|verification|kyc|refund|cashback|reward|prize|winner|claim|support|payment|wallet|otp|password|credential|secure|unlock|suspend)/i;

/*
|--------------------------------------------------------------------------
| Helpers
|--------------------------------------------------------------------------
*/

function normalizeHostname(hostname) {
  return hostname
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .replace(/\.$/, "");
}

function domainMatches(hostname, domain) {
  return (
    hostname === domain ||
    hostname.endsWith(`.${domain}`)
  );
}

function parseUrl(input) {
  const trimmed = input.trim();

  try {
    /*
     * If the user enters:
     *
     * example.com
     *
     * internally convert it to:
     *
     * https://example.com
     */

    const normalized =
      /^https?:\/\//i.test(trimmed)
        ? trimmed
        : `https://${trimmed}`;

    const parsed = new URL(normalized);

    /*
     * Only HTTP and HTTPS are supported.
     */

    if (
      !/^https?:$/.test(parsed.protocol)
    ) {
      return null;
    }

    /*
     * URL username/password are rejected.
     *
     * Example:
     *
     * https://admin:password@example.com
     */

    if (
      !parsed.hostname ||
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

/*
|--------------------------------------------------------------------------
| Safe URL representation
|--------------------------------------------------------------------------
|
| We don't want passwords, tokens or long random values
| appearing in the dashboard/report.
|
*/

function getSafeDisplayUrl(parsed) {
  const safePath = parsed.pathname
    .split("/")
    .map((segment) => {
      /*
       * Redact:
       *
       * very long path segments
       * Mongo/ObjectId-like strings
       * long hexadecimal identifiers
       */

      if (
        segment.length > 40 ||
        /^[a-f\d]{24,}$/i.test(segment)
      ) {
        return "[redacted]";
      }

      return segment;
    })
    .join("/");

  /*
   * Keep parameter names.
   * Remove parameter values.
   */

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

/*
|--------------------------------------------------------------------------
| Extract Suspicious Keywords
|--------------------------------------------------------------------------
*/

function analyzeKeywords(
  hostname,
  pathname,
  search
) {
  const text =
    `${hostname} ${pathname} ${search}`.toLowerCase();

  const matches = [
    ...new Set(
      suspiciousKeywords.filter(
        (keyword) =>
          text.includes(keyword)
      )
    ),
  ];

  let score = 0;

  if (matches.length >= 5) {
    score = 90;
  } else if (matches.length >= 4) {
    score = 80;
  } else if (matches.length >= 3) {
    score = 65;
  } else if (matches.length >= 2) {
    score = 45;
  } else if (matches.length === 1) {
    score = 25;
  }

  return {
    score,
    matches,
  };
}

/*
|--------------------------------------------------------------------------
| Brand Detection
|--------------------------------------------------------------------------
*/

function analyzeBrand(
  hostname,
  pathname
) {
  const text =
    `${hostname}${pathname}`.toLowerCase();

  /*
   * Find a brand token anywhere in hostname/path.
   */

  const mentionedBrand =
    brandHosts.find(
      ({ token }) =>
        text.includes(token)
    );

  if (!mentionedBrand) {
    return {
      mentionedBrand: null,
      recognizedBrand: null,
      suspiciousBrand: null,
    };
  }

  /*
   * Is the hostname actually owned by
   * the official domain family?
   */

  const recognizedBrand =
    mentionedBrand.official.some(
      (officialDomain) =>
        domainMatches(
          hostname,
          officialDomain
        )
    )
      ? mentionedBrand
      : null;

  /*
   * Brand token outside official domain
   * = possible impersonation.
   */

  const suspiciousBrand =
    recognizedBrand
      ? null
      : mentionedBrand;

  return {
    mentionedBrand,
    recognizedBrand,
    suspiciousBrand,
  };
}

/*
|--------------------------------------------------------------------------
| INVALID RESULT
|--------------------------------------------------------------------------
*/

function invalidResult(
  input,
  reason
) {
  return {
    id: `SCN-${crypto
      .randomUUID()
      .replace(/-/g, "")
      .slice(0, 12)
      .toUpperCase()}`,

    kind: "url",

    input: String(
      input ?? ""
    ),

    score: 90,

    riskLevel: "HIGH",

    status: "INVALID URL",

    reason,

    matchedDomain: null,

    evidence: [reason],

    breakdown: {},

    domain: "",

    protocol: "-",

    upi: "-",

    payee: "-",

    redirects: null,

    brand: "Unknown",

    reports: 0,

    users: 0,

    campaign: "-",

    demo: false,

    ts: new Date().toISOString(),

    urlDetails: null,
  };
}

/*
|--------------------------------------------------------------------------
| MAIN URL ANALYZER
|--------------------------------------------------------------------------
*/

function analyzeUrl(inputUrl) {
  /*
   * --------------------------------------------------------------
   * 1. Validate input
   * --------------------------------------------------------------
   */

  if (
    typeof inputUrl !== "string"
  ) {
    return invalidResult(
      inputUrl,
      "The entered value is not a valid URL"
    );
  }

  const value =
    inputUrl.trim();

  if (!value) {
    return invalidResult(
      value,
      "URL cannot be empty"
    );
  }

  /*
   * Protect backend from excessively large input.
   */

  if (value.length > 2048) {
    return invalidResult(
      value,
      "URL exceeds the maximum allowed length of 2048 characters"
    );
  }

  /*
   * --------------------------------------------------------------
   * 2. Parse URL
   * --------------------------------------------------------------
   */

  const parsedUrl =
    parseUrl(value);

  if (!parsedUrl) {
    return invalidResult(
      value,
      "Only valid HTTP and HTTPS URLs without embedded credentials can be analyzed"
    );
  }

  /*
   * --------------------------------------------------------------
   * 3. Normalize hostname
   * --------------------------------------------------------------
   */

  const hostname =
    normalizeHostname(
      parsedUrl.hostname
    );

  const protocol =
    parsedUrl.protocol
      .slice(0, -1)
      .toUpperCase();

  /*
   * --------------------------------------------------------------
   * 4. IP detection
   * --------------------------------------------------------------
   */

  const ipVersion =
    isIP(hostname);

  /*
   * --------------------------------------------------------------
   * 5. Hostname structure
   * --------------------------------------------------------------
   */

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

  /*
   * --------------------------------------------------------------
   * 6. Punycode detection
   * --------------------------------------------------------------
   */

  const isPunycode =
    labels.some(
      (label) =>
        label.startsWith("xn--")
    );

  /*
   * --------------------------------------------------------------
   * 7. Port analysis
   * --------------------------------------------------------------
   */

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

  /*
   * --------------------------------------------------------------
   * 8. Trusted-domain matching
   * --------------------------------------------------------------
   */

  const matchedDomain =
    trustedDomains.find(
      (domain) =>
        domainMatches(
          hostname,
          domain
        )
    ) || null;

  /*
   * --------------------------------------------------------------
   * 9. Brand analysis
   * --------------------------------------------------------------
   */

  const {
    recognizedBrand,
    suspiciousBrand,
  } = analyzeBrand(
    hostname,
    parsedUrl.pathname
  );

  /*
   * --------------------------------------------------------------
   * 10. Keyword analysis
   * --------------------------------------------------------------
   */

  const keyword =
    analyzeKeywords(
      hostname,
      parsedUrl.pathname,
      parsedUrl.search
    );

  /*
   * --------------------------------------------------------------
   * 11. Sensitive query parameters
   * --------------------------------------------------------------
   */

  const sensitiveQueryKeys =
    [
      ...parsedUrl.searchParams.keys(),
    ].filter((key) =>
      sensitiveQueryPattern.test(
        key
      )
    );

  /*
   * --------------------------------------------------------------
   * 12. URL risk signals
   * --------------------------------------------------------------
   */

  /*
   * HTTP is a risk indicator,
   * but HTTPS does NOT make a site safe.
   */

  const httpsRisk =
    protocol === "HTTPS"
      ? 0
      : 80;

  /*
   * Long URLs can be suspicious,
   * especially when combined with
   * other signals.
   */

  const lengthRisk =
    value.length > 180
      ? 85
      : value.length > 120
        ? 65
        : value.length > 80
          ? 35
          : 0;

  /*
   * Raw IP addresses are risky
   * for payment/login URLs.
   */

  const ipRisk =
    ipVersion
      ? 90
      : 0;

  /*
   * Excessive subdomains.
   */

  const subdomainRisk =
    subdomainCount >= 5
      ? 90
      : subdomainCount === 4
        ? 75
        : subdomainCount === 3
          ? 55
          : subdomainCount === 2
            ? 25
            : 0;

  /*
   * Punycode can be legitimate,
   * therefore we don't immediately call it malicious.
   */

  const punycodeRisk =
    isPunycode
      ? 70
      : 0;

  /*
   * Non-standard port.
   */

  const portRisk =
    hasNonStandardPort
      ? 45
      : 0;

  /*
   * Credential/session-related parameters.
   */

  const sensitiveQueryRisk =
    sensitiveQueryKeys.length >= 2
      ? 90
      : sensitiveQueryKeys.length === 1
        ? 70
        : 0;

  /*
   * Brand mismatch is one of our strongest
   * local indicators.
   */

  const brandRisk =
    suspiciousBrand
      ? 90
      : 0;

  /*
   * Login/payment/verification-looking path.
   */

  const suspiciousPath =
    suspiciousPathPattern.test(
      parsedUrl.pathname
    );

  const suspiciousPathRisk =
    suspiciousPath
      ? 55
      : 0;

  /*
   * --------------------------------------------------------------
   * 13. Calculate risk
   * --------------------------------------------------------------
   */

  const risk =
    calculateRisk({
      httpsRisk,
      lengthRisk,
      ipRisk,
      keywordRisk:
        keyword.score,
      subdomainRisk,
      punycodeRisk,
      portRisk,
      sensitiveQueryRisk,
      brandRisk,
    });

  /*
   * --------------------------------------------------------------
   * 14. IMPORTANT
   * --------------------------------------------------------------
   *
   * DO NOT overwrite risk.score here.
   *
   * The previous implementation did:
   *
   *     trusted → 10
   *     unknown → 75
   *
   * That destroyed the actual risk calculation.
   *
   * We now preserve the calculated score.
   */

  /*
   * --------------------------------------------------------------
   * 15. Determine status
   * --------------------------------------------------------------
   */

  let status;

  if (
    risk.riskLevel === "CRITICAL"
  ) {
    status = "HIGH RISK";
  } else if (
    risk.riskLevel === "HIGH"
  ) {
    status = "HIGH RISK";
  } else if (
    risk.riskLevel === "MEDIUM"
  ) {
    status = "SUSPICIOUS";
  } else if (
    matchedDomain
  ) {
    status = "AUTHORIZED";
  } else {
    status = "LOW RISK";
  }

  /*
   * --------------------------------------------------------------
   * 16. Determine reason
   * --------------------------------------------------------------
   */

  let reason;

  if (suspiciousBrand) {
    reason =
      `Possible ${suspiciousBrand.label} impersonation detected`;
  } else if (
    ipRisk >= 80
  ) {
    reason =
      "URL uses a raw IP address instead of a normal domain";
  } else if (
    sensitiveQueryRisk >= 70
  ) {
    reason =
      "URL contains parameters commonly associated with credentials or session data";
  } else if (
    punycodeRisk >= 70
  ) {
    reason =
      "URL contains a punycode hostname that requires additional verification";
  } else if (
    keyword.score >= 65
  ) {
    reason =
      "Multiple suspicious keywords were detected in the URL";
  } else if (
    matchedDomain
  ) {
    reason =
      `Domain belongs to the trusted ${matchedDomain} domain family`;
  } else if (
    risk.riskLevel === "LOW"
  ) {
    reason =
      "No strong malicious URL indicators were detected";
  } else {
    reason =
      "URL contains one or more suspicious structural indicators";
  }

  /*
   * --------------------------------------------------------------
   * 17. Generate evidence
   * --------------------------------------------------------------
   */

  const evidence = [];

  /*
   * Trusted domain evidence
   */

  if (matchedDomain) {
    evidence.push(
      `Hostname belongs to trusted domain ${matchedDomain}`
    );
  } else {
    evidence.push(
      "Hostname is not present in the local trusted-domain registry"
    );
  }

  /*
   * Official brand evidence
   */

  if (recognizedBrand) {
    evidence.push(
      `Hostname matches the known official ${recognizedBrand.label} domain family`
    );
  }

  /*
   * Brand impersonation
   */

  if (suspiciousBrand) {
    evidence.push(
      `Possible ${suspiciousBrand.label} impersonation: brand token appears outside its official domain`
    );
  }

  /*
   * HTTP
   */

  if (
    protocol === "HTTP"
  ) {
    evidence.push(
      "Connection uses HTTP and is not encrypted"
    );
  }

  /*
   * IP
   */

  if (ipVersion) {
    evidence.push(
      `Hostname is a raw IPv${ipVersion} address instead of a normal domain`
    );
  }

  /*
   * Keywords
   */

  if (
    keyword.matches.length
  ) {
    evidence.push(
      `Suspicious URL terms detected: ${keyword.matches.join(", ")}`
    );
  }

  /*
   * Long URL
   */

  if (
    lengthRisk > 0
  ) {
    evidence.push(
      `URL length is ${value.length} characters`
    );
  }

  /*
   * Subdomains
   */

  if (
    subdomainRisk > 0
  ) {
    evidence.push(
      `${subdomainCount} nested hostname labels were detected`
    );
  }

  /*
   * Punycode
   */

  if (isPunycode) {
    evidence.push(
      "Hostname contains a punycode label; verify the spelling carefully"
    );
  }

  /*
   * Port
   */

  if (
    hasNonStandardPort
  ) {
    evidence.push(
      `URL uses a non-standard port (${parsedUrl.port})`
    );
  }

  /*
   * Sensitive query
   */

  if (
    sensitiveQueryKeys.length
  ) {
    evidence.push(
      `Sensitive parameter names detected: ${sensitiveQueryKeys.join(", ")}; values were redacted`
    );
  }

  /*
   * Suspicious path
   */

  if (
    suspiciousPath
  ) {
    evidence.push(
      "Path contains terms commonly associated with login, verification, payment or credential pages"
    );
  }

  /*
   * General safe evidence
   */

  if (
    risk.riskLevel === "LOW" &&
    evidence.length <= 2
  ) {
    evidence.push(
      "No strong malicious URL indicators were found by the local rules"
    );
  }

  /*
   * IMPORTANT DISCLAIMER
   */

  evidence.push(
    "URL structure analysis cannot prove who operates the destination or whether a payment request is legitimate"
  );

  /*
   * --------------------------------------------------------------
   * 18. Build result
   * --------------------------------------------------------------
   */

  const today =
    new Date()
      .toISOString()
      .slice(0, 10);

  const safeUrl =
    getSafeDisplayUrl(
      parsedUrl
    );

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

    /*
     * We intentionally don't follow redirects yet.
     * That will belong to the crawler feature.
     */

    redirects: null,

    brand:
      suspiciousBrand?.label ||
      recognizedBrand?.label ||
      "Unknown",

    reports: 0,

    users: 0,

    first: today,

    last: today,

    campaign: "-",

    demo: false,

    ts:
      new Date().toISOString(),

    urlDetails: {
      hostname,

      path:
        parsedUrl.pathname ||
        "/",

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

      suspiciousKeywords:
        keyword.matches,

      suspiciousPath,
    },
  };

  /*
   * --------------------------------------------------------------
   * 19. Store threat observation
   * --------------------------------------------------------------
   *
   * IMPORTANT:
   *
   * We store the hostname as the primary IOC.
   *
   * Example:
   *
   * https://sbi-login.com/a
   *
   * https://sbi-login.com/b
   *
   * both belong to:
   *
   * sbi-login.com
   *
   * and therefore should contribute to the same threat record.
   */

  const threat =
    recordThreat(
      hostname,
      {
        status,
        campaign:
          suspiciousBrand
            ? `CAM-${suspiciousBrand.token.toUpperCase()}`
            : undefined,
      }
    );

  /*
   * --------------------------------------------------------------
   * 20. Attach threat intelligence metadata
   * --------------------------------------------------------------
   */

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

  /*
   * --------------------------------------------------------------
   * 21. Return final result
   * --------------------------------------------------------------
   */

  return result;
}

module.exports = {
  analyzeUrl,
};
import { authorizedPaymentProviders } from "./authorizedPaymentProviders.mjs";

const handleProviders = new Map();
for (const provider of Object.values(authorizedPaymentProviders)) {
  for (const handle of provider.handles) handleProviders.set(handle.toLowerCase(), provider.name);
}

function parsePayloadUrl(payload) {
  try {
    return new URL(payload.replace(/^upi:\/\//i, "https://upi.local/"));
  } catch {
    return null;
  }
}

function detectQrType(payload, parsedUrl) {
  if (/^upi:\/\/pay(?:\?|$)/i.test(payload)) return "UPI_PAYMENT";
  if (/^WIFI:/i.test(payload)) return "WIFI";
  if (/^BEGIN:VCARD/i.test(payload)) return "CONTACT";
  if (/^mailto:/i.test(payload)) return "EMAIL";
  if (parsedUrl && /^https?:$/.test(parsedUrl.protocol)) {
    return /(?:^|\/)(?:pay|payment|upi|collect|qr)(?:\/|$)/i.test(parsedUrl.pathname) || /(?:^|[?&])(?:pa|payee|merchant|amount|txnid)=/i.test(parsedUrl.search)
      ? "PAYMENT_URL"
      : "GENERIC_URL";
  }
  return payload.trim() ? "TEXT" : "UNKNOWN";
}

export function identifyPaymentProvider(payload) {
  if (typeof payload !== "string") return { provider: "Unknown" };
  const value = payload.trim();
  const parsedUrl = parsePayloadUrl(value);

  if (/^upi:\/\/pay(?:\?|$)/i.test(value) && parsedUrl) {
    const upiId = parsedUrl.searchParams.get("pa")?.trim() || "";
    if (!/^[\w.-]+@[\w.-]+$/.test(upiId)) return { provider: "Unknown" };
    const handle = upiId.split("@").pop().toLowerCase();
    return { provider: handleProviders.get(handle) || "Unknown" };
  }

  if (parsedUrl && /^https?:$/.test(parsedUrl.protocol)) {
    const isPaymentUrl = /(?:^|\/)(?:pay|payment|upi|collect|qr)(?:\/|$)/i.test(parsedUrl.pathname)
      || /(?:^|[?&])(?:pa|payee|merchant|amount|txnid)=/i.test(parsedUrl.search);
    if (!isPaymentUrl) return { provider: "Unknown" };
    const hostname = parsedUrl.hostname.toLowerCase();
    const provider = Object.values(authorizedPaymentProviders).find((candidate) =>
      candidate.domains?.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`))
    );
    return { provider: provider?.name || "Unknown" };
  }

  return { provider: "Unknown" };
}

export function analyzeQrPayload(input) {
  const payload = typeof input === "string" ? input.trim() : "";
  const parsedUrl = parsePayloadUrl(payload);
  const qrType = detectQrType(payload, parsedUrl);
  const isUpiPayment = qrType === "UPI_PAYMENT";
  const upiId = isUpiPayment ? parsedUrl.searchParams.get("pa")?.trim() || "" : "";
  const payeeName = isUpiPayment ? parsedUrl.searchParams.get("pn")?.trim() || "" : "";
  const amount = isUpiPayment ? parsedUrl.searchParams.get("am")?.trim() || "" : "";
  const currency = isUpiPayment ? parsedUrl.searchParams.get("cu")?.trim() || "" : "";
  const matchedProvider = identifyPaymentProvider(payload).provider;
  const authorized = (isUpiPayment && /^[\w.-]+@[\w.-]+$/.test(upiId) && matchedProvider !== "Unknown")
    || (qrType === "PAYMENT_URL" && matchedProvider !== "Unknown");
  const resolvedProvider = authorized ? matchedProvider : "Unknown";
  const isNonPaymentType = ["WIFI", "CONTACT", "EMAIL", "TEXT", "UNKNOWN"].includes(qrType);
  const status = authorized ? "AUTHORIZED" : isNonPaymentType ? "NON-PAYMENT QR" : "UNKNOWN";
  const reason = authorized
    ? `Recognized ${isUpiPayment ? "UPI payment QR" : "payment URL QR"} from an authorized payment provider (${resolvedProvider})`
    : isNonPaymentType
      ? "QR code is not a recognized payment QR"
      : "QR code is not recognized as an authorized payment QR";
  const score = authorized ? 10 : 85;
  const today = new Date().toISOString().slice(0, 10);
  const id = globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(16).slice(2)}`;

  return {
    id: `SCN-${id.replace(/-/g, "").slice(0, 12).toUpperCase()}`,
    kind: "qr",
    input: payload.slice(0, 2048),
    score,
    riskLevel: authorized ? "LOW" : "HIGH",
    status,
    reason,
    qrType,
    provider: resolvedProvider,
    upi: upiId || "-",
    payee: payeeName || "-",
    amount,
    currency,
    recommendation: authorized
      ? "Confirm the payee and amount in your UPI app before approving."
      : "Do not make a payment until the QR source is verified.",
    domain: parsedUrl && !isUpiPayment ? parsedUrl.hostname : "-",
    protocol: parsedUrl?.protocol?.slice(0, -1).toUpperCase() || "-",
    redirects: null,
    brand: resolvedProvider,
    reports: 0,
    users: 0,
    first: today,
    last: today,
    campaign: "-",
    demo: false,
    ts: new Date().toISOString(),
    evidence: [reason, "Allowlist matching does not confirm that the payee is trustworthy or the payment is safe"],
    breakdown: { "Authorized Payment QR": authorized ? 0 : 100 },
    paymentAssessment: { outcome: authorized ? "authorized" : "unverified", message: reason },
  };
}

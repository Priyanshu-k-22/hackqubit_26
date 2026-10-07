const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const dataDir = path.join(__dirname, "../data");
const dataFile = path.join(dataDir, "threats.json");

function ensureStore() {
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }

  if (!fs.existsSync(dataFile)) {
    fs.writeFileSync(dataFile, "{}", "utf8");
  }
}

function readStore() {
  ensureStore();

  try {
    return JSON.parse(fs.readFileSync(dataFile, "utf8"));
  } catch {
    return {};
  }
}

function writeStore(store) {
  ensureStore();

  const tempFile = `${dataFile}.${process.pid}.tmp`;

  fs.writeFileSync(
    tempFile,
    JSON.stringify(store, null, 2),
    "utf8"
  );

  fs.renameSync(tempFile, dataFile);
}

const today = () =>
  new Date().toISOString().slice(0, 10);

function createCampaignId(key) {
  const digest = crypto
    .createHash("sha256")
    .update(key)
    .digest("hex");

  return `CAM-${(parseInt(digest.slice(0, 6), 16) % 900) + 100}`;
}

function recordThreat(input, data = {}) {
  const key = String(input).trim().toLowerCase();

  if (!key) {
    throw new Error("Threat input cannot be empty");
  }

  const store = readStore();
  const existing = store[key];
  const now = today();

  if (existing) {
    existing.reports += 1;

    existing.users = Math.max(
      existing.users || 1,
      existing.reports
    );

    existing.last = now;

    existing.risk = Math.max(
      existing.risk,
      Number(data.risk) || 0
    );

    existing.riskLevel =
      data.riskLevel || existing.riskLevel;

    existing.status =
      data.status || existing.status;

    existing.reason =
      data.reason || existing.reason;

    existing.brand =
      data.brand || existing.brand;

    existing.target =
      data.target || existing.target;

    existing.type =
      data.type || existing.type;

    existing.analysis =
      data.analysis || existing.analysis;
  } else {
    store[key] = {
      id: `THR-${crypto
        .randomUUID()
        .replace(/-/g, "")
        .slice(0, 12)
        .toUpperCase()}`,

      target: data.target || key,

      input: key,

      type: data.type || "URL",

      risk: Number(data.risk) || 0,

      riskLevel:
        data.riskLevel || "LOW",

      brand:
        data.brand || "Unknown",

      reports: 1,

      users: 1,

      first: now,

      last: now,

      campaign:
        data.campaign ||
        createCampaignId(
          data.campaignKey || key
        ),

      status:
        data.status || "Analyzed",

      reason:
        data.reason ||
        "Observed by the URL intelligence engine",

      analysis:
        data.analysis || null,
    };
  }

  writeStore(store);

  return store[key];
}

function getThreat(input) {
  const store = readStore();

  return (
    store[String(input).trim().toLowerCase()] ||
    null
  );
}

function getThreatById(id) {
  return Object.values(readStore()).find(
    threat => threat.id === id
  ) || null;
}

function getAllThreats() {
  return Object.values(readStore()).sort(
    (a, b) => {
      if (b.risk !== a.risk) {
        return b.risk - a.risk;
      }

      return String(b.last).localeCompare(
        String(a.last)
      );
    }
  );
}

module.exports = {
  recordThreat,
  getThreat,
  getThreatById,
  getAllThreats,
};
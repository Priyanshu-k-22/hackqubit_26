const crypto = require("node:crypto");

const Threat = require("../models/Threat");
const ScanReport = require("../models/ScanReport");

// ==================================================
// HELPERS
// ==================================================

const normalizeInput = (input) => {
  return String(input || "")
    .trim()
    .toLowerCase();
};

const createCampaignId = () => {
  return `CAM-${crypto
    .randomUUID()
    .replace(/-/g, "")
    .slice(0, 8)
    .toUpperCase()}`;
};

// ==================================================
// RECORD THREAT
// ==================================================

const recordThreat = async (
  input,
  data = {}
) => {
  const normalizedTarget =
    normalizeInput(input);

  if (!normalizedTarget) {
    throw new Error(
      "Threat input cannot be empty"
    );
  }

  const now = new Date();

  const type =
    data.type || "URL";

  const campaign =
    data.campaign ||
    createCampaignId();

  // ==================================================
  // CREATE INDIVIDUAL SCAN REPORT
  // ==================================================

  const scanId =
    `SCN-${crypto
      .randomUUID()
      .replace(/-/g, "")
      .slice(0, 12)
      .toUpperCase()}`;

  const report =
    await ScanReport.create({
      scanId,

      type,

      input:
        data.input ||
        String(input),

      normalizedInput:
        normalizedTarget,

      target:
        data.target || "",

      domain:
        data.domain || "",

      score:
        Number(data.score) || 0,

      riskLevel:
        data.riskLevel ||
        "LOW",

      status:
        data.status ||
        "UNKNOWN",

      reason:
        data.reason || "",

      brand:
        data.brand ||
        "Unknown",

      campaign,

      evidence:
        Array.isArray(
          data.evidence
        )
          ? data.evidence
          : [],

      breakdown:
        data.breakdown || {},

      metadata:
        data.metadata || {},

      reporter:
        data.reporter || null,

      ipAddress:
        data.ipAddress || null,

      userAgent:
        data.userAgent || null,
    });

  // ==================================================
  // UPDATE AGGREGATED THREAT
  // ==================================================

  const threat =
    await Threat.findOneAndUpdate(
      {
        normalizedTarget,
      },

      {
        $setOnInsert: {
          input:
            data.input ||
            String(input),

          normalizedTarget,

          type,

          first:
            now,

          campaign,
        },

        $set: {
          target:
            data.target || "",

          domain:
            data.domain || "",

          brand:
            data.brand ||
            "Unknown",

          score:
            Number(data.score) || 0,

          riskLevel:
            data.riskLevel ||
            "LOW",

          status:
            data.status ||
            "UNKNOWN",

          reason:
            data.reason || "",

          latestReportId:
            report._id,

          latestAnalysis:
            data.analysis || {},

          last:
            now,
        },

        $inc: {
          reports: 1,

          // Currently every scan counts.
          // Later this can use authenticated user IDs.
          users: 1,
        },
      },

      {
        new: true,

        upsert: true,

        setDefaultsOnInsert:
          true,
      }
    );

  // ==================================================
  // RETURN FRONTEND DATA
  // ==================================================

  return {
    id:
      threat._id.toString(),

    reportId:
      report._id.toString(),

    scanId:
      report.scanId,

    reports:
      threat.reports,

    users:
      threat.users,

    first:
      threat.first,

    last:
      threat.last,

    campaign:
      threat.campaign,

    status:
      threat.status,

    risk:
      threat.score,

    riskLevel:
      threat.riskLevel,
  };
};

// ==================================================
// GET ONE THREAT
// ==================================================

const getThreat = async (
  input
) => {
  const normalizedTarget =
    normalizeInput(input);

  return Threat.findOne({
    normalizedTarget,
  }).lean();
};

// ==================================================
// GET ALL THREATS
// ==================================================

const getAllThreats =
  async () => {
    return Threat.find({})
      .sort({
        score: -1,
        last: -1,
      })
      .lean();
  };

// ==================================================
// GET REPORTS
// ==================================================

const getReports = async ({
  page = 1,
  limit = 20,
  type,
  riskLevel,
} = {}) => {
  const filters = {};

  if (type) {
    filters.type =
      type.toUpperCase();
  }

  if (riskLevel) {
    filters.riskLevel =
      riskLevel.toUpperCase();
  }

  const pageNumber =
    Math.max(
      1,
      Number(page) || 1
    );

  const limitNumber =
    Math.min(
      100,
      Math.max(
        1,
        Number(limit) || 20
      )
    );

  const skip =
    (pageNumber - 1) *
    limitNumber;

  const [
    reports,
    total,
  ] = await Promise.all([
    ScanReport.find(filters)
      .sort({
        createdAt: -1,
      })
      .skip(skip)
      .limit(limitNumber)
      .lean(),

    ScanReport.countDocuments(
      filters
    ),
  ]);

  return {
    reports,

    pagination: {
      page: pageNumber,

      limit: limitNumber,

      total,

      pages:
        Math.ceil(
          total /
            limitNumber
        ),
    },
  };
};

// ==================================================
// GET SINGLE REPORT
// ==================================================

const getReportById =
  async (id) => {
    return ScanReport.findById(
      id
    ).lean();
  };

// ==================================================
// EXPORT
// ==================================================

module.exports = {
  recordThreat,
  getThreat,
  getAllThreats,
  getReports,
  getReportById,
};
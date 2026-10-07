const mongoose = require("mongoose");

const scanReportSchema =
  new mongoose.Schema(
    {
      scanId: {
        type: String,
        required: true,
        unique: true,
        index: true,
      },

      type: {
        type: String,
        enum: [
          "URL",
          "UPI",
          "QR",
          "IMAGE",
        ],
        required: true,
        index: true,
      },

      input: {
        type: String,
        required: true,
      },

      normalizedInput: {
        type: String,
        required: true,
        index: true,
      },

      target: {
        type: String,
        default: "",
      },

      domain: {
        type: String,
        default: "",
        index: true,
      },

      score: {
        type: Number,
        min: 0,
        max: 100,
        default: 0,
      },

      riskLevel: {
        type: String,
        enum: [
          "LOW",
          "MEDIUM",
          "HIGH",
          "CRITICAL",
        ],
        default: "LOW",
        index: true,
      },

      status: {
        type: String,
        default: "UNKNOWN",
      },

      reason: {
        type: String,
        default: "",
      },

      brand: {
        type: String,
        default: "Unknown",
      },

      campaign: {
        type: String,
        default: "-",
      },

      evidence: {
        type: [String],
        default: [],
      },

      breakdown: {
        type: mongoose.Schema.Types.Mixed,
        default: {},
      },

      metadata: {
        type: mongoose.Schema.Types.Mixed,
        default: {},
      },

      reporter: {
        type: String,
        default: null,
      },

      ipAddress: {
        type: String,
        default: null,
      },

      userAgent: {
        type: String,
        default: null,
      },
    },
    {
      timestamps: true,
      collection: "scan_reports",
    }
  );

module.exports =
  mongoose.model(
    "ScanReport",
    scanReportSchema
  );
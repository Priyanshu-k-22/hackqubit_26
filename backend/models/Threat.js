const mongoose = require("mongoose");

const threatSchema = new mongoose.Schema(
  {
    // Original/raw input
    input: {
      type: String,
      required: true,
    },

    // Normalized IOC used for deduplication
    normalizedTarget: {
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

    target: {
      type: String,
      default: "",
    },

    domain: {
      type: String,
      default: "",
      index: true,
    },

    brand: {
      type: String,
      default: "Unknown",
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

    campaign: {
      type: String,
      default: "-",
    },

    reports: {
      type: Number,
      default: 0,
    },

    users: {
      type: Number,
      default: 0,
    },

    first: {
      type: Date,
      default: Date.now,
    },

    last: {
      type: Date,
      default: Date.now,
    },

    latestReportId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "ScanReport",
      default: null,
    },

    latestAnalysis: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
  },
  {
    timestamps: true,
    collection: "threats",
  }
);

module.exports =
  mongoose.model(
    "Threat",
    threatSchema
  );
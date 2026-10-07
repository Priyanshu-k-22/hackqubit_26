const express = require("express");

const router = express.Router();

const {
  getAllThreats,
  getThreat,
  getThreatById,
} = require("../services/threatStore");

// GET /api/threats
router.get("/", (req, res) => {
  res.json({
    success: true,
    threats: getAllThreats(),
  });
});

// GET /api/threats/id/:id
router.get("/id/:id", (req, res) => {
  const threat = getThreatById(req.params.id);

  if (!threat) {
    return res.status(404).json({
      message: "Threat not found",
    });
  }

  return res.json({
    success: true,
    threat,
  });
});

// GET /api/threats/lookup?input=example.com
router.get("/lookup", (req, res) => {
  const { input } = req.query;

  if (!input) {
    return res.status(400).json({
      message: "Input is required",
    });
  }

  const threat = getThreat(input);

  if (!threat) {
    return res.status(404).json({
      message: "Threat not found",
    });
  }

  return res.json({
    success: true,
    input,
    ...threat,
  });
});

module.exports = router;
const express = require("express");
const router = express.Router();

const { getAllThreats, getThreat } = require("../services/threatStore");

// Get all known threats
router.get("/", (req, res) => {
  res.json({
    success: true,
    threats: getAllThreats(),
  });
});

// Get one threat by input
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

  res.json({
    success: true,
    input,
    ...threat,
  });
});

module.exports = router;
const express = require("express");

const router =
  express.Router();

const {
  getAllThreats,

  getThreat,

  getReports,

  getReportById,
} = require("../services/threatStore");

/*
|--------------------------------------------------------------------------
| GET /api/threats
|--------------------------------------------------------------------------
|
| Aggregated threats.
|
*/

router.get(
  "/",
  async (req, res) => {
    try {
      const threats =
        await getAllThreats();

      return res.json({
        success: true,

        threats,
      });
    } catch (error) {
      console.error(
        "Get threats error:",
        error
      );

      return res.status(500).json({
        message:
          "Failed to fetch threats",
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| GET /api/threats/lookup
|--------------------------------------------------------------------------
|
| Example:
|
| /api/threats/lookup?input=sbi-login.com
|
*/

router.get(
  "/lookup",
  async (req, res) => {
    try {
      const {
        input,
      } = req.query;

      if (!input) {
        return res.status(400).json({
          message:
            "Input is required",
        });
      }

      const threat =
        await getThreat(
          input
        );

      if (!threat) {
        return res.status(404).json({
          message:
            "Threat not found",
        });
      }

      return res.json({
        success: true,

        input,

        ...threat,
      });
    } catch (error) {
      console.error(
        "Threat lookup error:",
        error
      );

      return res.status(500).json({
        message:
          "Threat lookup failed",
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| GET /api/threats/reports
|--------------------------------------------------------------------------
|
| Every scan stored in MongoDB.
|
| Supports:
|
| ?page=1
| ?limit=20
| ?type=URL
| ?riskLevel=HIGH
|
*/

router.get(
  "/reports",
  async (req, res) => {
    try {
      const {
        page,
        limit,
        type,
        riskLevel,
      } = req.query;

      const result =
        await getReports({
          page,

          limit,

          type,

          riskLevel,
        });

      return res.json({
        success: true,

        ...result,
      });
    } catch (error) {
      console.error(
        "Get reports error:",
        error
      );

      return res.status(500).json({
        message:
          "Failed to fetch reports",
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| GET /api/threats/reports/:id
|--------------------------------------------------------------------------
*/

router.get(
  "/reports/:id",
  async (req, res) => {
    try {
      const report =
        await getReportById(
          req.params.id
        );

      if (!report) {
        return res.status(404).json({
          message:
            "Report not found",
        });
      }

      return res.json({
        success: true,

        report,
      });
    } catch (error) {
      console.error(
        "Get report error:",
        error
      );

      return res.status(500).json({
        message:
          "Failed to fetch report",
      });
    }
  }
);

module.exports = router;
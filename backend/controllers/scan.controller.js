const { analyzeUrl } = require("../services/urlAnalyzer");
const { analyzeUpi } = require("../services/upiAnalyzer");

const scanUrl = (req, res) => {
  try {
    const { url } = req.body;

    if (!url) {
      return res.status(400).json({
        message: "URL is required",
      });
    }

    const result = analyzeUrl(url);

    // Return result directly because frontend expects:
    // res.score, res.breakdown, res.evidence, etc.
    res.json(result);
  } catch (error) {
    console.error("URL scan error:", error);

    res.status(500).json({
      message: "URL scanning failed",
    });
  }
};

const scanUpi = (req, res) => {
  try {
    const { upi } = req.body;

    if (!upi) {
      return res.status(400).json({
        message: "UPI ID is required",
      });
    }

    const result = analyzeUpi(upi);

    // Return result directly
    res.json(result);
  } catch (error) {
    console.error("UPI scan error:", error);

    res.status(500).json({
      message: "UPI scanning failed",
    });
  }
};

module.exports = {
  scanUrl,
  scanUpi,
};
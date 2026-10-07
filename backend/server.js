const express = require("express");
const cors = require("cors");

const app = express();

const PORT = 8000;

// Middleware
app.use(cors());
app.use(express.json());

// Health check
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    message: "UPIShield backend is running",
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`UPIShield backend running on http://localhost:${PORT}`);
});
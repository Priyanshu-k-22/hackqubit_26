const express = require("express");
const cors = require("cors");
const fs = require("node:fs");
const path = require("node:path");

const envFile = path.join(__dirname, ".env");
if (fs.existsSync(envFile)) process.loadEnvFile(envFile);

const scanRoutes = require("./routes/scan.routes"); 
const threatRoutes = require("./routes/threat.routes");
const app = express();

const PORT = 8000;

// Middleware
app.use(cors());
app.use(express.json({ limit: "16kb" }));


// Health check
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    message: "UPIShield backend is running",
  });
});

app.use("/api/scan", scanRoutes);
app.use("/api/threats", threatRoutes);


// Start server
app.listen(PORT, () => {
  console.log(`UPIShield backend running on http://localhost:${PORT}`);
});

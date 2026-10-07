const express = require("express");
const cors = require("cors");
const fs = require("node:fs");
const path = require("node:path");
const mongoose = require("mongoose");

// ==================================================
// LOAD ENV
// ==================================================

const envFile = path.join(
  __dirname,
  ".env"
);

if (fs.existsSync(envFile)) {
  process.loadEnvFile(envFile);
}

// ==================================================
// IMPORTS
// ==================================================

const connectDB =
  require("./config/db");

const scanRoutes =
  require("./routes/scan.routes");

const threatRoutes =
  require("./routes/threat.routes");

// ==================================================
// APP
// ==================================================

const app = express();

const PORT =
  process.env.PORT || 8000;

// ==================================================
// MIDDLEWARE
// ==================================================

app.use(cors());

app.use(
  express.json({
    limit: "16kb",
  })
);

// ==================================================
// HEALTH
// ==================================================

app.get(
  "/api/health",
  (req, res) => {
    const dbState =
      mongoose.connection.readyState;

    res.json({
      status: "ok",

      message:
        "UPIShield backend is running",

      database: {
        status:
          dbState === 1
            ? "connected"
            : "disconnected",
      },

      port: PORT,
    });
  }
);

// ==================================================
// SCAN ROUTES
// ==================================================

console.log(
  "Registering /api/scan routes..."
);

app.use(
  "/api/scan",
  scanRoutes
);

// ==================================================
// THREAT ROUTES
// ==================================================

console.log(
  "Registering /api/threats routes..."
);

app.use(
  "/api/threats",
  threatRoutes
);

// ==================================================
// 404
// ==================================================

app.use(
  (req, res) => {
    console.log(
      `404 -> ${req.method} ${req.originalUrl}`
    );

    res.status(404).json({
      success: false,

      message:
        `Route not found: ${req.method} ${req.originalUrl}`,
    });
  }
);

// ==================================================
// ERROR HANDLER
// ==================================================

app.use(
  (
    err,
    req,
    res,
    next
  ) => {
    console.error(
      "Unhandled error:"
    );

    console.error(err);

    res.status(500).json({
      success: false,

      message:
        "Internal server error",

      error:
        process.env.NODE_ENV ===
        "development"
          ? err.message
          : undefined,
    });
  }
);

// ==================================================
// START SERVER
// ==================================================

const startServer =
  async () => {
    try {
      // ------------------------------------------
      // Connect MongoDB FIRST
      // ------------------------------------------

      await connectDB();

      // ------------------------------------------
      // Start Express
      // ------------------------------------------

      app.listen(
        PORT,
        () => {
          console.log("");
          console.log(
            "===================================="
          );

          console.log(
            "UPIShield backend started"
          );

          console.log(
            `http://localhost:${PORT}`
          );

          console.log(
            "MongoDB connected"
          );

          console.log(
            "===================================="
          );

          console.log("");
        }
      );
    } catch (error) {
      console.error("");
      console.error(
        "===================================="
      );

      console.error(
        "SERVER STARTUP FAILED"
      );

      console.error(
        error
      );

      console.error(
        "===================================="
      );

      process.exit(1);
    }
  };

startServer();
require("dotenv").config();

const express = require("express");
const cors = require("cors");

const otpRouter = require("./routes/otp");
const kycRouter = require("./routes/kyc");
const kentPayRouter = require("./routes/kentPay");
const transferRouter = require("./routes/transfers");

const app = express();

const PORT =
  process.env.PORT || 3000;

app.set("trust proxy", 1);

// ============================================================
// CORS
// ============================================================

app.use(
  cors({
    origin: true,

    methods: [
      "GET",
      "POST",
      "OPTIONS",
    ],

    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "Accept",
      "X-Trace-Id",
      "X-Idempotency-Key",
    ],
  })
);

// ============================================================
// BODY PARSING
// ============================================================
//
// IMPORTANT:
//
// The rawBody is preserved because Flutterwave webhook
// signature verification requires the exact raw request body.
//
// Normal JSON requests continue to use req.body normally.
// ============================================================

app.use(
  express.json({
    limit: "1mb",

    verify: (
      req,
      res,
      buf
    ) => {
      req.rawBody =
        buf.toString("utf8");
    },
  })
);

app.use(
  express.urlencoded({
    extended: true,

    verify: (
      req,
      res,
      buf
    ) => {
      if (!req.rawBody) {
        req.rawBody =
          buf.toString("utf8");
      }
    },
  })
);

// ============================================================
// REQUEST LOGGING
// ============================================================

app.use(
  (req, res, next) => {
    console.log(
      `[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`
    );

    next();
  }
);

// ============================================================
// ROOT
// ============================================================

app.get(
  "/",
  (req, res) => {
    return res.status(200).json({
      success: true,

      service:
        "KENT Backend",

      status:
        "online",

      message:
        "KENT Nexus API is running.",

      timestamp:
        new Date().toISOString(),
    });
  }
);

// ============================================================
// HEALTH
// ============================================================

app.get(
  "/health",
  (req, res) => {
    return res.status(200).json({
      success: true,

      status:
        "healthy",

      service:
        "kent-backend",

      timestamp:
        new Date().toISOString(),
    });
  }
);

// ============================================================
// API ROUTES
// ============================================================

app.use(
  "/api/otp",
  otpRouter
);

app.use(
  "/api/kyc",
  kycRouter
);

app.use(
  "/api/kent-pay",
  kentPayRouter
);

// ============================================================
// KENT TRANSFER API
// ============================================================
//
// GET  /api/transfers/banks
// POST /api/transfers/resolve-account
// POST /api/transfers/send
// GET  /api/transfers/status/:transferId
// POST /api/transfers/webhook
//
// ============================================================

app.use(
  "/api/transfers",
  transferRouter
);

// ============================================================
// 404
// ============================================================

app.use(
  (req, res) => {
    return res.status(404).json({
      success: false,

      message:
        "KENT API endpoint not found.",

      path:
        req.originalUrl,
    });
  }
);

// ============================================================
// GLOBAL ERROR HANDLER
// ============================================================

app.use(
  (
    error,
    req,
    res,
    next
  ) => {
    console.error(
      "GLOBAL ERROR:",
      error
    );

    if (
      res.headersSent
    ) {
      return next(error);
    }

    return res.status(500).json({
      success: false,

      message:
        "Internal server error.",
    });
  }
);

// ============================================================
// START SERVER
// ============================================================

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      "=================================================="
    );

    console.log(
      "KENT BACKEND STARTED"
    );

    console.log(
      "=================================================="
    );

    console.log(
      `Port: ${PORT}`
    );

    console.log(
      `Environment: ${
        process.env.NODE_ENV ||
        "development"
      }`
    );

    console.log(
      "OTP API: /api/otp"
    );

    console.log(
      "KYC API: /api/kyc"
    );

    console.log(
      "KENT PAY API: /api/kent-pay"
    );

    console.log(
      "TRANSFER API: /api/transfers"
    );

    console.log(
      "Health: /health"
    );

    console.log(
      "=================================================="
    );
  }
);

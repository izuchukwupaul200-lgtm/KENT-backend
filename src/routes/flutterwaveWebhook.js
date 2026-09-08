const express = require("express");

const {
  handleFlutterwaveWebhook,
} = require("../controllers/flutterwaveWebhookController");

const router = express.Router();

// ============================================================
// FLUTTERWAVE WEBHOOK
// ============================================================
//
// POST /api/flutterwave/webhook
//
// Flutterwave sends incoming payment notifications here.
//
// ============================================================

router.post(
  "/webhook",
  handleFlutterwaveWebhook
);

// ============================================================
// EXPORT
// ============================================================

module.exports = router;


const express = require("express");

const authenticateUser = require("../middleware/authMiddleware");

const {
  getMyKentPayAccount,
  getMyKentPayStatus,
} = require("../controllers/kentPayController");

const router = express.Router();

// ============================================================
// GET MY KENT PAY ACCOUNT
// ============================================================
//
// GET /api/kent-pay/me
//
// Returns the authenticated user's KENT Pay
// virtual account details.
// ============================================================

router.get(
  "/me",
  authenticateUser,
  getMyKentPayAccount
);

// ============================================================
// GET MY KENT PAY STATUS
// ============================================================
//
// GET /api/kent-pay/status
//
// Returns whether KENT Pay is activated and
// whether the virtual account is ready.
// ============================================================

router.get(
  "/status",
  authenticateUser,
  getMyKentPayStatus
);

// ============================================================
// EXPORT
// ============================================================

module.exports = router;
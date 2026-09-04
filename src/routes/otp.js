
const express = require("express");
const { sendOTP, verifyOTP } = require("../services/otp_service");

const router = express.Router();

// ============================================================
// SEND OTP
// POST /api/otp/send
// ============================================================

router.post("/send", async (req, res) => {
  try {
    const { phone, purpose = "registration" } = req.body;

    if (!phone) {
      return res.status(400).json({
        success: false,
        message: "Phone number is required.",
      });
    }

    console.log("======================================");
    console.log("KENT OTP SEND REQUEST");
    console.log("Phone:", phone);
    console.log("Purpose:", purpose);
    console.log("======================================");

    await sendOTP(phone);

    return res.status(200).json({
      success: true,
      message: "Verification code sent successfully.",
    });
  } catch (error) {
    console.error("OTP SEND ERROR:", error.response?.data || error.message);

    return res.status(500).json({
      success: false,
      message: "Unable to send verification code.",
    });
  }
});

// ============================================================
// VERIFY OTP
// POST /api/otp/verify
// ============================================================

router.post("/verify", (req, res) => {
  try {
    const { phone, otp } = req.body;

    const result = verifyOTP(phone, otp);

    if (!result.success) {
      return res.status(400).json(result);
    }

    return res.status(200).json(result);
  } catch (error) {
    console.error("OTP VERIFY ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to verify OTP.",
    });
  }
});

// ============================================================
// STATUS
// GET /api/otp/status
// ============================================================

router.get("/status", (req, res) => {
  res.status(200).json({
    success: true,
    service: "KENT OTP",
    sendchampConfigured: Boolean(process.env.SENDCHAMP_API_KEY),
  });
});

module.exports = router;
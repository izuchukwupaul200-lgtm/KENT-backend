const crypto = require("crypto");
const { sendSMS } = require("./sendchamp_service");

// ============================================================
// TEMPORARY OTP STORAGE
// ============================================================

const otpStore = new Map();

// ============================================================
// GENERATE 6-DIGIT OTP
// ============================================================

function generateOTP() {
  return crypto.randomInt(100000, 1000000).toString();
}

// ============================================================
// SEND OTP
// ============================================================

async function sendOTP(phoneNumber) {
  if (!phoneNumber) {
    throw new Error("Phone number is required");
  }

  const otp = generateOTP();

  console.log("======================================");
  console.log("KENT OTP SERVICE");
  console.log("======================================");
  console.log("Generating OTP for:", phoneNumber);

  await sendSMS({
    phoneNumber,
    message:
      `Your KENT verification code is ${otp}. ` +
      "Do not share this code with anyone.",
    route: "non_dnd",
  });

  otpStore.set(phoneNumber, {
    code: otp,
    expiresAt: Date.now() + 5 * 60 * 1000,
    attempts: 0,
  });

  console.log("OTP stored successfully");
  console.log("OTP expires in 5 minutes");
  console.log("======================================");

  return true;
}

// ============================================================
// VERIFY OTP
// ============================================================

function verifyOTP(phoneNumber, code) {
  if (!phoneNumber || !code) {
    return {
      success: false,
      message: "Phone number and verification code are required",
    };
  }

  const savedOTP = otpStore.get(phoneNumber);

  if (!savedOTP) {
    return {
      success: false,
      message: "No verification code found. Please request a new code.",
    };
  }

  if (Date.now() > savedOTP.expiresAt) {
    otpStore.delete(phoneNumber);

    return {
      success: false,
      message: "Verification code has expired. Please request a new code.",
    };
  }

  if (savedOTP.attempts >= 5) {
    otpStore.delete(phoneNumber);

    return {
      success: false,
      message: "Too many attempts. Please request a new code.",
    };
  }

  if (savedOTP.code !== code.toString()) {
    savedOTP.attempts += 1;

    return {
      success: false,
      message: "Incorrect verification code.",
    };
  }

  otpStore.delete(phoneNumber);

  console.log("======================================");
  console.log("KENT OTP VERIFIED");
  console.log("Phone:", phoneNumber);
  console.log("======================================");

  return {
    success: true,
    message: "Phone number verified successfully.",
  };
}

// ============================================================
// EXPORT
// ============================================================

module.exports = {
  sendOTP,
  verifyOTP,
};
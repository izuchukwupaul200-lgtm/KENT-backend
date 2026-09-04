const express = require("express");
const crypto = require("crypto");
const axios = require("axios");

const { auth, db } = require("../firebaseAdmin");

const router = express.Router();

// ============================================================
// CONFIGURATION
// ============================================================

const NINJA_BASE_URL =
  process.env.NINJA_BASE_URL ||
  "https://api.ninja.boucloud.io";

const NINJA_CLIENT_KEY =
  process.env.NINJA_CLIENT_KEY;

const NINJA_CLIENT_SECRET =
  process.env.NINJA_CLIENT_SECRET;

// ============================================================
// SETTINGS
// ============================================================

const NINJA_TOKEN_LIFETIME_MS =
  4 * 60 * 1000;

const KYC_DUPLICATE_WINDOW_MS =
  24 * 60 * 60 * 1000;

const REQUEST_TIMEOUT_MS =
  45000;

// ============================================================
// IN-MEMORY LOCKS
// ============================================================
//
// Prevents duplicate requests while the same server instance
// is processing a KYC request.
//
// Firestore also stores the verification reference so the same
// verification is not unnecessarily repeated after deployment.
//
// ============================================================

const activeRequests = new Map();

// ============================================================
// NINJA TOKEN CACHE
// ============================================================

let ninjaSessionToken = null;
let ninjaSessionExpiresAt = 0;

// ============================================================
// BASIC VALIDATION
// ============================================================

function isElevenDigits(value) {
  return /^\d{11}$/.test(value);
}

function cleanString(value) {
  return typeof value === "string"
    ? value.trim()
    : "";
}

function isValidName(value) {
  if (!value) return false;

  return /^[A-Za-zÀ-ÿ' -]{2,80}$/.test(
    value
  );
}

function isValidDateOfBirth(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    return false;
  }

  const date = new Date(`${value}T00:00:00Z`);

  if (Number.isNaN(date.getTime())) {
    return false;
  }

  return true;
}

// ============================================================
// SAFE ERROR MESSAGE
// ============================================================

function extractNinjaMessage(error) {
  if (!error) {
    return "KYC provider error.";
  }

  const responseData =
    error.response &&
    error.response.data;

  if (
    responseData &&
    typeof responseData === "object"
  ) {
    if (
      typeof responseData.message ===
      "string"
    ) {
      return responseData.message;
    }

    if (
      responseData.error &&
      typeof responseData.error.message ===
        "string"
    ) {
      return responseData.error.message;
    }

    if (
      typeof responseData.error ===
      "string"
    ) {
      return responseData.error;
    }
  }

  if (
    typeof error.message === "string" &&
    error.message.trim()
  ) {
    return error.message;
  }

  return "KYC provider error.";
}

// ============================================================
// HASH ID
// ============================================================
//
// We do not put the raw BVN/NIN into logs or duplicate keys.
//
// ============================================================

function hashIdentity(idType, idNumber) {
  return crypto
    .createHash("sha256")
    .update(
      `${idType}:${idNumber}`
    )
    .digest("hex");
}

// ============================================================
// FIREBASE AUTH MIDDLEWARE
// ============================================================

async function requireAuth(
  req,
  res,
  next
) {
  try {
    const header =
      req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        verified: false,
        message:
          "Authentication required.",
      });
    }

    const token =
      header.substring(7).trim();

    if (!token) {
      return res.status(401).json({
        success: false,
        verified: false,
        message:
          "Authentication token is missing.",
      });
    }

    const decoded =
      await auth.verifyIdToken(token);

    req.user = decoded;

    next();
  } catch (error) {
    console.error(
      "KENT AUTH ERROR:",
      error.message
    );

    return res.status(401).json({
      success: false,
      verified: false,
      message:
        "Your login session is invalid or expired.",
    });
  }
}

// ============================================================
// FIRESTORE USER REFERENCE
// ============================================================

function getUserRef(uid) {
  return db.collection("users").doc(uid);
}

// ============================================================
// GET USER KYC DATA
// ============================================================

async function getUserData(uid) {
  const snapshot =
    await getUserRef(uid).get();

  if (!snapshot.exists) {
    return {};
  }

  return snapshot.data() || {};
}

// ============================================================
// NINJA AUTHENTICATION
// ============================================================

async function getNinjaSessionToken(
  forceRefresh = false
) {
  if (
    !forceRefresh &&
    ninjaSessionToken &&
    Date.now() <
      ninjaSessionExpiresAt
  ) {
    return ninjaSessionToken;
  }

  if (
    !NINJA_CLIENT_KEY ||
    !NINJA_CLIENT_SECRET
  ) {
    throw new Error(
      "Ninja credentials are not configured on the server."
    );
  }

  const response =
    await axios.post(
      `${NINJA_BASE_URL}/auth/session`,
      {
        client_key:
          NINJA_CLIENT_KEY,

        client_secret:
          NINJA_CLIENT_SECRET,
      },
      {
        headers: {
          "Content-Type":
            "application/json",
          Accept:
            "application/json",
        },

        timeout:
          REQUEST_TIMEOUT_MS,
      }
    );

  const token =
    response.data &&
    response.data.token;

  if (
    typeof token !== "string" ||
    !token.trim()
  ) {
    throw new Error(
      "Ninja did not return a session token."
    );
  }

  ninjaSessionToken =
    token.trim();

  ninjaSessionExpiresAt =
    Date.now() +
    NINJA_TOKEN_LIFETIME_MS;

  return ninjaSessionToken;
}

// ============================================================
// NINJA IDENTITY VERIFY
// ============================================================

async function ninjaVerifyIdentity({
  idType,
  idNumber,
  firstName,
  lastName,
  dateOfBirth,
  reference,
}) {
  let token =
    await getNinjaSessionToken();

  const payload = {
    idType,
    mode: "verify",
    idNumber,
    firstName,
    lastName,
    dateOfBirth,
    reference,
  };

  try {
    const response =
      await axios.post(
        `${NINJA_BASE_URL}/api/identity/identify`,
        payload,
        {
          headers: {
            Authorization:
              `Bearer ${token}`,

            "Content-Type":
              "application/json",

            Accept:
              "application/json",
          },

          timeout:
            REQUEST_TIMEOUT_MS,
        }
      );

    return response.data;
  } catch (error) {
    // ========================================================
    // TOKEN EXPIRED
    // ========================================================

    if (
      error.response &&
      error.response.status === 401
    ) {
      token =
        await getNinjaSessionToken(
          true
        );

      const retryResponse =
        await axios.post(
          `${NINJA_BASE_URL}/api/identity/identify`,
          payload,
          {
            headers: {
              Authorization:
                `Bearer ${token}`,

              "Content-Type":
                "application/json",

              Accept:
                "application/json",
            },

            timeout:
              REQUEST_TIMEOUT_MS,
          }
        );

      return retryResponse.data;
    }

    throw error;
  }
}

// ============================================================
// DUPLICATE / COOLDOWN CHECK
// ============================================================

async function checkRecentVerification(
  uid,
  idType,
  identityHash
) {
  const userData =
    await getUserData(uid);

  const field =
    idType === "bvn"
      ? "bvnVerification"
      : "ninVerification";

  const previous =
    userData[field];

  if (!previous) {
    return {
      duplicate: false,
    };
  }

  if (
    previous.identityHash !==
    identityHash
  ) {
    return {
      duplicate: false,
    };
  }

  const verifiedAt =
    previous.verifiedAt;

  if (!verifiedAt) {
    return {
      duplicate: false,
    };
  }

  let verifiedTime = 0;

  if (
    typeof verifiedAt.toMillis ===
    "function"
  ) {
    verifiedTime =
      verifiedAt.toMillis();
  } else if (
    typeof verifiedAt ===
    "string"
  ) {
    verifiedTime =
      new Date(
        verifiedAt
      ).getTime();
  } else if (
    typeof verifiedAt ===
    "number"
  ) {
    verifiedTime =
      verifiedAt;
  }

  if (!verifiedTime) {
    return {
      duplicate: false,
    };
  }

  const age =
    Date.now() -
    verifiedTime;

  if (
    age <
    KYC_DUPLICATE_WINDOW_MS
  ) {
    return {
      duplicate: true,
      previous,
    };
  }

  return {
    duplicate: false,
  };
}

// ============================================================
// REQUEST LOCK
// ============================================================

function getRequestLockKey(
  uid,
  idType,
  identityHash
) {
  return `${uid}:${idType}:${identityHash}`;
}

// ============================================================
// GENERATE REFERENCE
// ============================================================

function generateReference(
  uid,
  idType,
  identityHash
) {
  const shortUid =
    uid.substring(0, 12);

  const shortHash =
    identityHash.substring(0, 16);

  return `kent-${idType}-${shortUid}-${shortHash}`;
}

// ============================================================
// SAVE KYC RESULT
// ============================================================

async function saveKycResult({
  uid,
  idType,
  identityHash,
  verified,
  score,
  recommendation,
}) {
  const userRef =
    getUserRef(uid);

  const now =
    new Date();

  const update = {};

  if (idType === "bvn") {
    update.bvnVerified =
      verified;

    update.bvnVerifiedAt =
      verified
        ? now
        : null;

    update.bvnVerification = {
      identityHash,
      verified,
      score:
        typeof score === "number"
          ? score
          : null,
      recommendation:
        recommendation || null,
      verifiedAt:
        verified
          ? now
          : null,
    };
  }

  if (idType === "nin") {
    update.ninVerified =
      verified;

    update.ninVerifiedAt =
      verified
        ? now
        : null;

    update.ninVerification = {
      identityHash,
      verified,
      score:
        typeof score === "number"
          ? score
          : null,
      recommendation:
        recommendation || null,
      verifiedAt:
        verified
          ? now
          : null,
    };
  }

  // ==========================================================
  // CHECK BOTH KYC STATES
  // ==========================================================

  const current =
    await userRef.get();

  const currentData =
    current.exists
      ? current.data() || {}
      : {};

  const finalBvnVerified =
    idType === "bvn"
      ? verified
      : currentData.bvnVerified === true;

  const finalNinVerified =
    idType === "nin"
      ? verified
      : currentData.ninVerified === true;

  const activated =
    finalBvnVerified &&
    finalNinVerified;

  update.kycStatus =
    activated
      ? "verified"
      : finalBvnVerified ||
          finalNinVerified
        ? "partial"
        : "pending";

  update.kentPayActivated =
    activated;

  if (activated) {
    update.kycVerifiedAt =
      currentData.kycVerifiedAt ||
      now;
  } else {
    update.kycVerifiedAt = null;
  }

  await userRef.set(
    update,
    {
      merge: true,
    }
  );

  return activated;
}

// ============================================================
// COMMON VERIFICATION HANDLER
// ============================================================

async function verifyIdentity(
  req,
  res,
  idType
) {
  const uid =
    req.user.uid;

  const rawId =
    cleanString(
      idType === "bvn"
        ? req.body.bvn
        : req.body.nin
    );

  const firstName =
    cleanString(
      req.body.firstName
    );

  const lastName =
    cleanString(
      req.body.lastName
    );

  const dateOfBirth =
    cleanString(
      req.body.dateOfBirth
    );

  // ==========================================================
  // VALIDATE ID
  // ==========================================================

  if (!isElevenDigits(rawId)) {
    return res.status(400).json({
      success: false,
      verified: false,
      message:
        `${idType.toUpperCase()} must contain exactly 11 digits.`,
    });
  }

  // ==========================================================
  // VALIDATE NAME
  // ==========================================================

  if (!isValidName(firstName)) {
    return res.status(400).json({
      success: false,
      verified: false,
      message:
        "A valid first name is required.",
    });
  }

  if (!isValidName(lastName)) {
    return res.status(400).json({
      success: false,
      verified: false,
      message:
        "A valid last name is required.",
    });
  }

  // ==========================================================
  // VALIDATE DOB
  // ==========================================================

  if (!isValidDateOfBirth(dateOfBirth)) {
    return res.status(400).json({
      success: false,
      verified: false,
      message:
        "Date of birth must use YYYY-MM-DD format.",
    });
  }

  // ==========================================================
  // HASH
  // ==========================================================

  const identityHash =
    hashIdentity(
      idType,
      rawId
    );

  // ==========================================================
  // REQUEST LOCK
  // ==========================================================

  const lockKey =
    getRequestLockKey(
      uid,
      idType,
      identityHash
    );

  if (activeRequests.has(lockKey)) {
    return res.status(409).json({
      success: false,
      verified: false,
      message:
        "This verification request is already being processed. Please wait.",
    });
  }

  activeRequests.set(
    lockKey,
    Date.now()
  );

  try {
    // ========================================================
    // IF ALREADY VERIFIED
    // ========================================================

    const existing =
      await checkRecentVerification(
        uid,
        idType,
        identityHash
      );

    if (existing.duplicate) {
      const userData =
        await getUserData(uid);

      const activated =
        userData.kentPayActivated === true;

      return res.status(200).json({
        success: true,
        verified: true,
        alreadyVerified: true,
        kentPayActivated:
          activated,
        message:
          `${idType.toUpperCase()} is already verified.`,
      });
    }

    // ========================================================
    // REFERENCE
    // ========================================================

    const reference =
      generateReference(
        uid,
        idType,
        identityHash
      );

    // ========================================================
    // LOG SAFE INFORMATION ONLY
    // ========================================================

    console.log(
      `KENT ${idType.toUpperCase()} verification started`,
      {
        uid,
        reference,
      }
    );

    // ========================================================
    // CALL NINJA
    // ========================================================

    let result;

    try {
      result =
        await ninjaVerifyIdentity({
          idType,
          idNumber: rawId,
          firstName,
          lastName,
          dateOfBirth,
          reference,
        });
    } catch (error) {
      const providerStatus =
        error.response &&
        error.response.status;

      const providerMessage =
        extractNinjaMessage(
          error
        );

      console.error(
        `KENT ${idType.toUpperCase()} NINJA ERROR`,
        {
          status:
            providerStatus || null,
          message:
            providerMessage,
        }
      );

      // ======================================================
      // INSUFFICIENT BALANCE
      // ======================================================

      if (
        providerStatus === 402 ||
        /insufficient.*balance/i.test(
          providerMessage
        ) ||
        /insufficient.*wallet/i.test(
          providerMessage
        )
      ) {
        return res.status(402).json({
          success: false,
          verified: false,
          code:
            "KYC_PROVIDER_INSUFFICIENT_BALANCE",
          message:
            "KYC verification is temporarily unavailable because the KYC provider wallet has insufficient balance. Please try again later.",
        });
      }

      // ======================================================
      // RATE LIMIT
      // ======================================================

      if (
        providerStatus === 429
      ) {
        return res.status(429).json({
          success: false,
          verified: false,
          code:
            "KYC_PROVIDER_RATE_LIMIT",
          message:
            "Too many verification requests. Please wait a moment and try again.",
        });
      }

      // ======================================================
      // AUTH ERROR
      // ======================================================

      if (
        providerStatus === 401
      ) {
        return res.status(502).json({
          success: false,
          verified: false,
          code:
            "KYC_PROVIDER_AUTH_ERROR",
          message:
            "KYC provider authentication failed. Please contact KENT support.",
        });
      }

      // ======================================================
      // OTHER PROVIDER ERROR
      // ======================================================

      return res.status(502).json({
        success: false,
        verified: false,
        code:
          "KYC_PROVIDER_ERROR",
        message:
          "The KYC verification service could not complete the request. Please try again later.",
      });
    }

    // ========================================================
    // NORMALIZE RESULT
    // ========================================================

    const verified =
      result &&
      result.verified === true;

    const found =
      result &&
      result.found !== false;

    const score =
      result &&
      typeof result.score ===
        "number"
        ? result.score
        : null;

    const recommendation =
      result &&
      typeof result.recommendation ===
        "string"
        ? result.recommendation
        : null;

    // ========================================================
    // SAVE RESULT
    // ========================================================

    const activated =
      await saveKycResult({
        uid,
        idType,
        identityHash,
        verified,
        score,
        recommendation,
      });

    // ========================================================
    // VERIFICATION PASSED
    // ========================================================

    if (verified) {
      console.log(
        `KENT ${idType.toUpperCase()} VERIFIED`,
        {
          uid,
          reference,
          score,
          recommendation,
          kentPayActivated:
            activated,
        }
      );

      return res.status(200).json({
        success: true,
        verified: true,
        found: true,
        alreadyVerified: false,
        score,
        recommendation,
        kentPayActivated:
          activated,
        message:
          activated
            ? "Identity verified successfully. KENT Pay has been activated."
            : `${idType.toUpperCase()} verified successfully.`,
      });
    }

    // ========================================================
    // VERIFICATION FAILED
    // ========================================================

    console.log(
      `KENT ${idType.toUpperCase()} NOT VERIFIED`,
      {
        uid,
        reference,
        score,
        recommendation,
        found,
      }
    );

    return res.status(200).json({
      success: true,
      verified: false,
      found,
      alreadyVerified: false,
      score,
      recommendation,
      kentPayActivated:
        activated,
      message:
        recommendation === "review"
          ? "Your identity could not be automatically verified and requires review."
          : "The identity details did not pass verification. Please check that your name and date of birth exactly match your identity record.",
    });
  } catch (error) {
    console.error(
      `KENT ${idType.toUpperCase()} ROUTE ERROR:`,
      error.message
    );

    return res.status(500).json({
      success: false,
      verified: false,
      message:
        "An unexpected server error occurred during KYC verification.",
    });
  } finally {
    activeRequests.delete(
      lockKey
    );
  }
}

// ============================================================
// BVN
// ============================================================

router.post(
  "/bvn",
  requireAuth,
  async (req, res) => {
    return verifyIdentity(
      req,
      res,
      "bvn"
    );
  }
);

// ============================================================
// NIN
// ============================================================

router.post(
  "/nin",
  requireAuth,
  async (req, res) => {
    return verifyIdentity(
      req,
      res,
      "nin"
    );
  }
);

// ============================================================
// KYC STATUS
// ============================================================

router.get(
  "/status/me",
  requireAuth,
  async (req, res) => {
    try {
      const uid =
        req.user.uid;

      const data =
        await getUserData(uid);

      return res.status(200).json({
        success: true,

        bvnVerified:
          data.bvnVerified === true,

        ninVerified:
          data.ninVerified === true,

        kycStatus:
          data.kycStatus ||
          "pending",

        kentPayActivated:
          data.kentPayActivated === true,

        bvnVerifiedAt:
          data.bvnVerifiedAt || null,

        ninVerifiedAt:
          data.ninVerifiedAt || null,

        kycVerifiedAt:
          data.kycVerifiedAt || null,
      });
    } catch (error) {
      console.error(
        "KENT KYC STATUS ERROR:",
        error.message
      );

      return res.status(500).json({
        success: false,
        message:
          "Could not load KYC status.",
      });
    }
  }
);

// ============================================================
// KENT PAY STATUS
// ============================================================

router.get(
  "/kent-pay/me",
  requireAuth,
  async (req, res) => {
    try {
      const uid =
        req.user.uid;

      const data =
        await getUserData(uid);

      const bvnVerified =
        data.bvnVerified === true;

      const ninVerified =
        data.ninVerified === true;

      const activated =
        bvnVerified &&
        ninVerified;

      // Keep activation consistent.
      if (
        data.kentPayActivated !==
        activated
      ) {
        await getUserRef(uid).set(
          {
            kentPayActivated:
              activated,
          },
          {
            merge: true,
          }
        );
      }

      return res.status(200).json({
        success: true,
        bvnVerified,
        ninVerified,
        kentPayActivated:
          activated,
        kycStatus:
          activated
            ? "verified"
            : bvnVerified ||
                ninVerified
              ? "partial"
              : "pending",
      });
    } catch (error) {
      console.error(
        "KENT PAY STATUS ERROR:",
        error.message
      );

      return res.status(500).json({
        success: false,
        message:
          "Could not load KENT Pay status.",
      });
    }
  }
);

// ============================================================
// NINJA CONNECTION TEST
// ============================================================
//
// This only authenticates with Ninja.
// It does NOT perform a BVN/NIN lookup.
// Therefore it does not spend a KYC verification charge.
//
// ============================================================

router.get(
  "/ninja-test",
  requireAuth,
  async (req, res) => {
    try {
      await getNinjaSessionToken();

      return res.status(200).json({
        success: true,
        message:
          "KENT backend successfully authenticated with Ninja.",
        baseUrl:
          NINJA_BASE_URL,
      });
    } catch (error) {
      console.error(
        "KENT NINJA TEST ERROR:",
        error.message
      );

      return res.status(502).json({
        success: false,
        message:
          "KENT could not authenticate with Ninja.",
      });
    }
  }
);

// ============================================================
// 404 FOR KYC ROUTES
// ============================================================

router.use(
  (req, res) => {
    return res.status(404).json({
      success: false,
      message:
        "KYC endpoint not found.",
    });
  }
);

module.exports = router;
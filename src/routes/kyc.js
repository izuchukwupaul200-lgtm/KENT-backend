const express = require("express");
const crypto = require("crypto");
const axios = require("axios");

const { auth, db } = require("../../firebaseAdmin");

const {
  ensureKentPayVirtualAccount,
  getKentPayVirtualAccount,
} = require("../services/kentPayService");

const router = express.Router();

// ============================================================
// KENT PRODUCTION KYC - NINJA
// ============================================================
//
// LIVE:
// https://api.ninja.boucloud.io
//
// REQUIRED RENDER ENVIRONMENT VARIABLES:
//
// NINJA_CLIENT_KEY
// NINJA_CLIENT_SECRET
// NINJA_BASE_URL=https://api.ninja.boucloud.io
//
// KENT KYC ENCRYPTION:
//
// KENT_KYC_ENCRYPTION_KEY
//
// Must be exactly 64 hexadecimal characters.
//
// Generate locally:
//
// node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
//
// IMPORTANT:
//
// - Never send BVN/NIN back to Flutter.
// - Never log BVN/NIN.
// - Never store BVN/NIN as plaintext.
// - The encryption key stays only on Render.
// ============================================================


// ============================================================
// CONFIGURATION
// ============================================================

const NINJA_BASE_URL = (
  process.env.NINJA_BASE_URL ||
  "https://api.ninja.boucloud.io"
).replace(/\/+$/, "");

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
// IN-MEMORY REQUEST LOCK
// ============================================================

const activeRequests =
  new Map();


// ============================================================
// NINJA SESSION TOKEN CACHE
// ============================================================

let ninjaSessionToken = null;

let ninjaSessionExpiresAt = 0;


// ============================================================
// BASIC VALIDATION
// ============================================================

function cleanString(value) {
  if (
    typeof value !==
    "string"
  ) {
    return "";
  }

  return value.trim();
}


function isElevenDigits(value) {
  return /^\d{11}$/.test(
    value
  );
}


function isValidName(value) {
  if (!value) {
    return false;
  }

  return /^[A-Za-zÀ-ÿ' -]{2,80}$/.test(
    value
  );
}


function isValidDateOfBirth(value) {
  if (
    !/^\d{4}-\d{2}-\d{2}$/.test(
      value
    )
  ) {
    return false;
  }

  const date =
    new Date(
      `${value}T00:00:00.000Z`
    );

  if (
    Number.isNaN(
      date.getTime()
    )
  ) {
    return false;
  }

  const normalized =
    date
      .toISOString()
      .slice(0, 10);

  return normalized === value;
}


// ============================================================
// KYC ENCRYPTION KEY
// ============================================================

function getKycEncryptionKey() {
  const key =
    process.env.KENT_KYC_ENCRYPTION_KEY;

  if (!key) {
    throw new Error(
      "KENT_KYC_ENCRYPTION_KEY is missing from the backend environment."
    );
  }

  if (
    !/^[0-9a-fA-F]{64}$/.test(
      key
    )
  ) {
    throw new Error(
      "KENT_KYC_ENCRYPTION_KEY must contain exactly 64 hexadecimal characters."
    );
  }

  return Buffer.from(
    key,
    "hex"
  );
}


// ============================================================
// ENCRYPT SENSITIVE KYC VALUE
// ============================================================
//
// Format:
//
// v1:iv:authTag:ciphertext
//
// AES-256-GCM
// ============================================================

function encryptKycValue(
  value
) {
  if (!value) {
    throw new Error(
      "Cannot encrypt an empty KYC value."
    );
  }

  const key =
    getKycEncryptionKey();

  const iv =
    crypto.randomBytes(12);

  const cipher =
    crypto.createCipheriv(
      "aes-256-gcm",
      key,
      iv
    );

  const ciphertext =
    Buffer.concat([
      cipher.update(
        String(value).trim(),
        "utf8"
      ),
      cipher.final(),
    ]);

  const authTag =
    cipher.getAuthTag();

  return [
    "v1",
    iv.toString("base64"),
    authTag.toString("base64"),
    ciphertext.toString("base64"),
  ].join(":");
}


// ============================================================
// SAFE NINJA ERROR EXTRACTION
// ============================================================

function extractNinjaMessage(
  error
) {
  if (!error) {
    return "Ninja KYC provider error.";
  }

  const responseData =
    error.response &&
    error.response.data;

  if (
    responseData &&
    typeof responseData ===
      "object"
  ) {
    if (
      typeof responseData.message ===
      "string"
    ) {
      return responseData.message;
    }

    if (
      typeof responseData.error ===
      "string"
    ) {
      return responseData.error;
    }

    if (
      responseData.error &&
      typeof responseData.error ===
        "object" &&
      typeof responseData.error.message ===
        "string"
    ) {
      return responseData.error.message;
    }
  }

  if (
    typeof error.message ===
      "string" &&
    error.message.trim()
  ) {
    return error.message;
  }

  return "Ninja KYC provider error.";
}


// ============================================================
// GENERIC PROVIDER ERROR EXTRACTION
// ============================================================

function extractProviderError(
  error
) {
  if (!error) {
    return "Unknown provider error.";
  }

  const data =
    error.response?.data;

  if (
    typeof data ===
    "string"
  ) {
    return data;
  }

  if (
    data &&
    typeof data ===
      "object"
  ) {
    if (
      typeof data.message ===
      "string"
    ) {
      return data.message;
    }

    if (
      typeof data.error ===
      "string"
    ) {
      return data.error;
    }

    if (
      data.error &&
      typeof data.error ===
        "object" &&
      typeof data.error.message ===
        "string"
    ) {
      return data.error.message;
    }

    try {
      return JSON.stringify(
        data
      );
    } catch (_) {}
  }

  return (
    error.message ||
    "Unknown provider error."
  );
}


// ============================================================
// ID HASH
// ============================================================

function hashIdentity(
  idType,
  idNumber
) {
  return crypto
    .createHash("sha256")
    .update(
      `${idType}:${idNumber}`
    )
    .digest("hex");
}


// ============================================================
// FIREBASE AUTHENTICATION
// ============================================================

async function requireAuth(
  req,
  res,
  next
) {
  try {
    const authorization =
      req.headers.authorization ||
      "";

    if (
      !authorization.startsWith(
        "Bearer "
      )
    ) {
      return res.status(401).json({
        success: false,
        verified: false,
        message:
          "Authentication required.",
      });
    }

    const idToken =
      authorization
        .substring(7)
        .trim();

    if (!idToken) {
      return res.status(401).json({
        success: false,
        verified: false,
        message:
          "Authentication token is missing.",
      });
    }

    const decodedToken =
      await auth.verifyIdToken(
        idToken
      );

    req.user =
      decodedToken;

    return next();
  } catch (error) {
    console.error(
      "KENT FIREBASE AUTH ERROR:",
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
  return db
    .collection("users")
    .doc(uid);
}


// ============================================================
// GET USER DATA
// ============================================================

async function getUserData(
  uid
) {
  const snapshot =
    await getUserRef(uid).get();

  if (!snapshot.exists) {
    return {};
  }

  return (
    snapshot.data() || {}
  );
}


// ============================================================
// NINJA SESSION TOKEN
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
      "Ninja production credentials are not configured."
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
    typeof token !==
      "string" ||
    !token.trim()
  ) {
    throw new Error(
      "Ninja did not return a valid session token."
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
// NINJA LIVE IDENTITY VERIFICATION
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

    mode:
      "verify",

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
    if (
      error.response?.status ===
      401
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
// CHECK PREVIOUS VERIFICATION
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

  if (
    previous.verified !==
    true
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
// REQUEST LOCK KEY
// ============================================================

function getRequestLockKey(
  uid,
  idType,
  identityHash
) {
  return `${uid}:${idType}:${identityHash}`;
}


// ============================================================
// KYC REFERENCE
// ============================================================

function generateReference(
  uid,
  idType,
  identityHash
) {
  const safeUid =
    String(uid)
      .replace(
        /[^a-zA-Z0-9_-]/g,
        ""
      )
      .substring(
        0,
        16
      );

  const shortHash =
    identityHash.substring(
      0,
      24
    );

  return `kent-${idType}-${safeUid}-${shortHash}`;
}


// ============================================================
// SAVE KYC RESULT
// ============================================================
//
// IMPORTANT:
//
// rawId is encrypted before being stored.
//
// Plaintext BVN/NIN is NEVER stored.
//
// ============================================================

async function saveKycResult({
  uid,
  idType,
  rawId,
  identityHash,
  verified,
  score,
  recommendation,
  reference,
}) {
  const userRef =
    getUserRef(uid);

  const currentSnapshot =
    await userRef.get();

  const currentData =
    currentSnapshot.exists
      ? currentSnapshot.data() || {}
      : {};

  const now =
    new Date();

  const update = {};

  // ----------------------------------------------------------
  // ENCRYPT VERIFIED IDENTITY
  // ----------------------------------------------------------

  let encryptedIdentity =
    null;

  if (
    verified === true
  ) {
    if (
      !rawId ||
      !isElevenDigits(
        rawId
      )
    ) {
      throw new Error(
        "Verified identity number is invalid and cannot be securely stored."
      );
    }

    encryptedIdentity =
      encryptKycValue(
        rawId
      );
  }

  // ----------------------------------------------------------
  // BVN
  // ----------------------------------------------------------

  if (
    idType === "bvn"
  ) {
    update.bvnVerified =
      verified;

    update.bvnVerifiedAt =
      verified
        ? now
        : null;

    update.bvnVerification = {
      identityHash,

      verified,

      encryptedIdentity:
        encryptedIdentity,

      score:
        typeof score ===
        "number"
          ? score
          : null,

      recommendation:
        recommendation ||
        null,

      reference,

      verifiedAt:
        verified
          ? now
          : null,
    };
  }

  // ----------------------------------------------------------
  // NIN
  // ----------------------------------------------------------

  if (
    idType === "nin"
  ) {
    update.ninVerified =
      verified;

    update.ninVerifiedAt =
      verified
        ? now
        : null;

    update.ninVerification = {
      identityHash,

      verified,

      encryptedIdentity:
        encryptedIdentity,

      score:
        typeof score ===
        "number"
          ? score
          : null,

      recommendation:
        recommendation ||
        null,

      reference,

      verifiedAt:
        verified
          ? now
          : null,
    };
  }

  // ----------------------------------------------------------
  // FINAL KYC STATE
  // ----------------------------------------------------------

  const finalBvnVerified =
    idType === "bvn"
      ? verified
      : currentData.bvnVerified ===
        true;

  const finalNinVerified =
    idType === "nin"
      ? verified
      : currentData.ninVerified ===
        true;

  const activated =
    finalBvnVerified &&
    finalNinVerified;

  if (activated) {
    update.kycStatus =
      "verified";

    update.kentPayActivated =
      true;

    update.kycVerifiedAt =
      currentData.kycVerifiedAt ||
      now;
  } else if (
    finalBvnVerified ||
    finalNinVerified
  ) {
    update.kycStatus =
      "partial";

    update.kentPayActivated =
      false;

    update.kycVerifiedAt =
      null;
  } else {
    update.kycStatus =
      "pending";

    update.kentPayActivated =
      false;

    update.kycVerifiedAt =
      null;
  }

  await userRef.set(
    update,
    {
      merge: true,
    }
  );

  return {
    activated,

    bvnVerified:
      finalBvnVerified,

    ninVerified:
      finalNinVerified,
  };
}


// ============================================================
// AUTOMATIC KENT PAY ACCOUNT CREATION
// ============================================================

async function activateKentPayAccount({
  uid,
  idType,
  rawId,
}) {
  console.log(
    "KENT PAY AUTOMATIC ACCOUNT CREATION START:",
    {
      uid,
      idType,
      hasIdentityNumber:
        !!rawId,
    }
  );

  try {
    const existing =
      await getKentPayVirtualAccount(
        uid
      );

    if (
      existing &&
      existing.accountNumber
    ) {
      console.log(
        "KENT PAY ACCOUNT ALREADY EXISTS:",
        {
          uid,

          accountNumber:
            existing.accountNumber,

          bankName:
            existing.bankName ||
            null,
        }
      );

      return {
        success: true,

        created: false,

        alreadyExists: true,

        account:
          existing,
      };
    }

    console.log(
      "KENT PAY: Calling ensureKentPayVirtualAccount..."
    );

    const result =
      await ensureKentPayVirtualAccount({
        uid,

        idType,

        rawId,
      });

    if (
      !result ||
      !result.account
    ) {
      throw new Error(
        "KENT Pay service did not return a virtual account."
      );
    }

    console.log(
      "KENT PAY AUTOMATIC ACCOUNT CREATION SUCCESS:",
      {
        uid,

        accountNumber:
          result.account.accountNumber,

        bankName:
          result.account.bankName,

        accountName:
          result.account.accountName,
      }
    );

    return {
      success: true,

      created:
        result.created ===
        true,

      alreadyExists:
        result.alreadyExists ===
        true,

      account:
        result.account,
    };
  } catch (error) {
    console.error(
      "KENT PAY AUTOMATIC ACCOUNT CREATION FAILED:",
      {
        uid,

        idType,

        message:
          error.message,

        name:
          error.name,

        status:
          error.response?.status ||
          null,

        providerResponse:
          error.response?.data ||
          null,

        providerError:
          extractProviderError(
            error
          ),
      }
    );

    return {
      success: false,

      created: false,

      alreadyExists: false,

      account: null,

      error:
        extractProviderError(
          error
        ),
    };
  }
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

  // ----------------------------------------------------------
  // VALIDATE ID
  // ----------------------------------------------------------

  if (
    !isElevenDigits(rawId)
  ) {
    return res.status(400).json({
      success: false,

      verified: false,

      message:
        `${idType.toUpperCase()} must contain exactly 11 digits.`,
    });
  }

  // ----------------------------------------------------------
  // VALIDATE NAME
  // ----------------------------------------------------------

  if (
    !isValidName(
      firstName
    )
  ) {
    return res.status(400).json({
      success: false,

      verified: false,

      message:
        "A valid first name is required.",
    });
  }

  if (
    !isValidName(
      lastName
    )
  ) {
    return res.status(400).json({
      success: false,

      verified: false,

      message:
        "A valid last name is required.",
    });
  }

  // ----------------------------------------------------------
  // VALIDATE DOB
  // ----------------------------------------------------------

  if (
    !isValidDateOfBirth(
      dateOfBirth
    )
  ) {
    return res.status(400).json({
      success: false,

      verified: false,

      message:
        "Date of birth must use YYYY-MM-DD format.",
    });
  }

  // ----------------------------------------------------------
  // HASH ID
  // ----------------------------------------------------------

  const identityHash =
    hashIdentity(
      idType,
      rawId
    );

  // ----------------------------------------------------------
  // REQUEST LOCK
  // ----------------------------------------------------------

  const lockKey =
    getRequestLockKey(
      uid,
      idType,
      identityHash
    );

  if (
    activeRequests.has(
      lockKey
    )
  ) {
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
    // CHECK PREVIOUS VERIFICATION
    // ========================================================

    const existing =
      await checkRecentVerification(
        uid,
        idType,
        identityHash
      );

    if (
      existing.duplicate
    ) {
      const userData =
        await getUserData(
          uid
        );

      let kentPayAccount =
        await getKentPayVirtualAccount(
          uid
        );

      // ------------------------------------------------------
      // AUTOMATIC RETRY
      // ------------------------------------------------------

      if (
        userData.bvnVerified ===
          true &&
        userData.ninVerified ===
          true &&
        !kentPayAccount
      ) {
        console.log(
          "KENT PAY: Existing verified KYC detected with no account. Attempting automatic account creation."
        );

        const accountResult =
          await activateKentPayAccount({
            uid,

            idType,

            rawId,
          });

        kentPayAccount =
          accountResult.account;

        if (
          !accountResult.success
        ) {
          return res.status(502).json({
            success: false,

            verified: true,

            alreadyVerified:
              true,

            kentPayActivated:
              true,

            kentPayAccountReady:
              false,

            kentPayAccount:
              null,

            code:
              "KENT_PAY_ACCOUNT_CREATION_FAILED",

            message:
              "Your KYC is verified, but KENT Pay could not create your virtual account. Please try again.",

            accountSetupError:
              accountResult.error ||
              null,
          });
        }
      }

      return res.status(200).json({
        success: true,

        verified: true,

        alreadyVerified:
          true,

        score:
          existing.previous.score ??
          null,

        recommendation:
          existing.previous.recommendation ||
          "accept",

        kentPayActivated:
          userData.kentPayActivated ===
          true,

        kentPayAccountReady:
          !!kentPayAccount,

        kentPayAccount:
          kentPayAccount ||
          null,

        message:
          kentPayAccount
            ? `${idType.toUpperCase()} is already verified and your KENT Pay account is ready.`
            : `${idType.toUpperCase()} is already verified. KENT Pay account setup is still being completed.`,
      });
    }

    // ========================================================
    // NINJA REFERENCE
    // ========================================================

    const reference =
      generateReference(
        uid,
        idType,
        identityHash
      );

    console.log(
      `KENT LIVE ${idType.toUpperCase()} VERIFICATION STARTED`,
      {
        uid,

        reference,
      }
    );

    // ========================================================
    // NINJA VERIFICATION
    // ========================================================

    let result;

    try {
      result =
        await ninjaVerifyIdentity({
          idType,

          idNumber:
            rawId,

          firstName,

          lastName,

          dateOfBirth,

          reference,
        });
    } catch (error) {
      const providerStatus =
        error.response?.status;

      const providerMessage =
        extractNinjaMessage(
          error
        );

      console.error(
        `KENT LIVE NINJA ${idType.toUpperCase()} ERROR`,
        {
          status:
            providerStatus ||
            null,

          message:
            providerMessage,

          reference,
        }
      );

      if (
        providerStatus ===
        401
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

      if (
        providerStatus ===
        429
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

      if (
        providerStatus ===
          402 ||
        /insufficient.*balance/i.test(
          providerMessage
        ) ||
        /insufficient.*wallet/i.test(
          providerMessage
        ) ||
        /temporarily unavailable/i.test(
          providerMessage
        )
      ) {
        return res.status(402).json({
          success: false,

          verified: false,

          code:
            "KYC_PROVIDER_PAYMENT_ERROR",

          message:
            "KYC verification is temporarily unavailable. Please try again later.",
        });
      }

      if (
        providerStatus ===
        400
      ) {
        return res.status(400).json({
          success: false,

          verified: false,

          code:
            "KYC_PROVIDER_VALIDATION_ERROR",

          message:
            "The identity verification request could not be accepted. Please check the submitted details.",
        });
      }

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
    // PROCESS NINJA RESPONSE
    // ========================================================

    const found =
      result &&
      result.found === true;

    const verified =
      result &&
      result.verified === true;

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
    // NOT FOUND
    // ========================================================

    if (!found) {
      await saveKycResult({
        uid,

        idType,

        rawId,

        identityHash,

        verified: false,

        score,

        recommendation:
          recommendation ||
          "not_found",

        reference,
      });

      console.log(
        `KENT LIVE ${idType.toUpperCase()} NOT FOUND`,
        {
          uid,

          reference,
        }
      );

      return res.status(200).json({
        success: true,

        verified: false,

        found: false,

        alreadyVerified: false,

        score,

        recommendation:
          recommendation ||
          "not_found",

        kentPayActivated:
          false,

        kentPayAccountReady:
          false,

        message:
          `No matching ${idType.toUpperCase()} record was found. Please check the number and try again.`,
      });
    }

    // ========================================================
    // SAVE KYC
    // ========================================================

    const kycState =
      await saveKycResult({
        uid,

        idType,

        rawId,

        identityHash,

        verified,

        score,

        recommendation,

        reference,
      });

    const activated =
      kycState.activated;

    // ========================================================
    // VERIFIED
    // ========================================================

    if (
      verified &&
      recommendation ===
        "accept"
    ) {
      let kentPayAccount =
        null;

      let kentPayAccountReady =
        false;

      let kentPayAccountError =
        null;

      // ------------------------------------------------------
      // BOTH BVN AND NIN VERIFIED
      // ------------------------------------------------------

      if (
        activated
      ) {
        console.log(
          "KENT PAY ACTIVATED — STARTING AUTOMATIC ACCOUNT CREATION:",
          {
            uid,

            triggeringIdType:
              idType,
          }
        );

        const accountResult =
          await activateKentPayAccount({
            uid,

            idType,

            rawId,
          });

        kentPayAccount =
          accountResult.account;

        kentPayAccountReady =
          accountResult.success &&
          !!accountResult.account;

        if (
          !kentPayAccountReady
        ) {
          kentPayAccountError =
            accountResult.error;
        }
      }

      console.log(
        `KENT LIVE ${idType.toUpperCase()} VERIFIED`,
        {
          uid,

          reference,

          score,

          recommendation,

          kentPayActivated:
            activated,

          kentPayAccountReady,
        }
      );

      // ======================================================
      // KYC + KENT PAY ACCOUNT SUCCESS
      // ======================================================

      if (
        activated &&
        kentPayAccountReady
      ) {
        return res.status(200).json({
          success: true,

          verified: true,

          found: true,

          alreadyVerified: false,

          score,

          recommendation,

          kentPayActivated:
            true,

          kentPayAccountReady:
            true,

          kentPayAccount,

          message:
            "Identity verified successfully. Both BVN and NIN are verified and your KENT Pay virtual account has been created automatically.",
        });
      }

      // ======================================================
      // KYC SUCCESS / ACCOUNT CREATION FAILURE
      // ======================================================

      if (
        activated &&
        !kentPayAccountReady
      ) {
        return res.status(502).json({
          success: false,

          verified: true,

          found: true,

          alreadyVerified: false,

          score,

          recommendation,

          kentPayActivated:
            true,

          kentPayAccountReady:
            false,

          kentPayAccount:
            null,

          code:
            "KENT_PAY_ACCOUNT_CREATION_FAILED",

          message:
            "BVN and NIN verification succeeded, but KENT Pay could not create your virtual account automatically.",

          accountSetupError:
            kentPayAccountError ||
            "Unknown KENT Pay account creation error.",
        });
      }

      // ======================================================
      // ONLY ONE ID VERIFIED
      // ======================================================

      return res.status(200).json({
        success: true,

        verified: true,

        found: true,

        alreadyVerified: false,

        score,

        recommendation,

        kentPayActivated:
          false,

        kentPayAccountReady:
          false,

        kentPayAccount:
          null,

        message:
          `${idType.toUpperCase()} verified successfully. Complete the remaining KYC verification to activate KENT Pay.`,
      });
    }

    // ========================================================
    // REVIEW
    // ========================================================

    if (
      recommendation ===
      "review"
    ) {
      console.log(
        `KENT LIVE ${idType.toUpperCase()} REVIEW`,
        {
          uid,

          reference,

          score,

          recommendation,
        }
      );

      return res.status(200).json({
        success: true,

        verified: false,

        found: true,

        status:
          "review",

        alreadyVerified:
          false,

        score,

        recommendation:
          "review",

        kentPayActivated:
          activated,

        kentPayAccountReady:
          false,

        kentPayAccount:
          null,

        message:
          "Your identity details require manual review. KENT Pay has not been activated from this verification.",
      });
    }

    // ========================================================
    // REJECT / MISMATCH
    // ========================================================

    console.log(
      `KENT LIVE ${idType.toUpperCase()} REJECTED`,
      {
        uid,

        reference,

        score,

        recommendation,
      }
    );

    return res.status(200).json({
      success: true,

      verified: false,

      found: true,

      status:
        recommendation ||
        "reject",

      alreadyVerified:
        false,

      score,

      recommendation:
        recommendation ||
        "reject",

      kentPayActivated:
        activated,

      kentPayAccountReady:
        false,

      kentPayAccount:
        null,

      message:
        "The identity details did not pass verification. Please make sure your name and date of birth exactly match your identity record.",
    });
  } catch (error) {
    console.error(
      `KENT ${idType.toUpperCase()} ROUTE ERROR:`,
      {
        message:
          error.message,

        name:
          error.name,
      }
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
// BVN VERIFICATION
// ============================================================

router.post(
  "/bvn",
  requireAuth,
  async (
    req,
    res
  ) => {
    return verifyIdentity(
      req,
      res,
      "bvn"
    );
  }
);


// ============================================================
// NIN VERIFICATION
// ============================================================

router.post(
  "/nin",
  requireAuth,
  async (
    req,
    res
  ) => {
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
  async (
    req,
    res
  ) => {
    try {
      const uid =
        req.user.uid;

      const data =
        await getUserData(
          uid
        );

      const kentPayAccount =
        await getKentPayVirtualAccount(
          uid
        );

      const accountReady =
        !!(
          kentPayAccount &&
          kentPayAccount.accountNumber
        );

      return res.status(200).json({
        success: true,

        bvnVerified:
          data.bvnVerified ===
          true,

        ninVerified:
          data.ninVerified ===
          true,

        kycStatus:
          data.kycStatus ||
          "pending",

        kentPayActivated:
          data.kentPayActivated ===
          true,

        kentPayAccountReady:
          accountReady,

        kentPayAccount:
          kentPayAccount ||
          null,

        bvnVerifiedAt:
          data.bvnVerifiedAt ||
          null,

        ninVerifiedAt:
          data.ninVerifiedAt ||
          null,

        kycVerifiedAt:
          data.kycVerifiedAt ||
          null,
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
  async (
    req,
    res
  ) => {
    try {
      const uid =
        req.user.uid;

      const data =
        await getUserData(
          uid
        );

      const bvnVerified =
        data.bvnVerified ===
        true;

      const ninVerified =
        data.ninVerified ===
        true;

      const activated =
        bvnVerified &&
        ninVerified;

      const kentPayAccount =
        await getKentPayVirtualAccount(
          uid
        );

      const accountReady =
        !!(
          kentPayAccount &&
          kentPayAccount.accountNumber
        );

      const kycStatus =
        activated
          ? "verified"
          : bvnVerified ||
              ninVerified
            ? "partial"
            : "pending";

      if (
        data.kentPayActivated !==
          activated ||
        data.kycStatus !==
          kycStatus
      ) {
        await getUserRef(
          uid
        ).set(
          {
            kentPayActivated:
              activated,

            kycStatus,
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

        kentPayAccountReady:
          accountReady,

        kentPayAccount:
          kentPayAccount ||
          null,

        kycStatus,
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
// KYC ROUTE 404
// ============================================================

router.use(
  (
    req,
    res
  ) => {
    return res.status(404).json({
      success: false,

      message:
        "KYC endpoint not found.",

      path:
        req.originalUrl,
    });
  }
);


// ============================================================
// EXPORT
// ============================================================

module.exports =
  router;

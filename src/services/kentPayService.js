COUNT STATUS: 500
I/flutter ( 1929): KENT CREATE ACCOUNT BODY: {"success":false,"message":"Your verified BVN is not available for KENT Pay account creation. Please complete BVN verification again."}

Yes — this confirms the problem is still in kentPayService.js, not the Flutter screen and not the kentPay.js route.

Your backend is saying:

Your verified BVN is not available for KENT Pay account creation.

That means ensureKentPayVirtualAccount() is looking for the securely stored BVN (encryptedIdentity), but your Firestore record currently has the BVN hash only.

I need to see your current kentPayService.js so I can give you the complete replacement, rather than guessing at your existing code.

Please attach that file here:

Upload a file

Do not delete the BVN/NIN records and don't run another paid Ninja verification yet. Once I have kentPayService.js, I'll fix the exact part causing this 500 and give you the entire file directly in a code block.

the file you sent me is what

Yes — you're right. The file I sent you was the kentPay.js replacement, and you already put that in.

The new 500 error proves that file is working. The remaining problem is in kentPayService.js, specifically where it retrieves the verified BVN.

So don't replace kentPay.js again.

What we need to fix now is:

Flutter
   ↓
POST /api/kent-pay/create-account
   ↓
kentPay.js ✅
   ↓
ensureKentPayVirtualAccount()
   ↓
kentPayService.js ❌
   ↓
"Your verified BVN is not available..."

You already gave me the KYC file, but I need the actual current kentPayService.js to give you the exact complete replacement.

Please upload/paste kentPayService.js here. I won't ask you to download anything; I'll return the corrected code directly in the chat.

Pasted markdown(20260905-204626).md
File

I checked the kentPayService.js you just sent. The problem is now confirmed.

Your service is correctly looking for:

userData.bvnVerification?.encryptedIdentity

and if it doesn't find it, it deliberately returns the exact error you're seeing.

Your Firestore BVN record has verified: true and identityHash, but no encryptedIdentity.

So the fix is NOT kentPay.js

We need to fix your KYC verification file so that when you submit the same already-verified BVN, it securely creates the missing encryptedIdentity without calling Ninja again.

In your kentKyc.js, inside the duplicate verification section, add this immediately after you have obtained userData and before the duplicate response is returned:

// ------------------------------------------------------
// BACKFILL MISSING ENCRYPTED IDENTITY
// ------------------------------------------------------
//
// Some users were verified before encryptedIdentity was
// added to the KYC record.
//
// Their Firestore record contains:
//   - identityHash
//   - verified: true
//
// but does not contain:
//   - encryptedIdentity
//
// DO NOT call Ninja again.
// The identity has already been verified.
//
// We securely encrypt the same BVN/NIN supplied in this
// authenticated duplicate-verification request and save it.
//
// Plaintext BVN/NIN is NEVER stored in Firestore.
// Plaintext BVN/NIN is NEVER logged.
// ------------------------------------------------------

const verificationField =
  idType === "bvn"
    ? "bvnVerification"
    : "ninVerification";

const previousVerification =
  userData[verificationField] || {};

if (
  previousVerification.verified === true &&
  !previousVerification.encryptedIdentity
) {
  if (!isElevenDigits(rawId)) {
    return res.status(400).json({
      success: false,
      verified: true,
      alreadyVerified: true,
      message:
        `Your verified ${idType.toUpperCase()} record is missing its secure identity value. Please enter the same ${idType.toUpperCase()} number again.`,
    });
  }

  const encryptedIdentity =
    encryptKycValue(rawId);

  await getUserRef(uid).set(
    {
      [verificationField]: {
        ...previousVerification,
        encryptedIdentity,
      },
    },
    {
      merge: true,
    }
  );

  userData[verificationField] = {
    ...previousVerification,
    encryptedIdentity,
  };

  console.log(
    `KENT KYC: Missing encrypted ${idType.toUpperCase()} value was securely backfilled for the existing verified record.`,
    {
      uid,
    }
  );
}
Then do this
Deploy the updated kentKyc.js to Render.

Make sure Render has:

KENT_KYC_ENCRYPTION_KEY

with the same 64-character key used by the backend.

Do not delete the BVN or NIN from Firestore.
Do not pay for another Ninja verification.
Open the KENT KYC screen.
Enter the same BVN that is already verified.
Submit it.

The duplicate-verification path should then save:

bvnVerification
    ├── identityHash
    ├── verified: true
    ├── verifiedAt
    └── encryptedIdentity: "v1:..."

After that, press Create KENT Pay Account again.

Your existing kentPayService.js will then be able to decrypt the BVN and pass it to Flutterwave. The relevant service code already does exactly that.

Do not change kentPayService.js right now. The missing piece is the encrypted BVN in Firestore.

Pasted markdown(20260906-154527).md
File

Yes. I used your existing kentKyc.js and inserted the fix into the duplicate-verification path. Your existing KYC/Ninja logic is preserved; the important change is that an already-verified BVN/NIN with a missing encryptedIdentity is securely encrypted and saved without making another Ninja verification request.

Replace your entire kentKyc.js with this:

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

      // ======================================================
      // BACKFILL MISSING ENCRYPTED IDENTITY
      // ======================================================
      //
      // Some users were verified before encryptedIdentity
      // was added to their Firestore KYC record.
      //
      // Their record contains:
      //
      //   identityHash
      //   verified: true
      //
      // but does not contain:
      //
      //   encryptedIdentity
      //
      // DO NOT call Ninja again.
      //
      // This request is authenticated and the submitted
      // identity number has already been confirmed against
      // the stored identityHash by checkRecentVerification().
      //
      // We securely encrypt the supplied identity number and
      // save it to Firestore.
      //
      // Plaintext BVN/NIN is NEVER stored.
      // Plaintext BVN/NIN is NEVER logged.
      // ======================================================

      const verificationField =
        idType === "bvn"
          ? "bvnVerification"
          : "ninVerification";

      const previousVerification =
        userData[
          verificationField
        ] || {};

      if (
        previousVerification.verified === true &&
        !previousVerification.encryptedIdentity
      ) {
        if (
          !isElevenDigits(
            rawId
          )
        ) {
          return res.status(400).json({
            success: false,

            verified: true,

            alreadyVerified: true,

            message:
              `Your verified ${idType.toUpperCase()} record is missing its secure identity value. Please enter the same ${idType.toUpperCase()} number again.`,
          });
        }

        const encryptedIdentity =
          encryptKycValue(
            rawId
          );

        await getUserRef(
          uid
        ).set(
          {
            [verificationField]: {
              ...previousVerification,

              encryptedIdentity,
            },
          },
          {
            merge: true,
          }
        );

        userData[
          verificationField
        ] = {
          ...previousVerification,

          encryptedIdentity,
        };

        console.log(
          `KENT KYC: Missing encrypted ${idType.toUpperCase()} value was securely backfilled for the existing verified record.`,
          {
            uid,
          }
        );
      }

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
After replacing it

Do not delete the BVN/NIN from Firestore. Do not perform another paid Ninja verification just yet.

Deploy this backend to Render.

Then, because your current BVN is already verified, submit the same BVN through the KYC screen once. The new duplicate-verification code will:

Recognize that the BVN is already verified.
Not call Ninja again.
Create encryptedIdentity from the submitted BVN.
Save it inside bvnVerification.
Then retry KENT Pay account creation.
Your kentPayService will finally have the encrypted BVN it needs.

Your current Firestore record is missing exactly that encrypted field, which is why the KENT Pay creation service is returning the error you're seeing.

One important thing: make sure Render still has KENT_KYC_ENCRYPTION_KEY set to the same 64-character key that was configured for this encryption system. Do not change an existing key after encrypted KYC values have been created, because changing it would prevent decryption of those values.

om debug service on Chrome...
Restarted application in 5,372ms.
Hot restarting application from main method in: org-dartlang-app:/web_entrypoint.dart (generation: 2).
KENT HOME KYC STATUS: 200
KENT HOME KYC BODY: {"success":true,"bvnVerified":true,"ninVerified":true,"kycStatus":"verified","kentPayActivated":true,"kentPayAccountReady":false,"kentPayAccount":null,"bvnVerifiedAt":{"_seconds":1788615852,"_nanoseconds":179000000},"ninVerifiedAt":{"_seconds":1788615799,"_nanoseconds":41000000},"kycVerifiedAt":{"_seconds":1788615852,"_nanoseconds":179000000}}
KENT PAY ACCOUNT STATUS: 200
KENT PAY ACCOUNT BODY: {"success":true,"bvnVerified":true,"ninVerified":true,"kentPayActivated":true,"kentPayAccountReady":false,"kentPayAccount":null,"walletBalance":0,"accountName":"Onwudiwe izuchukwu paul"}
KENT CREATE ACCOUNT STATUS: 500
KENT CREATE ACCOUNT BODY: {"success":false,"message":"Your verified BVN is not available for KENT Pay account creation. Please complete BVN verification again."}
KENT CREATE ACCOUNT STATUS: 500
KENT CREATE ACCOUNT BODY: {"success":false,"message":"Your verified BVN is not available for KENT Pay account creation. Please complete BVN verification again."}

The important part is that the new KYC route is not fixing the record used by kentPayService.

Your logs still show the exact same error:

Your verified BVN is not available for KENT Pay account creation.

That means we need to inspect kentPayService.js, because that service is the code actually looking for the encrypted BVN.

Please send me your current kentPayService.js file. I need the actual file, not a screenshot, because I need to check exactly how it retrieves/decrypts the BVN and then give you a complete replacement.

Upload a file

Don't delete anything from Firestore and don't run another live BVN verification yet. Once I see kentPayService.js, I can fix the actual failing part instead of guessing.

const crypto = require("crypto");

const { db } = require("../../firebaseAdmin");

const {
  createFlutterwaveCustomer,
  createStaticVirtualAccount,
} = require("./flutterwave");

// ============================================================
// FIRESTORE USER REFERENCE
// ============================================================

function getUserRef(uid) {
  return db.collection("users").doc(uid);
}

// ============================================================
// KYC ENCRYPTION KEY
// ============================================================

function getKycEncryptionKey() {
  const key = process.env.KENT_KYC_ENCRYPTION_KEY;

  if (!key) {
    throw new Error(
      "KENT_KYC_ENCRYPTION_KEY is missing from the backend environment."
    );
  }

  if (!/^[0-9a-fA-F]{64}$/.test(key)) {
    throw new Error(
      "KENT_KYC_ENCRYPTION_KEY must contain exactly 64 hexadecimal characters."
    );
  }

  return Buffer.from(key, "hex");
}

// ============================================================
// ENCRYPT KYC VALUE
// ============================================================
//
// Format:
//
// v1:iv:authTag:ciphertext
//
// AES-256-GCM
//
// Plaintext BVN/NIN is never stored in Firestore.
// ============================================================

function encryptKycValue(value) {
  if (value === undefined || value === null) {
    throw new Error(
      "KYC value is required for encryption."
    );
  }

  const plaintext = String(value).trim();

  if (!/^\d{11}$/.test(plaintext)) {
    throw new Error(
      "KYC value must contain exactly 11 digits."
    );
  }

  const key = getKycEncryptionKey();

  const iv = crypto.randomBytes(12);

  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    key,
    iv
  );

  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);

  const authTag = cipher.getAuthTag();

  return [
    "v1",
    iv.toString("base64"),
    authTag.toString("base64"),
    ciphertext.toString("base64"),
  ].join(":");
}

// ============================================================
// DECRYPT KYC VALUE
// ============================================================

function decryptKycValue(encryptedValue) {
  if (!encryptedValue) {
    return null;
  }

  const value = String(encryptedValue);

  const parts = value.split(":");

  if (parts.length !== 4) {
    throw new Error(
      "Invalid encrypted KYC value."
    );
  }

  const [
    version,
    ivBase64,
    tagBase64,
    ciphertextBase64,
  ] = parts;

  if (version !== "v1") {
    throw new Error(
      "Unsupported encrypted KYC value version."
    );
  }

  const key = getKycEncryptionKey();

  const iv = Buffer.from(
    ivBase64,
    "base64"
  );

  const authTag = Buffer.from(
    tagBase64,
    "base64"
  );

  const ciphertext = Buffer.from(
    ciphertextBase64,
    "base64"
  );

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    iv
  );

  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  return decrypted.toString("utf8");
}

// ============================================================
// VALIDATE BVN
// ============================================================

function isValidBvn(value) {
  return /^\d{11}$/.test(
    String(value || "").trim()
  );
}

// ============================================================
// GET VERIFIED BVN
// ============================================================
//
// Priority:
//
// 1. Existing encryptedIdentity
// 2. Existing bvnEncrypted
//
// If neither exists, caller must provide the verified BVN
// through rawId.
//
// ============================================================

function getStoredVerifiedBvn(userData) {
  if (!userData) {
    throw new Error(
      "User data is missing."
    );
  }

  const bvnVerified =
    userData.bvnVerified === true ||
    userData.bvnVerification?.verified === true;

  if (!bvnVerified) {
    throw new Error(
      "Your BVN has not been verified."
    );
  }

  const encryptedBvn =
    userData.bvnVerification?.encryptedIdentity ||
    userData.bvnEncrypted ||
    null;

  if (!encryptedBvn) {
    return null;
  }

  const bvn =
    decryptKycValue(encryptedBvn);

  if (!isValidBvn(bvn)) {
    throw new Error(
      "The stored verified BVN is invalid."
    );
  }

  return String(bvn).trim();
}

// ============================================================
// BACKFILL ENCRYPTED BVN
// ============================================================
//
// This fixes existing verified users whose Firestore record
// has:
//
// bvnVerification.verified = true
// bvnVerification.identityHash = "..."
//
// but is missing:
//
// bvnVerification.encryptedIdentity
//
// rawId must be the SAME BVN that was verified.
//
// IMPORTANT:
// This function does NOT call Ninja.
// ============================================================

async function backfillEncryptedBvn(
  userRef,
  userData,
  rawId
) {
  if (!rawId) {
    return null;
  }

  const bvn = String(rawId).trim();

  if (!isValidBvn(bvn)) {
    throw new Error(
      "The verified BVN supplied for KENT Pay account creation is invalid."
    );
  }

  const bvnVerification =
    userData.bvnVerification || {};

  const bvnVerified =
    userData.bvnVerified === true ||
    bvnVerification.verified === true;

  if (!bvnVerified) {
    throw new Error(
      "The supplied BVN has not been verified."
    );
  }

  // ----------------------------------------------------------
  // If encryption already exists, do not replace it.
  // ----------------------------------------------------------

  if (
    bvnVerification.encryptedIdentity ||
    userData.bvnEncrypted
  ) {
    return getStoredVerifiedBvn(userData);
  }

  // ----------------------------------------------------------
  // IMPORTANT:
  //
  // We do not trust rawId merely because it is supplied.
  //
  // The request must already correspond to a verified BVN.
  //
  // The existing verified identityHash is used to confirm
  // that the supplied BVN is the same verified identity.
  // ----------------------------------------------------------

  if (bvnVerification.identityHash) {
    const suppliedHash = crypto
      .createHash("sha256")
      .update(bvn)
      .digest("hex");

    if (
      suppliedHash !==
      String(
        bvnVerification.identityHash
      ).toLowerCase()
    ) {
      throw new Error(
        "The supplied BVN does not match the BVN that was previously verified."
      );
    }
  }

  // ----------------------------------------------------------
  // Encrypt the already-verified BVN.
  // ----------------------------------------------------------

  const encryptedIdentity =
    encryptKycValue(bvn);

  // ----------------------------------------------------------
  // Save encrypted BVN.
  // ----------------------------------------------------------

  await userRef.set(
    {
      bvnVerification: {
        ...bvnVerification,
        encryptedIdentity,
      },
    },
    {
      merge: true,
    }
  );

  // Update local object so the caller can immediately use it.
  userData.bvnVerification = {
    ...bvnVerification,
    encryptedIdentity,
  };

  return bvn;
}

// ============================================================
// NORMALIZE NAME
// ============================================================

function splitName(displayName) {
  const cleanName =
    typeof displayName === "string"
      ? displayName.trim()
      : "";

  if (!cleanName) {
    return {
      firstName: "KENT",
      lastName: "User",
    };
  }

  const parts = cleanName
    .split(/\s+/)
    .filter(Boolean);

  if (parts.length === 1) {
    return {
      firstName: parts[0],
      lastName: "User",
    };
  }

  return {
    firstName: parts[0],
    lastName: parts.slice(1).join(" "),
  };
}

// ============================================================
// NORMALIZE PHONE
// ============================================================

function normalizePhone(phone) {
  if (!phone) {
    return null;
  }

  let value = String(phone).trim();

  if (value.startsWith("+234")) {
    value = value.substring(4);
  } else if (value.startsWith("234")) {
    value = value.substring(3);
  } else if (value.startsWith("0")) {
    value = value.substring(1);
  }

  return value;
}

// ============================================================
// CREATE STABLE CUSTOMER REFERENCE
// ============================================================

function createCustomerReference(uid) {
  const hash = crypto
    .createHash("sha256")
    .update(`kent-customer:${uid}`)
    .digest("hex")
    .substring(0, 24);

  return `kent-customer-${hash}`;
}

// ============================================================
// CREATE STABLE VIRTUAL ACCOUNT REFERENCE
// ============================================================

function createVirtualAccountReference(uid) {
  const hash = crypto
    .createHash("sha256")
    .update(`kent-virtual-account:${uid}`)
    .digest("hex")
    .substring(0, 24);

  return `kent-va-${hash}`;
}

// ============================================================
// ENSURE KENT PAY VIRTUAL ACCOUNT
// ============================================================
//
// Supported:
//
// ensureKentPayVirtualAccount({
//   uid
// });
//
// OR:
//
// ensureKentPayVirtualAccount({
//   uid,
//   idType: "bvn",
//   rawId: verifiedBvn
// });
//
// The second form is particularly important for existing users
// whose BVN was verified before encryptedIdentity was introduced.
// ============================================================

async function ensureKentPayVirtualAccount({
  uid,
  idType,
  rawId,
} = {}) {
  // ==========================================================
  // VALIDATE USER
  // ==========================================================

  if (!uid) {
    throw new Error(
      "User ID is required to create a KENT Pay account."
    );
  }

  const userRef =
    getUserRef(uid);

  // ==========================================================
  // READ USER
  // ==========================================================

  const snapshot =
    await userRef.get();

  if (!snapshot.exists) {
    throw new Error(
      "KENT user account was not found."
    );
  }

  const userData =
    snapshot.data() || {};

  // ==========================================================
  // ALREADY CREATED
  // ==========================================================

  const existing =
    userData.kentPayAccount ||
    null;

  if (
    existing &&
    existing.accountNumber &&
    existing.status === "active"
  ) {
    return {
      created: false,
      alreadyExists: true,
      account: existing,
    };
  }

  // ==========================================================
  // CHECK FULL KYC
  // ==========================================================

  const bvnVerified =
    userData.bvnVerified === true ||
    userData.bvnVerification?.verified === true;

  const ninVerified =
    userData.ninVerified === true ||
    userData.ninVerification?.verified === true;

  if (!bvnVerified || !ninVerified) {
    throw new Error(
      "KENT Pay requires both BVN and NIN verification before a virtual account can be created."
    );
  }

  // ==========================================================
  // GET BVN
  // ==========================================================

  let bvn = null;

  // ----------------------------------------------------------
  // CASE 1:
  //
  // A verified BVN was supplied by the KYC process.
  //
  // This allows us to repair an old Firestore record that is
  // missing encryptedIdentity.
  // ----------------------------------------------------------

  if (
    rawId &&
    String(idType || "").toLowerCase() === "bvn"
  ) {
    bvn =
      await backfillEncryptedBvn(
        userRef,
        userData,
        rawId
      );
  }

  // ----------------------------------------------------------
  // CASE 2:
  //
  // No raw BVN was supplied.
  //
  // Try existing encrypted value.
  // ----------------------------------------------------------

  if (!bvn) {
    bvn =
      getStoredVerifiedBvn(
        userData
      );
  }

  // ==========================================================
  // FINAL BVN VALIDATION
  // ==========================================================

  if (!isValidBvn(bvn)) {
    throw new Error(
      "The verified BVN is invalid."
    );
  }

  bvn = String(bvn).trim();

  // ==========================================================
  // USER INFORMATION
  // ==========================================================

  const email =
    userData.email ||
    userData.emailAddress ||
    null;

  if (!email) {
    throw new Error(
      "A verified email address is required before creating the KENT Pay account."
    );
  }

  const name =
    splitName(
      userData.displayName ||
        userData.fullName ||
        userData.name ||
        `${userData.firstName || ""} ${
          userData.lastName || ""
        }`
    );

  const firstName =
    userData.firstName ||
    name.firstName;

  const lastName =
    userData.lastName ||
    name.lastName;

  const phoneNumber =
    normalizePhone(
      userData.phoneNumber ||
        userData.phone ||
        null
    );

  // ==========================================================
  // STABLE REFERENCES
  // ==========================================================

  const customerReference =
    createCustomerReference(uid);

  const virtualAccountReference =
    createVirtualAccountReference(uid);

  // ==========================================================
  // CREATE OR REUSE FLUTTERWAVE CUSTOMER
  // ==========================================================

  let customerId =
    userData.kentPayFlutterwaveCustomerId ||
    null;

  if (!customerId) {
    console.log(
      "Creating Flutterwave customer for KENT user:",
      uid
    );

    const customerResponse =
      await createFlutterwaveCustomer({
        email,
        firstName,
        lastName,
        phoneNumber,
        idempotencyKey:
          customerReference,
      });

    customerId =
      customerResponse?.data?.id ||
      null;

    if (!customerId) {
      throw new Error(
        "Flutterwave customer creation did not return a customer ID."
      );
    }

    await userRef.set(
      {
        kentPayFlutterwaveCustomerId:
          customerId,
      },
      {
        merge: true,
      }
    );
  }

  // ==========================================================
  // CREATE STATIC VIRTUAL ACCOUNT
  // ==========================================================

  console.log(
    "Creating Flutterwave static virtual account for KENT user:",
    uid
  );

  const virtualAccountResponse =
    await createStaticVirtualAccount({
      customerId,

      reference:
        virtualAccountReference,

      narration:
        `${firstName} ${lastName}`.substring(
          0,
          35
        ),

      bvn,

      nin: undefined,
    });

  const accountData =
    virtualAccountResponse?.data;

  // ==========================================================
  // VALIDATE FLUTTERWAVE RESPONSE
  // ==========================================================

  if (
    !accountData ||
    !accountData.account_number
  ) {
    console.error(
      "INVALID FLUTTERWAVE VIRTUAL ACCOUNT RESPONSE:",
      {
        hasData: !!accountData,
        hasAccountNumber:
          !!accountData?.account_number,
      }
    );

    throw new Error(
      "Flutterwave did not return a valid virtual account."
    );
  }

  // ==========================================================
  // SAVE ACCOUNT
  // ==========================================================

  const account = {
    provider: "flutterwave",

    providerAccountId:
      accountData.id || null,

    providerCustomerId:
      customerId,

    reference:
      accountData.reference ||
      virtualAccountReference,

    accountNumber:
      accountData.account_number,

    accountName:
      accountData.narration ||
      `${firstName} ${lastName}`,

    bankName:
      accountData.account_bank_name ||
      null,

    accountType:
      accountData.account_type ||
      "static",

    currency:
      accountData.currency ||
      "NGN",

    status:
      accountData.status ||
      "active",

    createdAt:
      new Date(),

    updatedAt:
      new Date(),
  };

  // ==========================================================
  // SAVE ACCOUNT TO FIRESTORE
  // ==========================================================

  await userRef.set(
    {
      kentPayAccount:
        account,

      kentPayAccountReady:
        true,

      kentPayAccountCreatedAt:
        new Date(),

      kentPayActivated:
        true,

      kentPay: {
        activated: true,
        activatedAt: new Date(),
      },
    },
    {
      merge: true,
    }
  );

  // ==========================================================
  // SUCCESS LOG
  // ==========================================================

  console.log(
    "KENT Pay virtual account created successfully:",
    {
      uid,
      accountNumber:
        account.accountNumber,
      bankName:
        account.bankName,
    }
  );

  return {
    created: true,
    alreadyExists: false,
    account,
  };
}

// ============================================================
// GET EXISTING KENT PAY VIRTUAL ACCOUNT
// ============================================================

async function getKentPayVirtualAccount(uid) {
  if (!uid) {
    throw new Error(
      "User ID is required."
    );
  }

  const snapshot =
    await getUserRef(uid).get();

  if (!snapshot.exists) {
    return null;
  }

  const data =
    snapshot.data() || {};

  return (
    data.kentPayAccount ||
    null
  );
}

// ============================================================
// CHECK KENT PAY ACCOUNT STATUS
// ============================================================

async function getKentPayAccountStatus(uid) {
  if (!uid) {
    throw new Error(
      "User ID is required."
    );
  }

  const snapshot =
    await getUserRef(uid).get();

  if (!snapshot.exists) {
    throw new Error(
      "KENT user account was not found."
    );
  }

  const data =
    snapshot.data() || {};

  const account =
    data.kentPayAccount ||
    null;

  return {
    activated:
      data.kentPayActivated === true ||
      data.kentPay?.activated === true,

    accountReady:
      data.kentPayAccountReady === true,

    hasAccount:
      !!(
        account &&
        account.accountNumber
      ),

    account,
  };
}

// ============================================================
// EXPORTS
// ============================================================

module.exports = {
  ensureKentPayVirtualAccount,
  getKentPayVirtualAccount,
  getKentPayAccountStatus,
  encryptKycValue,
  decryptKycValue,
};

Yes. I can see the problem in this kentPayService.js.

Your service is correctly designed to use bvnVerification.encryptedIdentity, but your current Firestore record does not have that field. More importantly, your /create-account route currently calls:

ensureKentPayVirtualAccount({ uid });

so it never passes the BVN that could be used by backfillEncryptedBvn().

That is why the service reaches:

getStoredVerifiedBvn(userData)

and gets null, then ultimately fails with the “verified BVN is not available” error.

What needs to change

The clean fix is to make account creation obtain the verified BVN from the KYC flow when available and pass it into this service:

ensureKentPayVirtualAccount({
  uid,
  idType: "bvn",
  rawId: verifiedBvn,
});

But I do not want to guess where your verified BVN is currently available in your kentKyc.js, because that is exactly what caused the previous mismatch.

If you want, I can now give you the complete replacement kentPayService.js that is compatible with your current KYC structure and handles the missing encrypted BVN safely.

Chat paused until usage resets at 7:42 PM
You’ve reached the limit for chats that include files or images. Start a new text-only chat or upgrade to continue now.
New chat
Claim free offer

const crypto = require("crypto");

const { db } = require("../../firebaseAdmin");

const {
  createFlutterwaveCustomer,
  createStaticVirtualAccount,
} = require("./flutterwave");

// ============================================================
// FIRESTORE USER REFERENCE
// ============================================================

function getUserRef(uid) {
  return db.collection("users").doc(uid);
}

// ============================================================
// KYC ENCRYPTION
// ============================================================
//
// The real BVN/NIN is sensitive information.
//
// We keep the SHA-256 identity hash for comparison/verification,
// but the actual identity number is stored encrypted.
//
// Required Render environment variable:
//
// KENT_KYC_ENCRYPTION_KEY
//
// It must be exactly 64 hexadecimal characters = 32 bytes.
//
// Generate one locally with:
//
// node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
//
// IMPORTANT:
// Never put this key in Flutter.
// Never put this key in GitHub.
// Never log this key.
// ============================================================

function getKycEncryptionKey() {
  const key = process.env.KENT_KYC_ENCRYPTION_KEY;

  if (!key) {
    throw new Error(
      "KENT_KYC_ENCRYPTION_KEY is missing from the backend environment."
    );
  }

  if (!/^[0-9a-fA-F]{64}$/.test(key)) {
    throw new Error(
      "KENT_KYC_ENCRYPTION_KEY must contain exactly 64 hexadecimal characters."
    );
  }

  return Buffer.from(key, "hex");
}

// ============================================================
// DECRYPT SENSITIVE KYC VALUE
// ============================================================
//
// Format:
//
// v1:iv:authTag:ciphertext
//
// All binary components are base64 encoded.
// ============================================================

function decryptKycValue(encryptedValue) {
  if (!encryptedValue) {
    return null;
  }

  const value = String(encryptedValue);

  const parts = value.split(":");

  if (parts.length !== 4) {
    throw new Error("Invalid encrypted KYC value.");
  }

  const [version, ivBase64, tagBase64, ciphertextBase64] = parts;

  if (version !== "v1") {
    throw new Error("Unsupported encrypted KYC value version.");
  }

  const key = getKycEncryptionKey();

  const iv = Buffer.from(ivBase64, "base64");
  const authTag = Buffer.from(tagBase64, "base64");
  const ciphertext = Buffer.from(ciphertextBase64, "base64");

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    iv
  );

  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  return decrypted.toString("utf8");
}

// ============================================================
// GET VERIFIED BVN FROM FIRESTORE
// ============================================================
//
// The backend is the only place where the real BVN is recovered.
//
// Flutter does NOT send the BVN here.
//
// Expected Firestore structure:
//
// users/{uid}
//   bvnVerified: true
//   bvnVerification:
//     identityHash: "..."
//     encryptedIdentity: "v1:..."
//     verified: true
//
// ============================================================

function getStoredVerifiedBvn(userData) {
  if (!userData) {
    throw new Error("User data is missing.");
  }

  const bvnVerified =
    userData.bvnVerified === true ||
    userData.bvnVerification?.verified === true;

  if (!bvnVerified) {
    throw new Error(
      "Your BVN has not been verified."
    );
  }

  const encryptedBvn =
    userData.bvnVerification?.encryptedIdentity ||
    userData.bvnEncrypted ||
    null;

  if (!encryptedBvn) {
    throw new Error(
      "Your verified BVN is not available for KENT Pay account creation. Please complete BVN verification again."
    );
  }

  const bvn = decryptKycValue(encryptedBvn);

  if (!bvn || !/^\d{11}$/.test(String(bvn).trim())) {
    throw new Error(
      "The stored verified BVN is invalid."
    );
  }

  return String(bvn).trim();
}

// ============================================================
// NORMALIZE NAME
// ============================================================

function splitName(displayName) {
  const cleanName =
    typeof displayName === "string"
      ? displayName.trim()
      : "";

  if (!cleanName) {
    return {
      firstName: "KENT",
      lastName: "User",
    };
  }

  const parts = cleanName
    .split(/\s+/)
    .filter(Boolean);

  if (parts.length === 1) {
    return {
      firstName: parts[0],
      lastName: "User",
    };
  }

  return {
    firstName: parts[0],
    lastName: parts.slice(1).join(" "),
  };
}

// ============================================================
// NORMALIZE PHONE
// ============================================================

function normalizePhone(phone) {
  if (!phone) {
    return null;
  }

  let value = String(phone).trim();

  if (value.startsWith("+234")) {
    value = value.substring(4);
  } else if (value.startsWith("234")) {
    value = value.substring(3);
  } else if (value.startsWith("0")) {
    value = value.substring(1);
  }

  return value;
}

// ============================================================
// CREATE STABLE CUSTOMER REFERENCE
// ============================================================
//
// Never put BVN or NIN inside these references.
// ============================================================

function createCustomerReference(uid) {
  const hash = crypto
    .createHash("sha256")
    .update(`kent-customer:${uid}`)
    .digest("hex")
    .substring(0, 24);

  return `kent-customer-${hash}`;
}

// ============================================================
// CREATE STABLE VIRTUAL ACCOUNT REFERENCE
// ============================================================

function createVirtualAccountReference(uid) {
  const hash = crypto
    .createHash("sha256")
    .update(`kent-virtual-account:${uid}`)
    .digest("hex")
    .substring(0, 24);

  return `kent-va-${hash}`;
}

// ============================================================
// ENSURE KENT PAY VIRTUAL ACCOUNT
// ============================================================
//
// Usage:
//
// await ensureKentPayVirtualAccount({
//   uid
// });
//
// No BVN or NIN is required from Flutter.
//
// The backend retrieves the verified BVN from Firestore.
//
// For backward compatibility, rawId/idType are still accepted
// when called directly by the KYC verification process.
//
// If rawId is supplied:
//   - it is used for this request
//
// If rawId is NOT supplied:
//   - verified BVN is recovered from Firestore
//
// Flutter should use the first form:
//
// ensureKentPayVirtualAccount({ uid })
//
// ============================================================

async function ensureKentPayVirtualAccount({
  uid,
  idType,
  rawId,
} = {}) {
  // ==========================================================
  // VALIDATE USER
  // ==========================================================

  if (!uid) {
    throw new Error(
      "User ID is required to create a KENT Pay account."
    );
  }

  const userRef = getUserRef(uid);

  // ==========================================================
  // READ USER
  // ==========================================================

  const snapshot = await userRef.get();

  if (!snapshot.exists) {
    throw new Error(
      "KENT user account was not found."
    );
  }

  const userData = snapshot.data() || {};

  // ==========================================================
  // ALREADY CREATED
  // ==========================================================

  const existing =
    userData.kentPayAccount || null;

  if (
    existing &&
    existing.accountNumber &&
    existing.status === "active"
  ) {
    return {
      created: false,
      alreadyExists: true,
      account: existing,
    };
  }

  // ==========================================================
  // CHECK FULL KYC
  // ==========================================================

  const bvnVerified =
    userData.bvnVerified === true ||
    userData.bvnVerification?.verified === true;

  const ninVerified =
    userData.ninVerified === true ||
    userData.ninVerification?.verified === true;

  if (!bvnVerified || !ninVerified) {
    throw new Error(
      "KENT Pay requires both BVN and NIN verification before a virtual account can be created."
    );
  }

  // ==========================================================
  // DETERMINE BVN TO SEND TO FLUTTERWAVE
  // ==========================================================
  //
  // IMPORTANT:
  //
  // Flutter does NOT supply this value.
  //
  // If the KYC verification process supplies rawId and idType,
  // we can use that verified value for the current request.
  //
  // Otherwise, we recover the encrypted BVN from Firestore.
  //
  // For the new "Create your KENT Pay virtual account" button,
  // this function will be called with ONLY uid.
  //
  // Therefore:
  //
  // Firestore -> decrypt BVN -> Flutterwave
  //
  // ==========================================================

  let bvn = null;

  if (
    rawId &&
    String(idType || "").toLowerCase() === "bvn"
  ) {
    bvn = String(rawId).trim();
  } else {
    bvn = getStoredVerifiedBvn(userData);
  }

  // ==========================================================
  // VALIDATE BVN
  // ==========================================================

  if (!/^\d{11}$/.test(bvn)) {
    throw new Error(
      "The verified BVN is invalid."
    );
  }

  // ==========================================================
  // USER INFORMATION
  // ==========================================================

  const email =
    userData.email ||
    userData.emailAddress ||
    null;

  if (!email) {
    throw new Error(
      "A verified email address is required before creating the KENT Pay account."
    );
  }

  const name = splitName(
    userData.displayName ||
      userData.fullName ||
      userData.name ||
      `${userData.firstName || ""} ${
        userData.lastName || ""
      }`
  );

  const firstName =
    userData.firstName ||
    name.firstName;

  const lastName =
    userData.lastName ||
    name.lastName;

  const phoneNumber =
    normalizePhone(
      userData.phoneNumber ||
        userData.phone ||
        null
    );

  // ==========================================================
  // STABLE REFERENCES
  // ==========================================================

  const customerReference =
    createCustomerReference(uid);

  const virtualAccountReference =
    createVirtualAccountReference(uid);

  // ==========================================================
  // CREATE OR REUSE FLUTTERWAVE CUSTOMER
  // ==========================================================

  let customerId =
    userData.kentPayFlutterwaveCustomerId ||
    null;

  if (!customerId) {
    console.log(
      "Creating Flutterwave customer for KENT user:",
      uid
    );

    const customerResponse =
      await createFlutterwaveCustomer({
        email,
        firstName,
        lastName,
        phoneNumber,
        idempotencyKey:
          customerReference,
      });

    customerId =
      customerResponse?.data?.id ||
      null;

    if (!customerId) {
      throw new Error(
        "Flutterwave customer creation did not return a customer ID."
      );
    }

    await userRef.set(
      {
        kentPayFlutterwaveCustomerId:
          customerId,
      },
      {
        merge: true,
      }
    );
  }

  // ==========================================================
  // CREATE STATIC VIRTUAL ACCOUNT
  // ==========================================================
  //
  // IMPORTANT:
  //
  // This is the ONLY point where the real BVN is passed
  // to the Flutterwave service.
  //
  // It never goes to Flutter.
  // It is never logged.
  //
  // ==========================================================

  console.log(
    "Creating Flutterwave static virtual account for KENT user:",
    uid
  );

  const virtualAccountResponse =
    await createStaticVirtualAccount({
      customerId,

      reference:
        virtualAccountReference,

      narration:
        `${firstName} ${lastName}`.substring(
          0,
          35
        ),

      bvn,

      nin: undefined,
    });

  const accountData =
    virtualAccountResponse?.data;

  // ==========================================================
  // VALIDATE FLUTTERWAVE RESPONSE
  // ==========================================================

  if (
    !accountData ||
    !accountData.account_number
  ) {
    console.error(
      "INVALID FLUTTERWAVE VIRTUAL ACCOUNT RESPONSE:",
      {
        hasData: !!accountData,
        hasAccountNumber:
          !!accountData?.account_number,
      }
    );

    throw new Error(
      "Flutterwave did not return a valid virtual account."
    );
  }

  // ==========================================================
  // SAVE ACCOUNT
  // ==========================================================

  const account = {
    provider: "flutterwave",

    providerAccountId:
      accountData.id || null,

    providerCustomerId:
      customerId,

    reference:
      accountData.reference ||
      virtualAccountReference,

    accountNumber:
      accountData.account_number,

    accountName:
      accountData.narration ||
      `${firstName} ${lastName}`,

    bankName:
      accountData.account_bank_name ||
      null,

    accountType:
      accountData.account_type ||
      "static",

    currency:
      accountData.currency ||
      "NGN",

    status:
      accountData.status ||
      "active",

    createdAt:
      new Date(),

    updatedAt:
      new Date(),
  };

  // ==========================================================
  // SAVE ACCOUNT TO FIRESTORE
  // ==========================================================

  await userRef.set(
    {
      kentPayAccount:
        account,

      kentPayAccountReady:
        true,

      kentPayAccountCreatedAt:
        new Date(),

      kentPayActivated:
        true,

      kentPay: {
        activated: true,
        activatedAt: new Date(),
      },
    },
    {
      merge: true,
    }
  );

  // ==========================================================
  // SUCCESS LOG
  // ==========================================================
  //
  // NEVER log BVN/NIN.
  //
  // ==========================================================

  console.log(
    "KENT Pay virtual account created successfully:",
    {
      uid,
      accountNumber:
        account.accountNumber,
      bankName:
        account.bankName,
    }
  );

  return {
    created: true,
    alreadyExists: false,
    account,
  };
}

// ============================================================
// GET EXISTING KENT PAY VIRTUAL ACCOUNT
// ============================================================

async function getKentPayVirtualAccount(uid) {
  if (!uid) {
    throw new Error(
      "User ID is required."
    );
  }

  const snapshot =
    await getUserRef(uid).get();

  if (!snapshot.exists) {
    return null;
  }

  const data =
    snapshot.data() || {};

  return (
    data.kentPayAccount ||
    null
  );
}

// ============================================================
// CHECK KENT PAY ACCOUNT STATUS
// ============================================================

async function getKentPayAccountStatus(uid) {
  if (!uid) {
    throw new Error(
      "User ID is required."
    );
  }

  const snapshot =
    await getUserRef(uid).get();

  if (!snapshot.exists) {
    throw new Error(
      "KENT user account was not found."
    );
  }

  const data =
    snapshot.data() || {};

  const account =
    data.kentPayAccount || null;

  return {
    activated:
      data.kentPayActivated === true ||
      data.kentPay?.activated === true,

    accountReady:
      data.kentPayAccountReady === true,

    hasAccount:
      !!(
        account &&
        account.accountNumber
      ),

    account,
  };
}

// ============================================================
// EXPORTS
// ============================================================

module.exports = {
  ensureKentPayVirtualAccount,
  getKentPayVirtualAccount,
  getKentPayAccountStatus,
  decryptKycValue,
};


close
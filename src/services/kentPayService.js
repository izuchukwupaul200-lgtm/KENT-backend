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

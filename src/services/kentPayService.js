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
// KENT_KYC_ENCRYPTION_KEY must be exactly:
// 64 hexadecimal characters = 32 bytes.
//
// Generate locally:
//
// node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
//
// NEVER put this key in Flutter or GitHub.
// NEVER log the key.
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

function encryptKycValue(value) {
  if (value === undefined || value === null) {
    throw new Error(
      "KYC value is required for encryption."
    );
  }

  const plaintext =
    String(value).trim();

  if (!/^\d{11}$/.test(plaintext)) {
    throw new Error(
      "KYC value must contain exactly 11 digits."
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
        plaintext,
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
// DECRYPT KYC VALUE
// ============================================================
//
// Format:
//
// v1:iv:authTag:ciphertext
// ============================================================

function decryptKycValue(encryptedValue) {
  if (!encryptedValue) {
    return null;
  }

  const value =
    String(encryptedValue);

  const parts =
    value.split(":");

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

  const key =
    getKycEncryptionKey();

  const iv =
    Buffer.from(
      ivBase64,
      "base64"
    );

  const authTag =
    Buffer.from(
      tagBase64,
      "base64"
    );

  const ciphertext =
    Buffer.from(
      ciphertextBase64,
      "base64"
    );

  const decipher =
    crypto.createDecipheriv(
      "aes-256-gcm",
      key,
      iv
    );

  decipher.setAuthTag(
    authTag
  );

  const decrypted =
    Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);

  return decrypted.toString(
    "utf8"
  );
}

// ============================================================
// BVN VALIDATION
// ============================================================

function isValidBvn(value) {
  return /^\d{11}$/.test(
    String(value || "").trim()
  );
}

// ============================================================
// GET STORED VERIFIED BVN
// ============================================================
//
// Normal path:
//
// Firestore
//    ↓
// encryptedIdentity
//    ↓
// decrypt
//    ↓
// verified BVN
//
// If encryptedIdentity does not exist, this function does NOT
// invent a BVN and does NOT call the verification provider.
// ============================================================

function getStoredVerifiedBvn(
  userData
) {
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
    userData.bvnVerification
      ?.encryptedIdentity ||
    userData.bvnEncrypted ||
    null;

  if (!encryptedBvn) {
    throw new Error(
      "Your verified BVN is not available for KENT Pay account creation. Please complete BVN verification again."
    );
  }

  const bvn =
    decryptKycValue(
      encryptedBvn
    );

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
// Used only for older verified users whose BVN was verified
// before encryptedIdentity was introduced.
//
// SECURITY:
//
// The supplied BVN must match the existing identityHash.
//
// Current KYC hashing format:
//
// SHA256("bvn:" + BVN)
//
// For compatibility, the old format:
//
// SHA256(BVN)
//
// is also accepted.
//
// Once validated, only the encrypted value is stored.
// The plaintext BVN is never stored.
// ============================================================

async function backfillEncryptedBvn(
  userRef,
  userData,
  rawId
) {
  if (!rawId) {
    return null;
  }

  const bvn =
    String(rawId).trim();

  if (!isValidBvn(bvn)) {
    throw new Error(
      "The verified BVN supplied for KENT Pay account creation is invalid."
    );
  }

  const bvnVerification =
    userData.bvnVerification ||
    {};

  const bvnVerified =
    userData.bvnVerified === true ||
    bvnVerification.verified === true;

  if (!bvnVerified) {
    throw new Error(
      "The supplied BVN has not been verified."
    );
  }

  // ----------------------------------------------------------
  // ALREADY ENCRYPTED
  // ----------------------------------------------------------

  if (
    bvnVerification.encryptedIdentity ||
    userData.bvnEncrypted
  ) {
    return getStoredVerifiedBvn(
      userData
    );
  }

  // ----------------------------------------------------------
  // EXISTING VERIFICATION HASH
  // ----------------------------------------------------------

  const storedHash =
    bvnVerification.identityHash ||
    null;

  if (!storedHash) {
    throw new Error(
      "Your verified BVN record cannot be securely recovered because its verification hash is missing."
    );
  }

  // ----------------------------------------------------------
  // CURRENT KYC HASH FORMAT
  // ----------------------------------------------------------

  const currentHash =
    crypto
      .createHash("sha256")
      .update(`bvn:${bvn}`)
      .digest("hex");

  // ----------------------------------------------------------
  // LEGACY HASH FORMAT
  // ----------------------------------------------------------

  const legacyHash =
    crypto
      .createHash("sha256")
      .update(bvn)
      .digest("hex");

  const normalizedStoredHash =
    String(storedHash)
      .trim()
      .toLowerCase();

  const hashMatches =
    normalizedStoredHash ===
      currentHash ||
    normalizedStoredHash ===
      legacyHash;

  if (!hashMatches) {
    throw new Error(
      "The supplied BVN does not match the BVN that was previously verified."
    );
  }

  // ----------------------------------------------------------
  // ENCRYPT BVN
  // ----------------------------------------------------------

  const encryptedIdentity =
    encryptKycValue(bvn);

  // ----------------------------------------------------------
  // SAVE SECURE BVN
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

  return bvn;
}

// ============================================================
// NORMALIZE NAME
// ============================================================

function splitName(
  displayName
) {
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

  const parts =
    cleanName
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
    lastName:
      parts
        .slice(1)
        .join(" "),
  };
}

// ============================================================
// NORMALIZE PHONE
// ============================================================

function normalizePhone(
  phone
) {
  if (!phone) {
    return null;
  }

  let value =
    String(phone).trim();

  if (
    value.startsWith("+234")
  ) {
    value =
      value.substring(4);
  } else if (
    value.startsWith("234")
  ) {
    value =
      value.substring(3);
  } else if (
    value.startsWith("0")
  ) {
    value =
      value.substring(1);
  }

  return value;
}

// ============================================================
// CUSTOMER REFERENCE
// ============================================================

function createCustomerReference(
  uid
) {
  const hash =
    crypto
      .createHash("sha256")
      .update(
        `kent-customer:${uid}`
      )
      .digest("hex")
      .substring(0, 24);

  return `kent-customer-${hash}`;
}

// ============================================================
// VIRTUAL ACCOUNT REFERENCE
// ============================================================

function createVirtualAccountReference(
  uid
) {
  const hash =
    crypto
      .createHash("sha256")
      .update(
        `kent-virtual-account:${uid}`
      )
      .digest("hex")
      .substring(0, 24);

  return `kent-va-${hash}`;
}

// ============================================================
// ENSURE KENT PAY VIRTUAL ACCOUNT
// ============================================================

async function ensureKentPayVirtualAccount({
  uid,
  idType,
  rawId,
} = {}) {
  // ----------------------------------------------------------
  // VALIDATE UID
  // ----------------------------------------------------------

  if (!uid) {
    throw new Error(
      "User ID is required to create a KENT Pay account."
    );
  }

  const userRef =
    getUserRef(uid);

  // ----------------------------------------------------------
  // LOAD USER
  // ----------------------------------------------------------

  const snapshot =
    await userRef.get();

  if (!snapshot.exists) {
    throw new Error(
      "KENT user account was not found."
    );
  }

  const userData =
    snapshot.data() || {};

  // ----------------------------------------------------------
  // EXISTING ACCOUNT
  // ----------------------------------------------------------

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

  // ----------------------------------------------------------
  // CHECK BVN
  // ----------------------------------------------------------

  const bvnVerified =
    userData.bvnVerified === true ||
    userData.bvnVerification?.verified === true;

  // ----------------------------------------------------------
  // CHECK NIN
  // ----------------------------------------------------------

  const ninVerified =
    userData.ninVerified === true ||
    userData.ninVerification?.verified === true;

  if (
    !bvnVerified ||
    !ninVerified
  ) {
    throw new Error(
      "KENT Pay requires both BVN and NIN verification before a virtual account can be created."
    );
  }

  // ----------------------------------------------------------
  // DETERMINE BVN
  // ----------------------------------------------------------
  //
  // Case 1:
  // KYC process passes the already verified BVN.
  //
  // Case 2:
  // Manual Create Account request passes BVN because an old
  // verified record is missing encryptedIdentity.
  //
  // Case 3:
  // Normal users already have encryptedIdentity, so recover
  // the BVN from Firestore.
  // ----------------------------------------------------------

  let bvn = null;

  const normalizedIdType =
    String(idType || "")
      .trim()
      .toLowerCase();

  if (
    rawId &&
    normalizedIdType === "bvn"
  ) {
    bvn =
      await backfillEncryptedBvn(
        userRef,
        userData,
        rawId
      );
  }

  if (!bvn) {
    bvn =
      getStoredVerifiedBvn(
        userData
      );
  }

  // ----------------------------------------------------------
  // FINAL BVN VALIDATION
  // ----------------------------------------------------------

  if (!isValidBvn(bvn)) {
    throw new Error(
      "The verified BVN is invalid."
    );
  }

  bvn =
    String(bvn).trim();

  // ----------------------------------------------------------
  // EMAIL
  // ----------------------------------------------------------

  const email =
    userData.email ||
    userData.emailAddress ||
    null;

  if (!email) {
    throw new Error(
      "A verified email address is required before creating the KENT Pay account."
    );
  }

  // ----------------------------------------------------------
  // NAME
  // ----------------------------------------------------------

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

  // ----------------------------------------------------------
  // PHONE
  // ----------------------------------------------------------

  const phoneNumber =
    normalizePhone(
      userData.phoneNumber ||
        userData.phone ||
        null
    );

  // ----------------------------------------------------------
  // STABLE REFERENCES
  // ----------------------------------------------------------

  const customerReference =
    createCustomerReference(
      uid
    );

  const virtualAccountReference =
    createVirtualAccountReference(
      uid
    );

  // ----------------------------------------------------------
  // FLUTTERWAVE CUSTOMER
  // ----------------------------------------------------------

  let customerId =
    userData
      .kentPayFlutterwaveCustomerId ||
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
      customerResponse
        ?.data?.id ||
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

  // ----------------------------------------------------------
  // CREATE STATIC VIRTUAL ACCOUNT
  // ----------------------------------------------------------

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
        `${firstName} ${lastName}`
          .substring(0, 35),

      bvn,

      nin: undefined,
    });

  // ----------------------------------------------------------
  // FLUTTERWAVE RESPONSE
  // ----------------------------------------------------------

  const accountData =
    virtualAccountResponse?.data;

  if (
    !accountData ||
    !accountData.account_number
  ) {
    console.error(
      "INVALID FLUTTERWAVE VIRTUAL ACCOUNT RESPONSE:",
      {
        hasData:
          !!accountData,

        hasAccountNumber:
          !!accountData
            ?.account_number,
      }
    );

    throw new Error(
      "Flutterwave did not return a valid virtual account."
    );
  }

  // ----------------------------------------------------------
  // ACCOUNT OBJECT
  // ----------------------------------------------------------

  const account = {
    provider:
      "flutterwave",

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

  // ----------------------------------------------------------
  // SAVE ACCOUNT
  // ----------------------------------------------------------

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
        activatedAt:
          new Date(),
      },
    },
    {
      merge: true,
    }
  );

  // ----------------------------------------------------------
  // SUCCESS
  // ----------------------------------------------------------

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

async function getKentPayVirtualAccount(
  uid
) {
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

async function getKentPayAccountStatus(
  uid
) {
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
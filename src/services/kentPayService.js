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

async function ensureKentPayVirtualAccount({
  uid,
  idType,
  rawId,
}) {
  if (!uid) {
    throw new Error(
      "User ID is required to create a KENT Pay account."
    );
  }

  if (!rawId) {
    throw new Error(
      "Verified identity number is required."
    );
  }

  if (
    idType !== "bvn" &&
    idType !== "nin"
  ) {
    throw new Error(
      "Identity type must be BVN or NIN."
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
  // CHECK EXISTING ACCOUNT
  // ==========================================================

  const existing =
    userData.kentPayAccount;

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
  // CREATE / REUSE FLUTTERWAVE CUSTOMER
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

      bvn:
        idType === "bvn"
          ? rawId
          : undefined,

      nin:
        idType === "nin"
          ? rawId
          : undefined,
    });

  // ==========================================================
  // FLUTTERWAVE RESPONSE
  // ==========================================================

  const accountData =
    virtualAccountResponse?.data;

  if (
    !accountData ||
    !accountData.account_number
  ) {
    console.error(
      "INVALID FLUTTERWAVE VIRTUAL ACCOUNT RESPONSE:",
      virtualAccountResponse
    );

    throw new Error(
      "Flutterwave did not return a valid virtual account."
    );
  }

  // ==========================================================
  // BUILD KENT ACCOUNT
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
  // SAVE TO FIRESTORE
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
    },
    {
      merge: true,
    }
  );

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
// GET EXISTING KENT PAY ACCOUNT
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
// EXPORTS
// ============================================================
//
// IMPORTANT:
// Both functions MUST be exported because kentPay.js imports
// both of them.
//
// ============================================================

module.exports = {
  ensureKentPayVirtualAccount,
  getKentPayVirtualAccount,
};

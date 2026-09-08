const crypto = require("crypto");
const { promisify } = require("util");

const { db } = require("../../firebaseAdmin");

const {
  getNigerianBanks,
  resolveNigerianBankAccount,
  createDirectBankTransfer,
  getDirectTransferStatus,
} = require("./flutterwave");

// ============================================================
// SCRYPT
// ============================================================

const scryptAsync =
  promisify(crypto.scrypt);

// ============================================================
// SETTINGS
// ============================================================

const MIN_TRANSFER_AMOUNT = Number(
  process.env.KENT_MIN_TRANSFER_AMOUNT || 100
);

const MAX_TRANSFER_AMOUNT = Number(
  process.env.KENT_MAX_TRANSFER_AMOUNT || 500000
);

const TRANSFER_FEE = Number(
  process.env.KENT_TRANSFER_FEE || 0
);

// PIN security
const PIN_LENGTH = 4;

const MAX_PIN_ATTEMPTS = 5;

const PIN_LOCKOUT_MS =
  15 * 60 * 1000;

// ============================================================
// FIRESTORE REFERENCES
// ============================================================

function getUserRef(uid) {
  return db
    .collection("users")
    .doc(uid);
}

function getTransferPinRef(uid) {
  return getUserRef(uid)
    .collection("security")
    .doc("transferPin");
}

// ============================================================
// BASIC VALIDATION
// ============================================================

// Nigerian Flutterwave bank codes can be 3-digit
// traditional bank codes or longer codes used by
// some fintech/MFB institutions.
//
// Example:
// 011    -> First Bank
// 044    -> Access Bank
// 090551 -> longer fintech/MFB-style code
function validBankCode(value) {
  return /^\d{3,6}$/.test(
    String(value || "").trim()
  );
}

function validAccountNumber(value) {
  return /^\d{10}$/.test(
    String(value || "").trim()
  );
}

function validAmount(value) {
  const amount = Number(value);

  return (
    Number.isFinite(amount) &&
    amount > 0
  );
}

function validPin(pin) {
  return /^\d{4}$/.test(
    String(pin || "")
  );
}

// ============================================================
// GENERATE TRANSFER REFERENCE
// ============================================================

function generateTransferReference(uid) {
  const uidPart = String(uid)
    .replace(
      /[^a-zA-Z0-9]/g,
      ""
    )
    .substring(0, 12);

  const random =
    crypto
      .randomBytes(8)
      .toString("hex");

  return `kent-tr-${uidPart}-${Date.now()}-${random}`;
}

// ============================================================
// HASH PIN
// ============================================================

async function hashTransferPin(pin) {
  if (!validPin(pin)) {
    throw new Error(
      "Transfer PIN must contain exactly 4 digits."
    );
  }

  const salt =
    crypto.randomBytes(16);

  const derivedKey =
    await scryptAsync(
      String(pin),
      salt,
      64
    );

  return {
    algorithm: "scrypt",

    salt:
      salt.toString("base64"),

    hash:
      derivedKey.toString("base64"),

    version: 1,
  };
}

// ============================================================
// VERIFY HASH
// ============================================================

async function verifyTransferPinHash(
  pin,
  storedPin
) {
  if (
    !validPin(pin) ||
    !storedPin ||
    !storedPin.hash ||
    !storedPin.salt
  ) {
    return false;
  }

  try {
    const salt =
      Buffer.from(
        storedPin.salt,
        "base64"
      );

    const expectedHash =
      Buffer.from(
        storedPin.hash,
        "base64"
      );

    const derivedKey =
      await scryptAsync(
        String(pin),
        salt,
        expectedHash.length
      );

    if (
      derivedKey.length !==
      expectedHash.length
    ) {
      return false;
    }

    return crypto.timingSafeEqual(
      derivedKey,
      expectedHash
    );
  } catch (error) {
    return false;
  }
}

// ============================================================
// CREATE TRANSFER PIN
// ============================================================

async function createTransferPin({
  uid,
  pin,
}) {
  if (!uid) {
    throw new Error(
      "User ID is required."
    );
  }

  if (!validPin(pin)) {
    throw new Error(
      "Transfer PIN must contain exactly 4 digits."
    );
  }

  const pinRef =
    getTransferPinRef(uid);

  const snapshot =
    await pinRef.get();

  if (snapshot.exists) {
    throw new Error(
      "Transfer PIN already exists."
    );
  }

  const securePin =
    await hashTransferPin(pin);

  await pinRef.set({
    algorithm:
      securePin.algorithm,

    salt:
      securePin.salt,

    hash:
      securePin.hash,

    version:
      securePin.version,

    failedAttempts:
      0,

    lockedUntil:
      null,

    createdAt:
      new Date(),

    updatedAt:
      new Date(),
  });

  return {
    created: true,
  };
}

// ============================================================
// CHANGE TRANSFER PIN
// ============================================================

async function changeTransferPin({
  uid,
  currentPin,
  newPin,
}) {
  if (!uid) {
    throw new Error(
      "User ID is required."
    );
  }

  if (!validPin(currentPin)) {
    throw new Error(
      "Current transfer PIN must contain exactly 4 digits."
    );
  }

  if (!validPin(newPin)) {
    throw new Error(
      "New transfer PIN must contain exactly 4 digits."
    );
  }

  if (currentPin === newPin) {
    throw new Error(
      "New transfer PIN must be different from your current PIN."
    );
  }

  const pinRef =
    getTransferPinRef(uid);

  const snapshot =
    await pinRef.get();

  if (!snapshot.exists) {
    throw new Error(
      "Transfer PIN has not been created yet."
    );
  }

  const stored =
    snapshot.data() || {};

  const now =
    Date.now();

  const lockedUntil =
    stored.lockedUntil
      ? new Date(
          stored.lockedUntil
        ).getTime()
      : 0;

  if (
    lockedUntil &&
    now < lockedUntil
  ) {
    throw new Error(
      "Your transfer PIN is temporarily locked. Please try again later."
    );
  }

  const matches =
    await verifyTransferPinHash(
      currentPin,
      stored
    );

  if (!matches) {
    await recordFailedPinAttempt(
      pinRef,
      stored
    );

    throw new Error(
      "Current transfer PIN is incorrect."
    );
  }

  const securePin =
    await hashTransferPin(
      newPin
    );

  await pinRef.set(
    {
      algorithm:
        securePin.algorithm,

      salt:
        securePin.salt,

      hash:
        securePin.hash,

      version:
        securePin.version,

      failedAttempts:
        0,

      lockedUntil:
        null,

      updatedAt:
        new Date(),
    },
    {
      merge: true,
    }
  );

  return {
    changed: true,
  };
}

// ============================================================
// RECORD FAILED PIN ATTEMPT
// ============================================================

async function recordFailedPinAttempt(
  pinRef,
  currentData
) {
  await db.runTransaction(
    async (transaction) => {
      const snapshot =
        await transaction.get(
          pinRef
        );

      if (!snapshot.exists) {
        return;
      }

      const latest =
        snapshot.data() || {};

      const currentAttempts =
        Number(
          latest.failedAttempts || 0
        );

      const nextAttempts =
        currentAttempts + 1;

      const lock =
        nextAttempts >=
        MAX_PIN_ATTEMPTS;

      transaction.update(
        pinRef,
        {
          failedAttempts:
            nextAttempts,

          lockedUntil:
            lock
              ? new Date(
                  Date.now() +
                    PIN_LOCKOUT_MS
                )
              : null,

          updatedAt:
            new Date(),
        }
      );
    }
  );
}

// ============================================================
// VERIFY TRANSFER PIN
// ============================================================

async function verifyTransferPin({
  uid,
  pin,
}) {
  if (!uid) {
    throw new Error(
      "User ID is required."
    );
  }

  if (!validPin(pin)) {
    throw new Error(
      "Invalid transfer PIN."
    );
  }

  const pinRef =
    getTransferPinRef(uid);

  const snapshot =
    await pinRef.get();

  if (!snapshot.exists) {
    const error =
      new Error(
        "Transfer PIN has not been created yet."
      );

    error.code =
      "TRANSFER_PIN_NOT_SET";

    throw error;
  }

  const stored =
    snapshot.data() || {};

  const lockedUntil =
    stored.lockedUntil
      ? new Date(
          stored.lockedUntil
        ).getTime()
      : 0;

  if (
    lockedUntil &&
    Date.now() < lockedUntil
  ) {
    const error =
      new Error(
        "Your transfer PIN is temporarily locked. Please try again later."
      );

    error.code =
      "TRANSFER_PIN_LOCKED";

    throw error;
  }

  if (
    lockedUntil &&
    Date.now() >= lockedUntil
  ) {
    await pinRef.update({
      failedAttempts: 0,
      lockedUntil: null,
      updatedAt: new Date(),
    });
  }

  const matches =
    await verifyTransferPinHash(
      pin,
      stored
    );

  if (!matches) {
    await recordFailedPinAttempt(
      pinRef,
      stored
    );

    const attempts =
      Number(
        stored.failedAttempts || 0
      ) + 1;

    const error =
      new Error(
        attempts >=
        MAX_PIN_ATTEMPTS
          ? "Too many incorrect transfer PIN attempts. Your PIN is temporarily locked."
          : "Incorrect transfer PIN."
      );

    error.code =
      attempts >=
      MAX_PIN_ATTEMPTS
        ? "TRANSFER_PIN_LOCKED"
        : "TRANSFER_PIN_INCORRECT";

    throw error;
  }

  await pinRef.update({
    failedAttempts: 0,
    lockedUntil: null,
    updatedAt: new Date(),
  });

  return {
    verified: true,
  };
}

// ============================================================
// CHECK PIN STATUS
// ============================================================

async function getTransferPinStatus(
  uid
) {
  if (!uid) {
    throw new Error(
      "User ID is required."
    );
  }

  const snapshot =
    await getTransferPinRef(
      uid
    ).get();

  if (!snapshot.exists) {
    return {
      pinSet: false,
      locked: false,
    };
  }

  const data =
    snapshot.data() || {};

  const lockedUntil =
    data.lockedUntil
      ? new Date(
          data.lockedUntil
        ).getTime()
      : 0;

  const locked =
    lockedUntil &&
    Date.now() < lockedUntil;

  return {
    pinSet: true,
    locked: !!locked,
    lockedUntil:
      locked
        ? data.lockedUntil
        : null,
  };
}

// ============================================================
// GET NIGERIAN BANKS
// ============================================================

async function listNigerianBanks() {
  const response =
    await getNigerianBanks();

  if (!response) {
    return [];
  }

  if (
    Array.isArray(
      response.data
    )
  ) {
    return response.data;
  }

  if (
    Array.isArray(response)
  ) {
    return response;
  }

  return [];
}

// ============================================================
// RESOLVE BANK ACCOUNT
// ============================================================

async function resolveBankAccount({
  bankCode,
  accountNumber,
}) {
  const normalizedBankCode =
    String(bankCode || "")
      .trim();

  const normalizedAccountNumber =
    String(accountNumber || "")
      .trim();

  if (!validBankCode(normalizedBankCode)) {
    throw new Error(
      "Invalid bank code."
    );
  }

  if (
    !validAccountNumber(
      normalizedAccountNumber
    )
  ) {
    throw new Error(
      "Account number must contain 10 digits."
    );
  }

  try {
    const response =
      await resolveNigerianBankAccount({
        bankCode:
          normalizedBankCode,

        accountNumber:
          normalizedAccountNumber,
      });

    const data =
      response?.data || null;

    if (
      !data ||
      !data.account_name
    ) {
      throw new Error(
        "Unable to verify this bank account."
      );
    }

    return {
      bankCode:
        data.bank_code ||
        normalizedBankCode,

      accountNumber:
        data.account_number ||
        normalizedAccountNumber,

      accountName:
        String(
          data.account_name
        ).trim(),
    };
  } catch (error) {
    console.error(
      "KENT ACCOUNT RESOLUTION PROVIDER ERROR:",
      error.response?.data ||
        error.message
    );

    const providerData =
      error.response?.data;

    const providerMessage =
      providerData?.message ||
      providerData?.error?.message ||
      providerData?.error ||
      null;

    const providerError =
      new Error(
        providerMessage
          ? String(providerMessage)
          : error.message ||
            "Unable to verify this bank account."
      );

    providerError.status =
      error.response?.status;

    providerError.providerResponse =
      providerData || null;

    throw providerError;
  }
}

// ============================================================
// CREATE KENT TRANSFER
// ============================================================

async function createKentTransfer({
  uid,
  bankCode,
  accountNumber,
  amount,
  narration,
  pin,
}) {
  if (!uid) {
    throw new Error(
      "User ID is required."
    );
  }

  await verifyTransferPin({
    uid,
    pin,
  });

  if (!validBankCode(bankCode)) {
    throw new Error(
      "Invalid bank code."
    );
  }

  if (
    !validAccountNumber(
      accountNumber
    )
  ) {
    throw new Error(
      "Account number must contain 10 digits."
    );
  }

  if (!validAmount(amount)) {
    throw new Error(
      "Transfer amount must be greater than zero."
    );
  }

  const numericAmount =
    Number(amount);

  if (
    numericAmount <
    MIN_TRANSFER_AMOUNT
  ) {
    throw new Error(
      `Minimum transfer amount is ₦${MIN_TRANSFER_AMOUNT.toLocaleString()}.`
    );
  }

  if (
    numericAmount >
    MAX_TRANSFER_AMOUNT
  ) {
    throw new Error(
      `Maximum transfer amount is ₦${MAX_TRANSFER_AMOUNT.toLocaleString()}.`
    );
  }

  const recipient =
    await resolveBankAccount({
      bankCode,
      accountNumber,
    });

  const reference =
    generateTransferReference(
      uid
    );

  const transferRef =
    db.collection("transfers").doc();

  const userRef =
    getUserRef(uid);

  const totalDebit =
    numericAmount +
    TRANSFER_FEE;

  await db.runTransaction(
    async (transaction) => {
      const userSnapshot =
        await transaction.get(
          userRef
        );

      if (!userSnapshot.exists) {
        throw new Error(
          "KENT user account was not found."
        );
      }

      const userData =
        userSnapshot.data() || {};

      const bvnVerified =
        userData.bvnVerified === true ||
        userData.bvnVerification?.verified === true;

      const ninVerified =
        userData.ninVerified === true ||
        userData.ninVerification?.verified === true;

      if (
        !bvnVerified ||
        !ninVerified
      ) {
        throw new Error(
          "Complete BVN and NIN verification before sending money."
        );
      }

      const kentPayAccount =
        userData.kentPayAccount ||
        null;

      if (
        !kentPayAccount ||
        !kentPayAccount.accountNumber
      ) {
        throw new Error(
          "Your KENT Pay account is not ready yet."
        );
      }

      const walletBalance =
        typeof userData.walletBalance ===
        "number"
          ? userData.walletBalance
          : 0;

      if (
        walletBalance <
        totalDebit
      ) {
        throw new Error(
          "Insufficient KENT wallet balance."
        );
      }

      const newBalance =
        walletBalance -
        totalDebit;

      transaction.update(
        userRef,
        {
          walletBalance:
            newBalance,

          updatedAt:
            new Date(),
        }
      );

      transaction.set(
        transferRef,
        {
          uid,

          reference,

          status:
            "pending",

          providerStatus:
            "CREATING",

          amount:
            numericAmount,

          fee:
            TRANSFER_FEE,

          totalDebit,

          currency:
            "NGN",

          recipient: {
            bankCode:
              recipient.bankCode,

            accountNumber:
              recipient.accountNumber,

            accountName:
              recipient.accountName,
          },

          narration:
            narration ||
            "KENT Pay transfer",

          createdAt:
            new Date(),

          updatedAt:
            new Date(),
        }
      );
    }
  );

  try {
    const providerResponse =
      await createDirectBankTransfer({
        reference,

        amount:
          numericAmount,

        bankCode:
          recipient.bankCode,

        accountNumber:
          recipient.accountNumber,

        narration:
          narration ||
          "KENT Pay transfer",
      });

    const providerData =
      providerResponse?.data ||
      null;

    if (!providerData) {
      throw new Error(
        "Flutterwave did not return a transfer response."
      );
    }

    const providerTransferId =
      providerData.id ||
      null;

    const providerStatus =
      providerData.status ||
      "NEW";

    await transferRef.update({
      providerTransferId,

      providerStatus,

      status:
        "pending",

      providerResponse: {
        id:
          providerData.id ||
          null,

        status:
          providerData.status ||
          null,

        reference:
          providerData.reference ||
          reference,
      },

      updatedAt:
        new Date(),
    });

    return {
      success: true,

      reference,

      transferId:
        providerTransferId,

      status:
        providerStatus,

      amount:
        numericAmount,

      fee:
        TRANSFER_FEE,

      totalDebit,

      recipient,
    };
  } catch (error) {
    console.error(
      "KENT FLUTTERWAVE TRANSFER CREATION ERROR:",
      error.response?.data ||
        error.message
    );

    const providerStatus =
      error.response?.status;

    const definitiveFailure =
      Number.isInteger(
        providerStatus
      ) &&
      providerStatus >= 400 &&
      providerStatus < 500 &&
      providerStatus !== 408 &&
      providerStatus !== 409 &&
      providerStatus !== 429;

    if (
      definitiveFailure
    ) {
      await refundFailedTransfer({
        transferRef,

        uid,

        amount:
          totalDebit,

        reason:
          "Flutterwave rejected the transfer request.",
      });
    } else {
      await transferRef.update({
        status:
          "pending",

        providerStatus:
          "UNKNOWN",

        providerError:
          error.message ||
          "Flutterwave response status is unknown.",

        updatedAt:
          new Date(),
      });
    }

    throw error;
  }
}

// ============================================================
// REFUND FAILED TRANSFER
// ============================================================

async function refundFailedTransfer({
  transferRef,
  uid,
  amount,
  reason,
}) {
  const userRef =
    getUserRef(uid);

  await db.runTransaction(
    async (transaction) => {
      const userSnapshot =
        await transaction.get(
          userRef
        );

      if (!userSnapshot.exists) {
        throw new Error(
          "User account disappeared during transfer refund."
        );
      }

      const transferSnapshot =
        await transaction.get(
          transferRef
        );

      const transferData =
        transferSnapshot.exists
          ? transferSnapshot.data() || {}
          : {};

      if (
        transferData.refunded === true
      ) {
        return;
      }

      const userData =
        userSnapshot.data() ||
        {};

      const currentBalance =
        typeof userData.walletBalance ===
        "number"
          ? userData.walletBalance
          : 0;

      transaction.update(
        userRef,
        {
          walletBalance:
            currentBalance +
            Number(amount),

          updatedAt:
            new Date(),
        }
      );

      transaction.update(
        transferRef,
        {
          status:
            "failed",

          providerStatus:
            "FAILED",

          refunded:
            true,

          refundedAt:
            new Date(),

          failureReason:
            reason,

          updatedAt:
            new Date(),
        }
      );
    }
  );
}

// ============================================================
// GET TRANSFER STATUS
// ============================================================

async function getKentTransferStatus({
  uid,
  transferId,
}) {
  if (!uid) {
    throw new Error(
      "User ID is required."
    );
  }

  if (!transferId) {
    throw new Error(
      "Transfer ID is required."
    );
  }

  const transferQuery =
    await db
      .collection("transfers")
      .where(
        "uid",
        "==",
        uid
      )
      .where(
        "providerTransferId",
        "==",
        transferId
      )
      .limit(1)
      .get();

  if (
    transferQuery.empty
  ) {
    throw new Error(
      "Transfer was not found."
    );
  }

  const transferDoc =
    transferQuery.docs[0];

  const transferData =
    transferDoc.data() || {};

  if (
    transferData.status ===
      "successful" ||
    transferData.status ===
      "failed"
  ) {
    return {
      ...transferData,

      id:
        transferDoc.id,
    };
  }

  const providerResponse =
    await getDirectTransferStatus(
      transferId
    );

  const providerData =
    providerResponse?.data ||
    null;

  if (!providerData) {
    return {
      ...transferData,

      id:
        transferDoc.id,
    };
  }

  const providerStatus =
    String(
      providerData.status ||
        ""
    ).toUpperCase();

  if (
    providerStatus ===
    "SUCCESSFUL"
  ) {
    await transferDoc.ref.update({
      status:
        "successful",

      providerStatus,

      completedAt:
        new Date(),

      updatedAt:
        new Date(),
    });

    return {
      ...transferData,

      id:
        transferDoc.id,

      status:
        "successful",

      providerStatus,
    };
  }

  if (
    providerStatus ===
      "FAILED" ||
    providerStatus ===
      "CANCELLED"
  ) {
    await refundFailedTransfer({
      transferRef:
        transferDoc.ref,

      uid,

      amount:
        Number(
          transferData.totalDebit ||
            0
        ),

      reason:
        `Flutterwave transfer status: ${providerStatus}`,
    });

    return {
      ...transferData,

      id:
        transferDoc.id,

      status:
        "failed",

      providerStatus,
    };
  }

  await transferDoc.ref.update({
    status:
      "pending",

    providerStatus,

    updatedAt:
      new Date(),
  });

  return {
    ...transferData,

    id:
      transferDoc.id,

    status:
      "pending",

    providerStatus,
  };
}

// ============================================================
// EXPORTS
// ============================================================

module.exports = {
  listNigerianBanks,

  resolveBankAccount,

  createKentTransfer,

  getKentTransferStatus,

  createTransferPin,

  changeTransferPin,

  verifyTransferPin,

  getTransferPinStatus,
};
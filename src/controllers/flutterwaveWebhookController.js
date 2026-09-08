const crypto = require("crypto");

const { db } = require("../../firebaseAdmin");

const {
  getFlutterwaveAccessToken,
} = require("../services/flutterwave");

// ============================================================
// FLUTTERWAVE V4 WEBHOOK CONTROLLER
// ============================================================
//
// POST /api/flutterwave/webhook
//
// Purpose:
// 1. Receive Flutterwave webhook
// 2. Verify Flutterwave signature
// 3. Verify the charge directly with Flutterwave
// 4. Find the KENT user from their virtual account
// 5. Prevent duplicate wallet funding
// 6. Add the payment amount to walletBalance
// 7. Record the wallet transaction
//
// IMPORTANT:
// Flutterwave sends the webhook to:
// /api/flutterwave/webhook
//
// The raw request body must be preserved by server.js.
// ============================================================


// ============================================================
// CONFIG
// ============================================================

const FLW_BASE_URL =
  process.env.FLW_BASE_URL ||
  "https://f4bexperience.flutterwave.com";


// ============================================================
// SAFE JSON LOGGING
// ============================================================

function safeJson(value) {
  try {
    return JSON.stringify(value, null, 2);
  } catch (error) {
    return "[Unable to serialize value]";
  }
}


// ============================================================
// SIGNATURE VERIFICATION
// ============================================================
//
// Flutterwave V4 webhook signature:
//
// HMAC-SHA256
// Base64 encoded
//
// Header:
// flutterwave-signature
//
// Secret:
// FLW_WEBHOOK_SECRET_HASH
//
// ============================================================

function verifyFlutterwaveSignature(req) {
  const secret =
    process.env.FLW_WEBHOOK_SECRET_HASH ||
    process.env.FLW_SECRET_HASH;

  const receivedSignature =
    req.headers["flutterwave-signature"];

  const rawBody =
    req.rawBody;

  if (!secret) {
    console.error(
      "FLUTTERWAVE WEBHOOK ERROR: FLW_WEBHOOK_SECRET_HASH is missing."
    );

    return false;
  }

  if (!receivedSignature) {
    console.error(
      "FLUTTERWAVE WEBHOOK ERROR: flutterwave-signature header is missing."
    );

    return false;
  }

  if (
    typeof rawBody !== "string"
  ) {
    console.error(
      "FLUTTERWAVE WEBHOOK ERROR: req.rawBody is missing."
    );

    return false;
  }

  try {
    const expectedSignature =
      crypto
        .createHmac(
          "sha256",
          secret
        )
        .update(rawBody, "utf8")
        .digest("base64");

    const receivedBuffer =
      Buffer.from(
        String(receivedSignature),
        "utf8"
      );

    const expectedBuffer =
      Buffer.from(
        expectedSignature,
        "utf8"
      );

    if (
      receivedBuffer.length !==
      expectedBuffer.length
    ) {
      return false;
    }

    return crypto.timingSafeEqual(
      receivedBuffer,
      expectedBuffer
    );
  } catch (error) {
    console.error(
      "FLUTTERWAVE SIGNATURE VERIFICATION ERROR:",
      error
    );

    return false;
  }
}


// ============================================================
// FLUTTERWAVE CHARGE VERIFICATION
// ============================================================
//
// Never trust the webhook amount/status alone.
//
// We verify the charge directly with Flutterwave.
//
// Endpoint:
//
// GET /charges/{chargeId}
//
// ============================================================

async function verifyFlutterwaveCharge(
  chargeId
) {
  if (!chargeId) {
    throw new Error(
      "Flutterwave charge ID is missing."
    );
  }

  console.log(
    "=================================================="
  );

  console.log(
    "VERIFYING FLUTTERWAVE CHARGE"
  );

  console.log(
    "Charge ID:",
    chargeId
  );

  console.log(
    "=================================================="
  );

  const accessToken =
    await getFlutterwaveAccessToken();

  if (!accessToken) {
    throw new Error(
      "Unable to obtain Flutterwave access token."
    );
  }

  // ----------------------------------------------------------
  // IMPORTANT:
  // Do not use a template literal here.
  // This avoids syntax problems and safely encodes chargeId.
  // ----------------------------------------------------------

  const url =
    FLW_BASE_URL +
    "/charges/" +
    encodeURIComponent(chargeId);

  console.log(
    "FLUTTERWAVE CHARGE VERIFY URL:",
    url
  );

  const axios =
    require("axios");

  const response =
    await axios.get(
      url,
      {
        headers: {
          Authorization:
            "Bearer " +
            accessToken,

          Accept:
            "application/json",
        },

        timeout: 30000,
      }
    );

  const responseData =
    response.data;

  console.log(
    "FLUTTERWAVE CHARGE VERIFICATION RESPONSE:"
  );

  console.log(
    safeJson(responseData)
  );

  if (
    !responseData ||
    !responseData.data
  ) {
    throw new Error(
      "Flutterwave charge verification returned no data."
    );
  }

  console.log(
    "FLUTTERWAVE CHARGE VERIFIED"
  );

  return responseData.data;
}


// ============================================================
// NORMALIZE ACCOUNT NUMBER
// ============================================================

function normalizeAccountNumber(
  value
) {
  if (
    value === null ||
    value === undefined
  ) {
    return null;
  }

  const digits =
    String(value).replace(
      /\D/g,
      ""
    );

  if (
    digits.length !== 10
  ) {
    return null;
  }

  return digits;
}


// ============================================================
// FIND USER BY KENT VIRTUAL ACCOUNT
// ============================================================
//
// Primary match:
// users/{uid}.kentPayAccount.accountNumber
//
// Secondary identifiers are also checked for compatibility.
// ============================================================

async function findUserByPayment(
  {
    accountNumber,
    customerId,
    virtualAccountId,
  }
) {
  console.log(
    "=================================================="
  );

  console.log(
    "SEARCHING FOR KENT USER"
  );

  console.log(
    "Account Number:",
    accountNumber
      ? accountNumber
      : "none"
  );

  console.log(
    "Customer ID:",
    customerId
      ? customerId
      : "none"
  );

  console.log(
    "Virtual Account ID:",
    virtualAccountId
      ? virtualAccountId
      : "none"
  );

  console.log(
    "=================================================="
  );

  // ----------------------------------------------------------
  // 1. PRIMARY:
  // kentPayAccount.accountNumber
  // ----------------------------------------------------------

  if (accountNumber) {
    const snapshot =
      await db
        .collection("users")
        .where(
          "kentPayAccount.accountNumber",
          "==",
          accountNumber
        )
        .limit(1)
        .get();

    if (
      !snapshot.empty
    ) {
      return snapshot.docs[0];
    }
  }

  // ----------------------------------------------------------
  // 2. Flutterwave customer ID
  // ----------------------------------------------------------

  if (customerId) {
    const snapshot =
      await db
        .collection("users")
        .where(
          "kentPayAccount.providerCustomerId",
          "==",
          customerId
        )
        .limit(1)
        .get();

    if (
      !snapshot.empty
    ) {
      return snapshot.docs[0];
    }

    // --------------------------------------------------------
    // Legacy field
    // --------------------------------------------------------

    const legacySnapshot =
      await db
        .collection("users")
        .where(
          "kentPayFlutterwaveCustomerId",
          "==",
          customerId
        )
        .limit(1)
        .get();

    if (
      !legacySnapshot.empty
    ) {
      return legacySnapshot.docs[0];
    }

    // --------------------------------------------------------
    // Older legacy field
    // --------------------------------------------------------

    const oldSnapshot =
      await db
        .collection("users")
        .where(
          "kentPayAccount.customerId",
          "==",
          customerId
        )
        .limit(1)
        .get();

    if (
      !oldSnapshot.empty
    ) {
      return oldSnapshot.docs[0];
    }
  }

  // ----------------------------------------------------------
  // 3. Virtual account ID
  // ----------------------------------------------------------

  if (virtualAccountId) {
    const snapshot =
      await db
        .collection("users")
        .where(
          "kentPayAccount.providerAccountId",
          "==",
          virtualAccountId
        )
        .limit(1)
        .get();

    if (
      !snapshot.empty
    ) {
      return snapshot.docs[0];
    }
  }

  return null;
}


// ============================================================
// EXTRACT ACCOUNT NUMBER
// ============================================================

function extractAccountNumber(
  payload
) {
  const data =
    payload &&
    payload.data
      ? payload.data
      : {};

  const meta =
    payload &&
    payload.meta
      ? payload.meta
      : {};

  const candidates = [
    data.account_number,

    data.accountNumber,

    data.virtual_account_number,

    data.virtualAccountNumber,

    data.bank_account_number,

    data.bankAccountNumber,

    data.account,

    data.virtual_account &&
      data.virtual_account.account_number,

    data.virtualAccount &&
      data.virtualAccount.accountNumber,

    data.meta &&
      data.meta.account_number,

    data.meta &&
      data.meta.accountNumber,

    meta.account_number,

    meta.accountNumber,

    meta.virtual_account_number,

    meta.virtualAccountNumber,
  ];

  for (
    const candidate of candidates
  ) {
    const normalized =
      normalizeAccountNumber(
        candidate
      );

    if (normalized) {
      return normalized;
    }
  }

  return null;
}


// ============================================================
// EXTRACT CUSTOMER ID
// ============================================================

function extractCustomerId(
  payload
) {
  const data =
    payload &&
    payload.data
      ? payload.data
      : {};

  const customer =
    data.customer || {};

  const candidates = [
    data.customer_id,

    data.customerId,

    customer.id,

    customer.customer_id,

    customer.customerId,

    data.meta &&
      data.meta.customer_id,

    data.meta &&
      data.meta.customerId,
  ];

  for (
    const candidate of candidates
  ) {
    if (
      candidate !== null &&
      candidate !== undefined &&
      String(candidate).trim() !== ""
    ) {
      return String(candidate);
    }
  }

  return null;
}


// ============================================================
// EXTRACT VIRTUAL ACCOUNT ID
// ============================================================

function extractVirtualAccountId(
  payload
) {
  const data =
    payload &&
    payload.data
      ? payload.data
      : {};

  const candidates = [
    data.virtual_account_id,

    data.virtualAccountId,

    data.account_id,

    data.accountId,

    data.virtual_account &&
      data.virtual_account.id,

    data.virtualAccount &&
      data.virtualAccount.id,
  ];

  for (
    const candidate of candidates
  ) {
    if (
      candidate !== null &&
      candidate !== undefined &&
      String(candidate).trim() !== ""
    ) {
      return String(candidate);
    }
  }

  return null;
}


// ============================================================
// EXTRACT TRANSACTION REFERENCE
// ============================================================

function extractTransactionReference(
  payload,
  verifiedCharge
) {
  const data =
    payload &&
    payload.data
      ? payload.data
      : {};

  const candidates = [
    data.tx_ref,

    data.txRef,

    data.reference,

    data.transaction_reference,

    data.transactionReference,

    verifiedCharge &&
      verifiedCharge.tx_ref,

    verifiedCharge &&
      verifiedCharge.txRef,

    verifiedCharge &&
      verifiedCharge.reference,

    verifiedCharge &&
      verifiedCharge.transaction_reference,

    verifiedCharge &&
      verifiedCharge.transactionReference,
  ];

  for (
    const candidate of candidates
  ) {
    if (
      candidate !== null &&
      candidate !== undefined &&
      String(candidate).trim() !== ""
    ) {
      return String(candidate);
    }
  }

  return null;
}


// ============================================================
// EXTRACT CHARGE ID
// ============================================================

function extractChargeId(
  payload
) {
  const data =
    payload &&
    payload.data
      ? payload.data
      : {};

  const candidates = [
    data.id,

    data.charge_id,

    data.chargeId,
  ];

  for (
    const candidate of candidates
  ) {
    if (
      candidate !== null &&
      candidate !== undefined &&
      String(candidate).trim() !== ""
    ) {
      return String(candidate);
    }
  }

  return null;
}


// ============================================================
// EXTRACT STATUS
// ============================================================

function extractStatus(
  payload,
  verifiedCharge
) {
  const data =
    payload &&
    payload.data
      ? payload.data
      : {};

  const status =
    verifiedCharge &&
    verifiedCharge.status
      ? verifiedCharge.status
      : data.status;

  if (
    status === null ||
    status === undefined
  ) {
    return null;
  }

  return String(status)
    .trim()
    .toLowerCase();
}


// ============================================================
// EXTRACT AMOUNT
// ============================================================

function extractAmount(
  payload,
  verifiedCharge
) {
  const data =
    payload &&
    payload.data
      ? payload.data
      : {};

  const candidate =
    verifiedCharge &&
    verifiedCharge.amount !== undefined
      ? verifiedCharge.amount
      : data.amount;

  const amount =
    Number(candidate);

  if (
    !Number.isFinite(amount)
  ) {
    return null;
  }

  return amount;
}


// ============================================================
// EXTRACT CURRENCY
// ============================================================

function extractCurrency(
  payload,
  verifiedCharge
) {
  const data =
    payload &&
    payload.data
      ? payload.data
      : {};

  const candidate =
    verifiedCharge &&
    verifiedCharge.currency
      ? verifiedCharge.currency
      : data.currency;

  if (
    candidate === null ||
    candidate === undefined
  ) {
    return null;
  }

  return String(candidate)
    .trim()
    .toUpperCase();
}


// ============================================================
// WEBHOOK CONTROLLER
// ============================================================

async function handleFlutterwaveWebhook(
  req,
  res
) {
  console.log(
    "=================================================="
  );

  console.log(
    "FLUTTERWAVE WEBHOOK HTTP REQUEST RECEIVED"
  );

  console.log(
    "Time:",
    new Date().toISOString()
  );

  console.log(
    "Method:",
    req.method
  );

  console.log(
    "URL:",
    req.originalUrl
  );

  console.log(
    "=================================================="
  );

  try {
    // --------------------------------------------------------
    // WEBHOOK DIAGNOSTICS
    // --------------------------------------------------------

    console.log(
      "WEBHOOK DIAGNOSTICS"
    );

    console.log(
      "rawBody exists:",
      typeof req.rawBody === "string"
    );

    console.log(
      "rawBody length:",
      typeof req.rawBody === "string"
        ? req.rawBody.length
        : 0
    );

    console.log(
      "flutterwave-signature exists:",
      Boolean(
        req.headers[
          "flutterwave-signature"
        ]
      )
    );

    console.log(
      "FLW_WEBHOOK_SECRET_HASH exists:",
      Boolean(
        process.env.FLW_WEBHOOK_SECRET_HASH
      )
    );

    console.log(
      "FLW_BASE_URL:",
      FLW_BASE_URL
    );

    // --------------------------------------------------------
    // SIGNATURE
    // --------------------------------------------------------

    const signatureValid =
      verifyFlutterwaveSignature(
        req
      );

    console.log(
      "WEBHOOK SIGNATURE RESULT:",
      signatureValid
        ? "VALID"
        : "INVALID"
    );

    if (!signatureValid) {
      console.error(
        "FLUTTERWAVE WEBHOOK REJECTED: INVALID SIGNATURE"
      );

      return res.status(401).json({
        success: false,
        message:
          "Invalid Flutterwave webhook signature.",
      });
    }

    // --------------------------------------------------------
    // PAYLOAD
    // --------------------------------------------------------

    const payload =
      req.body || {};

    console.log(
      "FLUTTERWAVE WEBHOOK RECEIVED"
    );

    console.log(
      safeJson({
        event:
          payload.event,
        type:
          payload.type,
        id:
          payload.id,
        dataId:
          payload.data &&
          payload.data.id,
        status:
          payload.data &&
          payload.data.status,
      })
    );

    // --------------------------------------------------------
    // EVENT TYPE
    // --------------------------------------------------------

    const eventType =
      String(
        payload.type ||
        payload.event ||
        ""
      )
        .trim()
        .toLowerCase();

    console.log(
      "FLUTTERWAVE EVENT TYPE:",
      eventType
    );

    // --------------------------------------------------------
    // ONLY PROCESS CHARGE.COMPLETED
    // --------------------------------------------------------

    if (
      eventType !==
      "charge.completed"
    ) {
      console.log(
        "Ignoring unsupported Flutterwave event:",
        eventType
      );

      return res.status(200).json({
        success: true,
        message:
          "Event received but not processed.",
      });
    }

    // --------------------------------------------------------
    // CHARGE ID
    // --------------------------------------------------------

    const chargeId =
      extractChargeId(
        payload
      );

    if (!chargeId) {
      console.error(
        "FLUTTERWAVE WEBHOOK ERROR: Charge ID is missing."
      );

      return res.status(400).json({
        success: false,
        message:
          "Charge ID is missing.",
      });
    }

    // --------------------------------------------------------
    // VERIFY CHARGE
    // --------------------------------------------------------

    const verifiedCharge =
      await verifyFlutterwaveCharge(
        chargeId
      );

    // --------------------------------------------------------
    // PAYMENT STATUS
    // --------------------------------------------------------

    const status =
      extractStatus(
        payload,
        verifiedCharge
      );

    console.log(
      "VERIFIED PAYMENT STATUS:",
      status
    );

    if (
      status !== "successful" &&
      status !== "succeeded"
    ) {
      console.log(
        "Ignoring unsuccessful Flutterwave charge."
      );

      return res.status(200).json({
        success: true,
        message:
          "Charge received but payment was not successful.",
      });
    }

    // --------------------------------------------------------
    // AMOUNT
    // --------------------------------------------------------

    const amount =
      extractAmount(
        payload,
        verifiedCharge
      );

    console.log(
      "VERIFIED PAYMENT AMOUNT:",
      amount
    );

    if (
      amount === null ||
      amount <= 0
    ) {
      console.error(
        "FLUTTERWAVE WEBHOOK ERROR: Invalid payment amount."
      );

      return res.status(400).json({
        success: false,
        message:
          "Invalid payment amount.",
      });
    }

    // --------------------------------------------------------
    // CURRENCY
    // --------------------------------------------------------

    const currency =
      extractCurrency(
        payload,
        verifiedCharge
      );

    console.log(
      "VERIFIED PAYMENT CURRENCY:",
      currency
    );

    if (
      currency !== "NGN"
    ) {
      console.error(
        "FLUTTERWAVE WEBHOOK ERROR: Unsupported currency:",
        currency
      );

      return res.status(400).json({
        success: false,
        message:
          "Unsupported payment currency.",
      });
    }

    // --------------------------------------------------------
    // IDENTIFIERS
    // --------------------------------------------------------

    const accountNumber =
      extractAccountNumber(
        payload
      );

    const customerId =
      extractCustomerId(
        payload
      );

    const virtualAccountId =
      extractVirtualAccountId(
        payload
      );

    const transactionReference =
      extractTransactionReference(
        payload,
        verifiedCharge
      );

    console.log(
      "=================================================="
    );

    console.log(
      "KENT PAYMENT IDENTIFIERS"
    );

    console.log(
      "Account Number:",
      accountNumber ||
        "none"
    );

    console.log(
      "Customer ID:",
      customerId ||
        "none"
    );

    console.log(
      "Virtual Account ID:",
      virtualAccountId ||
        "none"
    );

    console.log(
      "Transaction Reference:",
      transactionReference ||
        "none"
    );

    console.log(
      "Charge ID:",
      chargeId
    );

    console.log(
      "=================================================="
    );

    // --------------------------------------------------------
    // FIND USER
    // --------------------------------------------------------

    const userDoc =
      await findUserByPayment({
        accountNumber,
        customerId,
        virtualAccountId,
      });

    if (!userDoc) {
      console.error(
        "KENT USER NOT FOUND FOR FLUTTERWAVE PAYMENT."
      );

      return res.status(404).json({
        success: false,
        message:
          "KENT user could not be matched to this payment.",
      });
    }

    const uid =
      userDoc.id;

    console.log(
      "KENT USER FOUND:",
      uid
    );

    const userRef =
      db
        .collection("users")
        .doc(uid);

    // --------------------------------------------------------
    // IDEMPOTENCY
    // --------------------------------------------------------
    //
    // One Flutterwave charge must only fund the wallet once.
    //
    // We use the Flutterwave charge ID as the unique
    // wallet transaction document ID.
    // --------------------------------------------------------

    const walletTransactionRef =
      userRef
        .collection(
          "walletTransactions"
        )
        .doc(chargeId);

    // --------------------------------------------------------
    // FIRESTORE TRANSACTION
    // --------------------------------------------------------

    let alreadyProcessed =
      false;

    await db.runTransaction(
      async (
        transaction
      ) => {
        const userSnapshot =
          await transaction.get(
            userRef
          );

        if (
          !userSnapshot.exists
        ) {
          throw new Error(
            "KENT user document no longer exists."
          );
        }

        const transactionSnapshot =
          await transaction.get(
            walletTransactionRef
          );

        // ----------------------------------------------------
        // DUPLICATE WEBHOOK
        // ----------------------------------------------------

        if (
          transactionSnapshot.exists
        ) {
          alreadyProcessed =
            true;

          return;
        }

        const userData =
          userSnapshot.data() || {};

        // ----------------------------------------------------
        // IMPORTANT:
        //
        // walletBalance is the correct KENT field.
        //
        // If it does not exist yet, use 0.
        //
        // DO NOT use "balance".
        // DO NOT overwrite an existing wallet balance.
        // ----------------------------------------------------

        const currentBalance =
          Number(
            userData.walletBalance
          );

        const safeCurrentBalance =
          Number.isFinite(
            currentBalance
          )
            ? currentBalance
            : 0;

        const newBalance =
          safeCurrentBalance +
          amount;

        console.log(
          "KENT WALLET BALANCE CALCULATION"
        );

        console.log(
          "Previous walletBalance:",
          safeCurrentBalance
        );

        console.log(
          "Incoming amount:",
          amount
        );

        console.log(
          "New walletBalance:",
          newBalance
        );

        // ----------------------------------------------------
        // UPDATE USER WALLET
        // ----------------------------------------------------

        transaction.set(
          userRef,
          {
            walletBalance:
              newBalance,

            walletLastFundedAt:
              new Date(),

            walletLastFundingAmount:
              amount,

            walletLastFundingCurrency:
              currency,

            walletLastFundingReference:
              transactionReference ||
              chargeId,
          },
          {
            merge: true,
          }
        );

        // ----------------------------------------------------
        // RECORD TRANSACTION
        // ----------------------------------------------------

        transaction.set(
          walletTransactionRef,
          {
            type:
              "wallet_funding",

            direction:
              "credit",

            status:
              "successful",

            amount:
              amount,

            currency:
              currency,

            provider:
              "flutterwave",

            providerTransactionId:
              chargeId,

            flutterwaveChargeId:
              chargeId,

            reference:
              transactionReference ||
              chargeId,

            accountNumber:
              accountNumber,

            customerId:
              customerId,

            virtualAccountId:
              virtualAccountId,

            source:
              "flutterwave_webhook",

            createdAt:
              new Date(),

            processedAt:
              new Date(),
          },
          {
            merge: false,
          }
        );
      }
    );

    // --------------------------------------------------------
    // DUPLICATE RESPONSE
    // --------------------------------------------------------

    if (
      alreadyProcessed
    ) {
      console.log(
        "FLUTTERWAVE WEBHOOK ALREADY PROCESSED:",
        chargeId
      );

      return res.status(200).json({
        success: true,

        message:
          "Flutterwave payment was already processed.",

        chargeId,
      });
    }

    // --------------------------------------------------------
    // SUCCESS
    // --------------------------------------------------------

    console.log(
      "=================================================="
    );

    console.log(
      "KENT WALLET FUNDED SUCCESSFULLY"
    );

    console.log(
      "User:",
      uid
    );

    console.log(
      "Amount:",
      amount,
      currency
    );

    console.log(
      "Reference:",
      transactionReference ||
        chargeId
    );

    console.log(
      "=================================================="
    );

    return res.status(200).json({
      success: true,

      message:
        "Flutterwave payment processed successfully.",

      chargeId,

      reference:
        transactionReference ||
        chargeId,

      amount,

      currency,
    });
  } catch (error) {
    console.error(
      "=================================================="
    );

    console.error(
      "FLUTTERWAVE WEBHOOK PROCESSING ERROR"
    );

    console.error(
      error
    );

    console.error(
      "Message:",
      error.message
    );

    console.error(
      "Stack:",
      error.stack
    );

    console.error(
      "=================================================="
    );

    if (
      res.headersSent
    ) {
      return;
    }

    return res.status(500).json({
      success: false,

      message:
        "Flutterwave webhook processing failed.",
    });
  }
}


// ============================================================
// EXPORT
// ============================================================

module.exports = {
  handleFlutterwaveWebhook,
};
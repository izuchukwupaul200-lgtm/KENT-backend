```js
const crypto = require("crypto");

const { db } = require("../../firebaseAdmin");

const {
  getFlutterwaveAccessToken,
} = require("../services/flutterwave");

// ============================================================
// FLUTTERWAVE WEBHOOK CONTROLLER
// ============================================================
//
// POST /api/flutterwave/webhook
//
// Handles Flutterwave V4 charge.completed webhooks for KENT
// static virtual-account bank-transfer deposits.
//
// Flow:
//
// Flutterwave bank transfer
//        ↓
// charge.completed webhook
//        ↓
// verify signature
//        ↓
// verify charge with Flutterwave
//        ↓
// identify KENT user
//        ↓
// atomically increase walletBalance
//        ↓
// record wallet transaction
//
// ============================================================


// ============================================================
// SIGNATURE VERIFICATION
// ============================================================

function isValidFlutterwaveSignature(
  rawBody,
  signature,
  secretHash
) {
  if (
    !rawBody ||
    !signature ||
    !secretHash
  ) {
    return false;
  }

  const expectedSignature =
    crypto
      .createHmac(
        "sha256",
        secretHash
      )
      .update(rawBody)
      .digest("base64");

  const received =
    String(signature).trim();

  const expected =
    String(expectedSignature).trim();

  if (
    received.length !==
    expected.length
  ) {
    return false;
  }

  return crypto.timingSafeEqual(
    Buffer.from(received, "utf8"),
    Buffer.from(expected, "utf8")
  );
}


// ============================================================
// VERIFY CHARGE WITH FLUTTERWAVE
// ============================================================

async function getFlutterwaveCharge(
  chargeId
) {
  if (!chargeId) {
    throw new Error(
      "Flutterwave charge ID is required."
    );
  }

  const accessToken =
    await getFlutterwaveAccessToken();

  const baseUrl =
    (
      process.env.FLW_BASE_URL ||
      "https://f4bexperience.flutterwave.com"
    ).replace(/\/+$/, "");

  const response =
    await fetch(
      `${baseUrl}/charges/${encodeURIComponent(
        String(chargeId)
      )}`,
      {
        method: "GET",

        headers: {
          Accept:
            "application/json",

          Authorization:
            `Bearer ${accessToken}`,
        },
      }
    );

  const responseText =
    await response.text();

  let responseData = {};

  try {
    responseData =
      responseText
        ? JSON.parse(responseText)
        : {};
  } catch {
    responseData = {
      raw: responseText,
    };
  }

  if (!response.ok) {
    console.error(
      "FLUTTERWAVE CHARGE LOOKUP FAILED:",
      {
        status:
          response.status,

        response:
          responseData,
      }
    );

    throw new Error(
      `Flutterwave charge verification failed with HTTP ${response.status}.`
    );
  }

  return (
    responseData?.data ||
    null
  );
}


// ============================================================
// NORMALIZE ACCOUNT NUMBER
// ============================================================

function normalizeAccountNumber(
  value
) {
  if (
    value === undefined ||
    value === null
  ) {
    return null;
  }

  const normalized =
    String(value)
      .replace(/\s+/g, "")
      .trim();

  if (
    !/^\d{10}$/.test(
      normalized
    )
  ) {
    return null;
  }

  return normalized;
}


// ============================================================
// FIND USER BY KENT VIRTUAL ACCOUNT NUMBER
// ============================================================

async function findUserByAccountNumber(
  accountNumber
) {
  const normalized =
    normalizeAccountNumber(
      accountNumber
    );

  if (!normalized) {
    return null;
  }

  const snapshot =
    await db
      .collection("users")
      .where(
        "kentPayAccount.accountNumber",
        "==",
        normalized
      )
      .limit(1)
      .get();

  if (
    snapshot.empty
  ) {
    return null;
  }

  const doc =
    snapshot.docs[0];

  return {
    uid:
      doc.id,

    ref:
      doc.ref,

    data:
      doc.data() || {},
  };
}


// ============================================================
// FIND USER BY FLUTTERWAVE CUSTOMER ID
// ============================================================

async function findUserByFlutterwaveCustomerId(
  customerId
) {
  if (
    customerId === undefined ||
    customerId === null
  ) {
    return null;
  }

  const normalized =
    String(customerId).trim();

  if (!normalized) {
    return null;
  }

  // Current KENT field
  let snapshot =
    await db
      .collection("users")
      .where(
        "kentPayAccount.providerCustomerId",
        "==",
        normalized
      )
      .limit(1)
      .get();

  if (
    !snapshot.empty
  ) {
    const doc =
      snapshot.docs[0];

    return {
      uid:
        doc.id,

      ref:
        doc.ref,

      data:
        doc.data() || {},
    };
  }

  // Top-level fallback
  snapshot =
    await db
      .collection("users")
      .where(
        "kentPayFlutterwaveCustomerId",
        "==",
        normalized
      )
      .limit(1)
      .get();

  if (
    !snapshot.empty
  ) {
    const doc =
      snapshot.docs[0];

    return {
      uid:
        doc.id,

      ref:
        doc.ref,

      data:
        doc.data() || {},
    };
  }

  // Legacy fallback
  snapshot =
    await db
      .collection("users")
      .where(
        "kentPayAccount.customerId",
        "==",
        normalized
      )
      .limit(1)
      .get();

  if (
    !snapshot.empty
  ) {
    const doc =
      snapshot.docs[0];

    return {
      uid:
        doc.id,

      ref:
        doc.ref,

      data:
        doc.data() || {},
    };
  }

  return null;
}


// ============================================================
// FIND USER BY FLUTTERWAVE VIRTUAL ACCOUNT ID
// ============================================================

async function findUserByVirtualAccountId(
  virtualAccountId
) {
  if (
    virtualAccountId === undefined ||
    virtualAccountId === null
  ) {
    return null;
  }

  const normalized =
    String(virtualAccountId).trim();

  if (!normalized) {
    return null;
  }

  const snapshot =
    await db
      .collection("users")
      .where(
        "kentPayAccount.providerAccountId",
        "==",
        normalized
      )
      .limit(1)
      .get();

  if (
    snapshot.empty
  ) {
    return null;
  }

  const doc =
    snapshot.docs[0];

  return {
    uid:
      doc.id,

    ref:
      doc.ref,

    data:
      doc.data() || {},
  };
}


// ============================================================
// EXTRACT VIRTUAL ACCOUNT NUMBER
// ============================================================
//
// Flutterwave's virtual-account bank-transfer webhook can
// provide the account number inside meta_data.
//
// Example:
//
// meta_data.virtualaccountnumber
//
// ============================================================

function extractAccountNumber(
  payload,
  charge
) {
  const candidates = [
    // Flutterwave V3-style virtual account webhook
    payload?.meta_data?.virtualaccountnumber,

    payload?.meta_data?.virtual_account_number,

    payload?.meta_data?.account_number,

    // Other possible payload locations
    payload?.data?.account_number,

    payload?.data?.virtual_account_number,

    payload?.data?.account?.account_number,

    payload?.data?.payment_entity?.account_number,

    payload?.data?.meta_data?.account_number,

    payload?.data?.meta_data
      ?.virtual_account_number,

    // Charge response
    charge?.account_number,

    charge?.virtual_account_number,

    charge?.payment_method
      ?.bank_transfer
      ?.account_number,

    charge?.payment_method_details
      ?.bank_transfer
      ?.account_number,
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
  payload,
  charge
) {
  return (
    payload?.data?.customer?.id ||

    payload?.data?.customer_id ||

    payload?.data?.payment_method
      ?.customer_id ||

    charge?.customer?.id ||

    charge?.customer_id ||

    charge?.payment_method
      ?.customer_id ||

    null
  );
}


// ============================================================
// EXTRACT VIRTUAL ACCOUNT ID
// ============================================================

function extractVirtualAccountId(
  payload,
  charge
) {
  return (
    payload?.data?.virtual_account_id ||

    payload?.data?.virtualAccountId ||

    payload?.data?.account_id ||

    payload?.data?.virtual_account
      ?.id ||

    charge?.virtual_account_id ||

    charge?.virtualAccountId ||

    charge?.account_id ||

    null
  );
}


// ============================================================
// EXTRACT TRANSACTION REFERENCE
// ============================================================

function extractTransactionReference(
  payload,
  charge
) {
  return (
    payload?.data?.reference ||

    payload?.data?.tx_ref ||

    payload?.data?.flw_ref ||

    charge?.reference ||

    charge?.tx_ref ||

    charge?.flw_ref ||

    null
  );
}


// ============================================================
// EXTRACT EVENT TYPE
// ============================================================

function extractEventType(
  payload
) {
  return (
    payload?.type ||

    payload?.event ||

    payload?.["event.type"] ||

    ""
  );
}


// ============================================================
// WEBHOOK HANDLER
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
    "=================================================="
  );

  try {
    // ----------------------------------------------------------
    // ENVIRONMENT CHECK
    // ----------------------------------------------------------

    const secretHash =
      process.env.FLW_WEBHOOK_SECRET_HASH ||
      process.env.FLW_SECRET_HASH ||
      "";

    const signature =
      req.headers[
        "flutterwave-signature"
      ];

    console.log(
      "WEBHOOK DIAGNOSTICS:",
      {
        hasSecretHash:
          Boolean(secretHash),

        hasSignature:
          Boolean(signature),

        hasRawBody:
          Boolean(req.rawBody),

        contentType:
          req.headers[
            "content-type"
          ],

        userAgent:
          req.headers[
            "user-agent"
          ],
      }
    );

    // ----------------------------------------------------------
    // SECRET CHECK
    // ----------------------------------------------------------

    if (!secretHash) {
      console.error(
        "FLUTTERWAVE WEBHOOK ERROR: SECRET HASH IS NOT CONFIGURED."
      );

      return res.status(500).json({
        success: false,

        message:
          "Webhook configuration error.",
      });
    }

    // ----------------------------------------------------------
    // SIGNATURE CHECK
    // ----------------------------------------------------------

    const rawBody =
      req.rawBody ||
      JSON.stringify(
        req.body || {}
      );

    const validSignature =
      isValidFlutterwaveSignature(
        rawBody,
        signature,
        secretHash
      );

    console.log(
      "WEBHOOK SIGNATURE RESULT:",
      validSignature
        ? "VALID"
        : "INVALID"
    );

    if (!validSignature) {
      console.warn(
        "FLUTTERWAVE WEBHOOK REJECTED: INVALID SIGNATURE"
      );

      return res.status(401).json({
        success: false,

        message:
          "Invalid webhook signature.",
      });
    }

    // ----------------------------------------------------------
    // PAYLOAD
    // ----------------------------------------------------------

    const payload =
      req.body || {};

    const eventType =
      extractEventType(
        payload
      );

    console.log(
      "FLUTTERWAVE WEBHOOK RECEIVED:",
      {
        eventType,

        webhookId:
          payload.id ||
          payload.webhook_id ||
          null,
      }
    );

    // ----------------------------------------------------------
    // SAFE DEBUG INFORMATION
    // ----------------------------------------------------------
    //
    // We deliberately do NOT print the secret hash.
    //
    // This gives us enough information to understand exactly
    // what Flutterwave sent.
    //
    // ----------------------------------------------------------

    console.log(
      "FLUTTERWAVE WEBHOOK PAYMENT INFO:",
      {
        eventType,

        chargeId:
          payload?.data?.id ||
          null,

        amount:
          payload?.data?.amount ||
          null,

        currency:
          payload?.data?.currency ||
          null,

        status:
          payload?.data?.status ||
          null,

        paymentType:
          payload?.data?.payment_type ||
          payload?.data?.payment_method
            ?.type ||
          null,

        customerId:
          payload?.data?.customer?.id ||
          null,

        reference:
          payload?.data?.reference ||
          payload?.data?.tx_ref ||
          null,

        virtualAccountNumber:
          payload?.meta_data
            ?.virtualaccountnumber ||
          payload?.meta_data
            ?.virtual_account_number ||
          null,

        originatorAmount:
          payload?.meta_data
            ?.originatoramount ||
          null,

        originatorName:
          payload?.meta_data
            ?.originatorname ||
          null,

        eventTypeMeta:
          payload?.["event.type"] ||
          null,
      }
    );

    // ----------------------------------------------------------
    // ONLY PROCESS PAYMENT WEBHOOK
    // ----------------------------------------------------------

    if (
      eventType !==
      "charge.completed"
    ) {
      console.log(
        "FLUTTERWAVE WEBHOOK IGNORED:",
        {
          eventType,
        }
      );

      return res.status(200).json({
        success: true,

        ignored: true,

        message:
          "Flutterwave event acknowledged.",
      });
    }

    // ----------------------------------------------------------
    // WEBHOOK DATA
    // ----------------------------------------------------------

    const webhookData =
      payload.data || {};

    const chargeId =
      webhookData.id;

    if (!chargeId) {
      console.error(
        "FLUTTERWAVE WEBHOOK ERROR: CHARGE ID MISSING."
      );

      return res.status(400).json({
        success: false,

        message:
          "Charge ID is missing.",
      });
    }

    // ----------------------------------------------------------
    // VERIFY CHARGE
    // ----------------------------------------------------------

    console.log(
      "VERIFYING FLUTTERWAVE CHARGE:",
      String(chargeId)
    );

    const charge =
      await getFlutterwaveCharge(
        chargeId
      );

    if (!charge) {
      console.error(
        "FLUTTERWAVE WEBHOOK ERROR: CHARGE VERIFICATION RETURNED NO DATA."
      );

      return res.status(400).json({
        success: false,

        message:
          "Unable to verify charge.",
      });
    }

    console.log(
      "FLUTTERWAVE CHARGE VERIFIED:",
      {
        chargeId:
          String(chargeId),

        status:
          charge.status,

        amount:
          charge.amount,

        currency:
          charge.currency,

        customerId:
          charge.customer?.id ||
          null,

        reference:
          charge.reference ||
          null,

        paymentType:
          charge.payment_method
            ?.type ||
          charge.payment_type ||
          null,
      }
    );

    // ----------------------------------------------------------
    // STATUS
    // ----------------------------------------------------------

    const chargeStatus =
      String(
        charge.status ||
        webhookData.status ||
        ""
      )
        .trim()
        .toLowerCase();

    if (
      chargeStatus !==
        "succeeded" &&
      chargeStatus !==
        "successful"
    ) {
      console.log(
        "FLUTTERWAVE CHARGE NOT SUCCESSFUL:",
        {
          chargeId:
            String(chargeId),

          status:
            chargeStatus,
        }
      );

      return res.status(200).json({
        success: true,

        ignored: true,

        message:
          "Charge is not successful.",
      });
    }

    // ----------------------------------------------------------
    // CURRENCY
    // ----------------------------------------------------------

    const currency =
      String(
        charge.currency ||
        webhookData.currency ||
        ""
      )
        .trim()
        .toUpperCase();

    if (
      currency !==
      "NGN"
    ) {
      console.warn(
        "FLUTTERWAVE WEBHOOK: UNSUPPORTED CURRENCY:",
        currency
      );

      return res.status(200).json({
        success: true,

        ignored: true,

        message:
          "Only NGN wallet funding is supported.",
      });
    }

    // ----------------------------------------------------------
    // AMOUNT
    // ----------------------------------------------------------

    const amount =
      Number(
        charge.amount ??
        webhookData.amount
      );

    if (
      !Number.isFinite(
        amount
      ) ||
      amount <= 0
    ) {
      console.error(
        "FLUTTERWAVE WEBHOOK: INVALID AMOUNT:",
        amount
      );

      return res.status(400).json({
        success: false,

        message:
          "Invalid transaction amount.",
      });
    }

    // ----------------------------------------------------------
    // IDENTIFIERS
    // ----------------------------------------------------------

    const accountNumber =
      extractAccountNumber(
        payload,
        charge
      );

    const customerId =
      extractCustomerId(
        payload,
        charge
      );

    const virtualAccountId =
      extractVirtualAccountId(
        payload,
        charge
      );

    const transactionReference =
      extractTransactionReference(
        payload,
        charge
      );

    console.log(
      "KENT PAYMENT IDENTIFIERS:",
      {
        accountNumber,

        customerId,

        virtualAccountId,

        transactionReference,
      }
    );

    // ----------------------------------------------------------
    // FIND USER
    // ----------------------------------------------------------

    let user = null;

    // 1. Virtual account number
    if (
      accountNumber
    ) {
      console.log(
        "KENT USER LOOKUP: BY VIRTUAL ACCOUNT NUMBER",
        accountNumber
      );

      user =
        await findUserByAccountNumber(
          accountNumber
        );
    }

    // 2. Customer ID
    if (
      !user &&
      customerId
    ) {
      console.log(
        "KENT USER LOOKUP: BY FLUTTERWAVE CUSTOMER ID",
        customerId
      );

      user =
        await findUserByFlutterwaveCustomerId(
          customerId
        );
    }

    // 3. Virtual account ID
    if (
      !user &&
      virtualAccountId
    ) {
      console.log(
        "KENT USER LOOKUP: BY VIRTUAL ACCOUNT ID",
        virtualAccountId
      );

      user =
        await findUserByVirtualAccountId(
          virtualAccountId
        );
    }

    // ----------------------------------------------------------
    // USER NOT FOUND
    // ----------------------------------------------------------

    if (!user) {
      console.error(
        "=================================================="
      );

      console.error(
        "KENT USER NOT FOUND FOR FLUTTERWAVE PAYMENT"
      );

      console.error(
        "=================================================="
      );

      console.error(
        "Charge ID:",
        chargeId
      );

      console.error(
        "Account Number:",
        accountNumber
      );

      console.error(
        "Customer ID:",
        customerId
      );

      console.error(
        "Virtual Account ID:",
        virtualAccountId
      );

      console.error(
        "Reference:",
        transactionReference
      );

      console.error(
        "Amount:",
        amount,
        currency
      );

      console.error(
        "=================================================="
      );

      return res.status(200).json({
        success: true,

        processed: false,

        message:
          "Payment received but KENT account could not be identified.",
      });
    }

    // ----------------------------------------------------------
    // USER FOUND
    // ----------------------------------------------------------

    console.log(
      "KENT USER FOUND:",
      {
        uid:
          user.uid,

        accountNumber:
          user.data
            ?.kentPayAccount
            ?.accountNumber ||
          null,
      }
    );

    const userRef =
      user.ref;

    // ----------------------------------------------------------
    // IDEMPOTENCY
    // ----------------------------------------------------------

    const transactionId =
      String(
        chargeId
      );

    const transactionRef =
      db
        .collection("users")
        .doc(user.uid)
        .collection(
          "walletTransactions"
        )
        .doc(transactionId);

    // ----------------------------------------------------------
    // FIRESTORE TRANSACTION
    // ----------------------------------------------------------

    const result =
      await db.runTransaction(
        async (
          transaction
        ) => {
          const existing =
            await transaction.get(
              transactionRef
            );

          if (
            existing.exists
          ) {
            return {
              alreadyProcessed:
                true,

              walletBalance:
                existing.data()
                  ?.walletBalanceAfter ??
                null,
            };
          }

          const userSnapshot =
            await transaction.get(
              userRef
            );

          if (
            !userSnapshot.exists
          ) {
            throw new Error(
              "KENT user account does not exist."
            );
          }

          const userData =
            userSnapshot.data() ||
            {};

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

          // ----------------------------------------------------
          // UPDATE WALLET
          // ----------------------------------------------------

          transaction.update(
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
                transactionId,
            }
          );

          // ----------------------------------------------------
          // RECORD TRANSACTION
          // ----------------------------------------------------

          transaction.set(
            transactionRef,
            {
              type:
                "wallet_funding",

              direction:
                "credit",

              status:
                "successful",

              amount,

              currency,

              walletBalanceBefore:
                safeCurrentBalance,

              walletBalanceAfter:
                newBalance,

              flutterwaveChargeId:
                transactionId,

              flutterwaveReference:
                transactionReference ||
                null,

              flutterwaveCustomerId:
                customerId
                  ? String(
                      customerId
                    )
                  : null,

              flutterwaveVirtualAccountId:
                virtualAccountId
                  ? String(
                      virtualAccountId
                    )
                  : null,

              virtualAccountNumber:
                accountNumber ||
                null,

              provider:
                "flutterwave",

              createdAt:
                new Date(),
            }
          );

          return {
            alreadyProcessed:
              false,

            walletBalance:
              newBalance,
          };
        }
      );

    // ----------------------------------------------------------
    // DUPLICATE
    // ----------------------------------------------------------

    if (
      result.alreadyProcessed
    ) {
      console.log(
        "FLUTTERWAVE WEBHOOK: TRANSACTION ALREADY PROCESSED.",
        {
          uid:
            user.uid,

          chargeId:
            transactionId,

          walletBalance:
            result.walletBalance,
        }
      );

      return res.status(200).json({
        success: true,

        processed: false,

        alreadyProcessed:
          true,

        walletBalance:
          result.walletBalance,
      });
    }

    // ----------------------------------------------------------
    // SUCCESS
    // ----------------------------------------------------------

    console.log(
      "=================================================="
    );

    console.log(
      "KENT WALLET FUNDED SUCCESSFULLY"
    );

    console.log(
      "=================================================="
    );

    console.log(
      "UID:",
      user.uid
    );

    console.log(
      "Amount:",
      amount,
      currency
    );

    console.log(
      "Flutterwave Charge:",
      transactionId
    );

    console.log(
      "Flutterwave Customer:",
      customerId
    );

    console.log(
      "Virtual Account:",
      accountNumber
    );

    console.log(
      "Reference:",
      transactionReference
    );

    console.log(
      "New Wallet Balance:",
      result.walletBalance
    );

    console.log(
      "=================================================="
    );

    return res.status(200).json({
      success: true,

      processed: true,

      amount,

      currency,

      walletBalance:
        result.walletBalance,
    });
  } catch (error) {
    console.error(
      "=================================================="
    );

    console.error(
      "FLUTTERWAVE WEBHOOK ERROR"
    );

    console.error(
      "=================================================="
    );

    console.error(
      "Message:",
      error?.message ||
        "Unknown error"
    );

    console.error(
      "Name:",
      error?.name ||
        null
    );

    console.error(
      "Stack:",
      error?.stack ||
        null
    );

    console.error(
      "=================================================="
    );

    return res.status(500).json({
      success: false,

      message:
        "Unable to process Flutterwave webhook.",
    });
  }
}


// ============================================================
// EXPORT
// ============================================================

module.exports = {
  handleFlutterwaveWebhook,
};
```

### Then do these 4 things

1. Replace the entire contents of:
   `src/controllers/flutterwaveWebhookController.js`

2. Save it.

3. Deploy the backend to Render.

4. **Do not make another payment.** After deployment, use Flutterwave's **resend webhook** on the existing successful ₦200 transaction again.

Then go to Render Logs.

This time we should see something like:

```text
FLUTTERWAVE WEBHOOK HTTP REQUEST RECEIVED
WEBHOOK DIAGNOSTICS: ...
WEBHOOK SIGNATURE RESULT: VALID
FLUTTERWAVE WEBHOOK RECEIVED: ...
```

If it says:

```text
WEBHOOK SIGNATURE RESULT: INVALID
```

we know the secret/signature is the problem.

If it says:

```text
WEBHOOK SIGNATURE RESULT: VALID
```

but then:

```text
KENT USER NOT FOUND
```

we know the payment is reaching KENT but the virtual account/customer isn't being matched.

If you see:

```text
KENT WALLET FUNDED SUCCESSFULLY
```

then **the ₦200 should be added to `walletBalance`**.

Flutterwave's documentation specifically shows that virtual-account bank transfers generate `charge.completed` webhooks and that `data.id` should be used to verify the transaction, which is why this replacement keeps that verification flow.

**One important thing:** because your Render logs already show `POST /api/flutterwave/webhook`, we don't need to change your webhook URL again. The endpoint is being reached. We are now diagnosing what happens **inside the controller**.

const axios = require("axios");

// ============================================================
// KENT - FLUTTERWAVE V4 SERVICE
// ============================================================
//
// Production API:
// https://f4bexperience.flutterwave.com
//
// OAuth:
// https://idp.flutterwave.com/realms/flutterwave/protocol/openid-connect/token
//
// REQUIRED ENVIRONMENT VARIABLES:
//
// FLW_CLIENT_ID
// FLW_CLIENT_SECRET
// FLW_BASE_URL=https://f4bexperience.flutterwave.com
// FLW_TRANSFER_WEBHOOK_URL=YOUR_WEBHOOK_URL
//
// NEVER put Flutterwave credentials in this file.
// NEVER expose Flutterwave credentials to Flutter.
// ============================================================

// ============================================================
// CONFIGURATION
// ============================================================

const FLW_CLIENT_ID =
  process.env.FLW_CLIENT_ID;

const FLW_CLIENT_SECRET =
  process.env.FLW_CLIENT_SECRET;

const FLW_BASE_URL = (
  process.env.FLW_BASE_URL ||
  "https://f4bexperience.flutterwave.com"
).replace(/\/+$/, "");

const FLW_OAUTH_URL =
  "https://idp.flutterwave.com/realms/flutterwave/protocol/openid-connect/token";

const FLW_TRANSFER_WEBHOOK_URL =
  process.env.FLW_TRANSFER_WEBHOOK_URL || "";

// ============================================================
// SETTINGS
// ============================================================

const REQUEST_TIMEOUT_MS =
  45000;

const TOKEN_REFRESH_BUFFER_MS =
  60 * 1000;

// ============================================================
// OAUTH TOKEN CACHE
// ============================================================

let accessToken = null;

let accessTokenExpiresAt = 0;

// ============================================================
// BANK CODE VALIDATION
// ============================================================

function validNigerianBankCode(value) {
  return /^\d{3,6}$/.test(
    String(value || "").trim()
  );
}

// ============================================================
// ACCOUNT NUMBER VALIDATION
// ============================================================

function validNigerianAccountNumber(value) {
  return /^\d{10}$/.test(
    String(value || "").trim()
  );
}

// ============================================================
// TRANSFER REFERENCE VALIDATION
// ============================================================

function validTransferReference(reference) {
  return (
    typeof reference === "string" &&
    reference.length >= 6 &&
    reference.length <= 42 &&
    /^[a-zA-Z0-9-]+$/.test(reference)
  );
}

// ============================================================
// CONFIGURATION VALIDATION
// ============================================================

function validateConfiguration() {
  if (
    !FLW_CLIENT_ID ||
    !FLW_CLIENT_ID.trim()
  ) {
    throw new Error(
      "FLW_CLIENT_ID is not configured."
    );
  }

  if (
    !FLW_CLIENT_SECRET ||
    !FLW_CLIENT_SECRET.trim()
  ) {
    throw new Error(
      "FLW_CLIENT_SECRET is not configured."
    );
  }

  if (
    !FLW_BASE_URL ||
    !FLW_BASE_URL.trim()
  ) {
    throw new Error(
      "FLW_BASE_URL is not configured."
    );
  }
}

// ============================================================
// GET FLUTTERWAVE OAUTH ACCESS TOKEN
// ============================================================

async function getFlutterwaveAccessToken(
  forceRefresh = false
) {
  validateConfiguration();

  const now =
    Date.now();

  if (
    !forceRefresh &&
    accessToken &&
    now <
      accessTokenExpiresAt -
        TOKEN_REFRESH_BUFFER_MS
  ) {
    return accessToken;
  }

  try {
    const body =
      new URLSearchParams({
        client_id:
          FLW_CLIENT_ID,

        client_secret:
          FLW_CLIENT_SECRET,

        grant_type:
          "client_credentials",
      });

    const response =
      await axios.post(
        FLW_OAUTH_URL,
        body.toString(),
        {
          headers: {
            "Content-Type":
              "application/x-www-form-urlencoded",

            Accept:
              "application/json",
          },

          timeout:
            REQUEST_TIMEOUT_MS,
        }
      );

    const token =
      response.data &&
      response.data.access_token;

    const expiresIn =
      Number(
        response.data &&
          response.data.expires_in
      );

    if (
      typeof token !== "string" ||
      !token.trim()
    ) {
      throw new Error(
        "Flutterwave did not return an access token."
      );
    }

    accessToken =
      token.trim();

    accessTokenExpiresAt =
      Date.now() +
      (
        Number.isFinite(expiresIn) &&
        expiresIn > 0
          ? expiresIn * 1000
          : 10 * 60 * 1000
      );

    console.log(
      "Flutterwave OAuth access token obtained successfully."
    );

    return accessToken;
  } catch (error) {
    console.error(
      "FLUTTERWAVE OAUTH ERROR:",
      error.response?.data ||
        error.message
    );

    throw new Error(
      "Unable to authenticate with Flutterwave."
    );
  }
}

// ============================================================
// GENERATE TRACE ID
// ============================================================

function generateTraceId(
  prefix = "kent"
) {
  return `${prefix}-${Date.now()}-${Math.random()
    .toString(36)
    .substring(2, 10)}`;
}

// ============================================================
// GENERATE IDEMPOTENCY KEY
// ============================================================

function generateIdempotencyKey(
  prefix = "kent"
) {
  return `${prefix}-${Date.now()}-${Math.random()
    .toString(36)
    .substring(2, 14)}`;
}

// ============================================================
// FLUTTERWAVE API REQUEST
// ============================================================

async function flutterwaveRequest({
  method,
  path,
  data,
  idempotencyKey,
  traceId,
  retryOn401 = true,
}) {
  let token =
    await getFlutterwaveAccessToken();

  const headers = {
    Authorization:
      `Bearer ${token}`,

    "Content-Type":
      "application/json",

    Accept:
      "application/json",

    "X-Trace-Id":
      traceId ||
      generateTraceId(),
  };

  if (idempotencyKey) {
    headers[
      "X-Idempotency-Key"
    ] =
      idempotencyKey;
  }

  try {
    return await axios({
      method,

      url:
        `${FLW_BASE_URL}${path}`,

      data,

      headers,

      timeout:
        REQUEST_TIMEOUT_MS,
    });
  } catch (error) {
    if (
      retryOn401 &&
      error.response?.status === 401
    ) {
      console.log(
        "Flutterwave returned 401. Refreshing OAuth token..."
      );

      token =
        await getFlutterwaveAccessToken(
          true
        );

      headers.Authorization =
        `Bearer ${token}`;

      return axios({
        method,

        url:
          `${FLW_BASE_URL}${path}`,

        data,

        headers,

        timeout:
          REQUEST_TIMEOUT_MS,
      });
    }

    throw error;
  }
}

// ============================================================
// CREATE FLUTTERWAVE CUSTOMER
// ============================================================

async function createFlutterwaveCustomer({
  email,
  firstName,
  lastName,
  phoneNumber,
  idempotencyKey,
}) {
  if (
    !email ||
    typeof email !== "string"
  ) {
    throw new Error(
      "Customer email is required."
    );
  }

  if (
    !firstName ||
    typeof firstName !== "string"
  ) {
    throw new Error(
      "Customer first name is required."
    );
  }

  if (
    !lastName ||
    typeof lastName !== "string"
  ) {
    throw new Error(
      "Customer last name is required."
    );
  }

  const payload = {
    name: {
      first:
        firstName.trim(),

      last:
        lastName.trim(),
    },

    email:
      email.trim(),
  };

  if (phoneNumber) {
    let phone =
      String(phoneNumber)
        .trim();

    if (
      phone.startsWith("+234")
    ) {
      phone =
        phone.substring(4);
    } else if (
      phone.startsWith("234")
    ) {
      phone =
        phone.substring(3);
    } else if (
      phone.startsWith("0")
    ) {
      phone =
        phone.substring(1);
    }

    if (phone) {
      payload.phone = {
        country_code:
          "234",

        number:
          phone,
      };
    }
  }

  const finalIdempotencyKey =
    idempotencyKey ||
    generateIdempotencyKey(
      "kent-customer"
    );

  try {
    const response =
      await flutterwaveRequest({
        method:
          "POST",

        path:
          "/customers",

        data:
          payload,

        idempotencyKey:
          finalIdempotencyKey,

        traceId:
          generateTraceId(
            "kent-customer"
          ),
      });

    return response.data;
  } catch (error) {
    console.error(
      "FLUTTERWAVE CUSTOMER CREATION ERROR:",
      error.response?.data ||
        error.message
    );

    throw error;
  }
}

// ============================================================
// CREATE STATIC VIRTUAL ACCOUNT
// ============================================================

async function createStaticVirtualAccount({
  customerId,
  reference,
  narration,
  bvn,
  nin,
  bankCode,
}) {
  if (
    !customerId ||
    typeof customerId !== "string"
  ) {
    throw new Error(
      "Flutterwave customer ID is required."
    );
  }

  if (
    !reference ||
    typeof reference !== "string"
  ) {
    throw new Error(
      "Virtual account reference is required."
    );
  }

  if (
    !validTransferReference(reference)
  ) {
    throw new Error(
      "Virtual account reference must contain 6-42 letters, numbers, or hyphens."
    );
  }

  if (
    !bvn &&
    !nin
  ) {
    throw new Error(
      "A verified BVN or NIN is required to create the static NGN virtual account."
    );
  }

  const payload = {
    reference,

    customer_id:
      customerId,

    amount:
      0,

    currency:
      "NGN",

    account_type:
      "static",

    narration:
      narration ||
      "KENT Pay",

    bank_code:
      bankCode ||
      "090567",
  };

  if (bvn) {
    payload.bvn =
      String(bvn).trim();
  }

  if (nin) {
    payload.nin =
      String(nin).trim();
  }

  const idempotencyKey =
    `kent-account-${reference}`;

  try {
    const response =
      await flutterwaveRequest({
        method:
          "POST",

        path:
          "/virtual-accounts",

        data:
          payload,

        idempotencyKey,

        traceId:
          generateTraceId(
            "kent-account"
          ),
      });

    return response.data;
  } catch (error) {
    console.error(
      "FLUTTERWAVE VIRTUAL ACCOUNT ERROR:",
      error.response?.data ||
        error.message
    );

    throw error;
  }
}

// ============================================================
// GET NIGERIAN BANKS
// ============================================================

async function getNigerianBanks() {
  try {
    const response =
      await flutterwaveRequest({
        method:
          "GET",

        path:
          "/banks?country=NG",

        traceId:
          generateTraceId(
            "kent-banks"
          ),
      });

    const responseBody =
      response?.data;

    const banks =
      responseBody?.data;

    if (
      !Array.isArray(banks)
    ) {
      console.error(
        "FLUTTERWAVE BANK LIST INVALID RESPONSE:",
        responseBody
      );

      return [];
    }

    return banks;
  } catch (error) {
    console.error(
      "FLUTTERWAVE BANK LIST ERROR:",
      error.response?.data ||
        error.message
    );

    throw error;
  }
}

// ============================================================
// RESOLVE NIGERIAN BANK ACCOUNT
// ============================================================

async function resolveNigerianBankAccount({
  bankCode,
  accountNumber,
}) {
  const cleanBankCode =
    String(
      bankCode || ""
    ).trim();

  const cleanAccountNumber =
    String(
      accountNumber || ""
    ).trim();

  if (
    !validNigerianBankCode(
      cleanBankCode
    )
  ) {
    throw new Error(
      "Invalid Nigerian bank code."
    );
  }

  if (
    !validNigerianAccountNumber(
      cleanAccountNumber
    )
  ) {
    throw new Error(
      "Nigerian bank account number must contain 10 digits."
    );
  }

  try {
    console.log(
      "KENT FLUTTERWAVE ACCOUNT RESOLVE:",
      {
        bankCode:
          cleanBankCode,

        accountNumber:
          cleanAccountNumber,
      }
    );

    const response =
      await flutterwaveRequest({
        method:
          "POST",

        path:
          "/banks/account-resolve",

        data: {
          account: {
            code:
              cleanBankCode,

            number:
              cleanAccountNumber,
          },

          currency:
            "NGN",
        },

        traceId:
          generateTraceId(
            "kent-resolve"
          ),
      });

    console.log(
      "KENT FLUTTERWAVE ACCOUNT RESOLVE RESPONSE:",
      response?.data
    );

    return response.data;
  } catch (error) {
    console.error(
      "FLUTTERWAVE ACCOUNT RESOLVE ERROR:",
      error.response?.data ||
        error.message
    );

    throw error;
  }
}

// ============================================================
// CREATE DIRECT BANK TRANSFER
// ============================================================
//
// POST /direct-transfers
//
// Exact NGN structure:
//
// {
//   action: "instant",
//   type: "bank",
//   reference: "...",
//   narration: "...",
//   payment_instruction: {
//     source_currency: "NGN",
//     destination_currency: "NGN",
//     amount: {
//       applies_to: "destination_currency",
//       value: 1000
//     },
//     recipient: {
//       bank: {
//         code: "044",
//         account_number: "0123456789"
//       }
//     }
//   }
// }
// ============================================================

async function createDirectBankTransfer({
  reference,
  amount,
  bankCode,
  accountNumber,
  narration,
}) {
  // ==========================================================
  // REFERENCE
  // ==========================================================

  if (
    !validTransferReference(
      reference
    )
  ) {
    throw new Error(
      "Transfer reference must contain 6-42 letters, numbers, or hyphens."
    );
  }

  // ==========================================================
  // AMOUNT
  // ==========================================================

  const numericAmount =
    Number(amount);

  if (
    !Number.isFinite(
      numericAmount
    ) ||
    numericAmount <= 0
  ) {
    throw new Error(
      "Transfer amount must be greater than zero."
    );
  }

  // ==========================================================
  // BANK CODE
  // ==========================================================

  const cleanBankCode =
    String(
      bankCode || ""
    ).trim();

  if (
    !validNigerianBankCode(
      cleanBankCode
    )
  ) {
    throw new Error(
      "Invalid Nigerian bank code."
    );
  }

  // ==========================================================
  // ACCOUNT NUMBER
  // ==========================================================

  const cleanAccountNumber =
    String(
      accountNumber || ""
    ).trim();

  if (
    !validNigerianAccountNumber(
      cleanAccountNumber
    )
  ) {
    throw new Error(
      "Nigerian bank account number must contain 10 digits."
    );
  }

  // ==========================================================
  // PAYLOAD
  // ==========================================================

  const payload = {
    action:
      "instant",

    type:
      "bank",

    reference:
      reference,

    narration:
      narration ||
      "KENT Pay transfer",

    payment_instruction: {
      source_currency:
        "NGN",

      destination_currency:
        "NGN",

      amount: {
        applies_to:
          "destination_currency",

        value:
          numericAmount,
      },

      recipient: {
        bank: {
          code:
            cleanBankCode,

          account_number:
            cleanAccountNumber,
        },
      },
    },
  };

  // ==========================================================
  // CALLBACK
  // ==========================================================

  if (
    FLW_TRANSFER_WEBHOOK_URL
  ) {
    payload.callback_url =
      FLW_TRANSFER_WEBHOOK_URL;
  }

  // ==========================================================
  // IDEMPOTENCY
  // ==========================================================

  const idempotencyKey =
    `kent-transfer-${reference}`;

  const traceId =
    generateTraceId(
      "kent-transfer"
    );

  console.log(
    "============================================================"
  );

  console.log(
    "KENT FLUTTERWAVE DIRECT TRANSFER REQUEST"
  );

  console.log(
    "TRACE ID:",
    traceId
  );

  console.log(
    "REFERENCE:",
    reference
  );

  console.log(
    "AMOUNT:",
    numericAmount
  );

  console.log(
    "BANK CODE:",
    cleanBankCode
  );

  console.log(
    "ACCOUNT NUMBER:",
    cleanAccountNumber
  );

  console.log(
    "BASE URL:",
    FLW_BASE_URL
  );

  console.log(
    "ENDPOINT:",
    `${FLW_BASE_URL}/direct-transfers`
  );

  console.log(
    "PAYLOAD:",
    JSON.stringify(
      payload,
      null,
      2
    )
  );

  console.log(
    "============================================================"
  );

  try {
    const response =
      await flutterwaveRequest({
        method:
          "POST",

        path:
          "/direct-transfers",

        data:
          payload,

        idempotencyKey,

        traceId,
      });

    console.log(
      "============================================================"
    );

    console.log(
      "FLUTTERWAVE DIRECT TRANSFER SUCCESS"
    );

    console.log(
      "HTTP STATUS:",
      response?.status
    );

    console.log(
      "RESPONSE:",
      JSON.stringify(
        response?.data,
        null,
        2
      )
    );

    console.log(
      "============================================================"
    );

    return response.data;
  } catch (error) {
    // ========================================================
    // IMPORTANT:
    // NEVER hide Flutterwave's actual response.
    // ========================================================

    const status =
      error.response?.status;

    const responseData =
      error.response?.data;

    console.error(
      "============================================================"
    );

    console.error(
      "FLUTTERWAVE DIRECT TRANSFER FAILED"
    );

    console.error(
      "HTTP STATUS:",
      status || "NO_HTTP_STATUS"
    );

    console.error(
      "TRACE ID:",
      traceId
    );

    console.error(
      "REFERENCE:",
      reference
    );

    console.error(
      "URL:",
      `${FLW_BASE_URL}/direct-transfers`
    );

    console.error(
      "FLUTTERWAVE RESPONSE:",
      JSON.stringify(
        responseData,
        null,
        2
      )
    );

    console.error(
      "AXIOS ERROR:",
      error.message
    );

    console.error(
      "============================================================"
    );

    // ========================================================
    // Return a useful error to the controller/service.
    // ========================================================

    const providerMessage =
      responseData?.message ||
      responseData?.error ||
      responseData?.data?.message ||
      error.message ||
      "Flutterwave transfer request failed.";

    const providerError =
      new Error(
        `Flutterwave transfer failed: ${providerMessage}`
      );

    providerError.providerStatus =
      status || null;

    providerError.providerResponse =
      responseData || null;

    providerError.traceId =
      traceId;

    throw providerError;
  }
}

// ============================================================
// GET DIRECT TRANSFER STATUS
// ============================================================

async function getDirectTransferStatus(
  transferId
) {
  if (!transferId) {
    throw new Error(
      "Flutterwave transfer ID is required."
    );
  }

  try {
    const response =
      await flutterwaveRequest({
        method:
          "GET",

        path:
          `/transfers/${encodeURIComponent(
            transferId
          )}`,

        traceId:
          generateTraceId(
            "kent-transfer-status"
          ),
      });

    console.log(
      "KENT FLUTTERWAVE TRANSFER STATUS RESPONSE:",
      JSON.stringify(
        response?.data,
        null,
        2
      )
    );

    return response.data;
  } catch (error) {
    console.error(
      "FLUTTERWAVE TRANSFER STATUS ERROR:",
      error.response?.data ||
        error.message
    );

    throw error;
  }
}

// ============================================================
// EXPORTS
// ============================================================

module.exports = {
  getFlutterwaveAccessToken,

  flutterwaveRequest,

  createFlutterwaveCustomer,

  createStaticVirtualAccount,

  getNigerianBanks,

  resolveNigerianBankAccount,

  createDirectBankTransfer,

  getDirectTransferStatus,
};
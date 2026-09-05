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
// Required environment variables:
//
// FLW_CLIENT_ID
// FLW_CLIENT_SECRET
// FLW_BASE_URL=https://f4bexperience.flutterwave.com
//
// NEVER put Flutterwave credentials in this file.
// NEVER expose them to Flutter/Android.
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
// VALIDATE CONFIGURATION
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
//
// Flutterwave OAuth tokens currently expire after
// approximately 10 minutes.
//
// We refresh one minute before expiry.
// ============================================================

async function getFlutterwaveAccessToken(
  forceRefresh = false
) {
  validateConfiguration();

  const now =
    Date.now();

  // Reuse valid cached token.
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
//
// Flutterwave requires X-Trace-Id to be a unique value
// between 12 and 255 characters.
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
//
// Flutterwave requires an idempotency key to prevent
// accidental duplicate POST operations.
//
// For account creation we will supply a stable key based
// on the KENT virtual-account reference.
//
// For other operations this function can generate one.
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
    ] = idempotencyKey;
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
    // ========================================================
    // TOKEN EXPIRED
    // ========================================================

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
//
// Current v4 flow:
//
// 1. Create customer.
// 2. Receive customer_id.
// 3. Use customer_id to create static virtual account.
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

  // ----------------------------------------------------------
  // CUSTOMER PAYLOAD
  // ----------------------------------------------------------

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

  // ----------------------------------------------------------
  // PHONE
  // ----------------------------------------------------------

  if (
    phoneNumber
  ) {
    let phone =
      String(phoneNumber)
        .trim();

    // Convert Nigerian formats to local number.
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

  // ----------------------------------------------------------
  // IDEMPOTENCY
  // ----------------------------------------------------------

  const finalIdempotencyKey =
    idempotencyKey ||
    generateIdempotencyKey(
      "kent-customer"
    );

  // ----------------------------------------------------------
  // REQUEST
  // ----------------------------------------------------------

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
//
// Current v4 static NGN account:
//
// amount = 0
// account_type = static
// currency = NGN
// customer_id required
// BVN or NIN required
//
// Flutterwave's current documentation shows bank code
// 090567 for Flutterwave MFB when specifying the NGN bank.
// ============================================================

async function createStaticVirtualAccount({
  customerId,
  reference,
  narration,
  bvn,
  nin,
  bankCode,
}) {
  // ----------------------------------------------------------
  // CUSTOMER ID
  // ----------------------------------------------------------

  if (
    !customerId ||
    typeof customerId !== "string"
  ) {
    throw new Error(
      "Flutterwave customer ID is required."
    );
  }

  // ----------------------------------------------------------
  // REFERENCE
  // ----------------------------------------------------------

  if (
    !reference ||
    typeof reference !== "string"
  ) {
    throw new Error(
      "Virtual account reference is required."
    );
  }

  // Flutterwave reference:
  // 6-42 characters, letters/numbers/hyphens.
  if (
    reference.length < 6 ||
    reference.length > 42 ||
    !/^[a-zA-Z0-9-]+$/.test(
      reference
    )
  ) {
    throw new Error(
      "Virtual account reference must contain 6-42 letters, numbers, or hyphens."
    );
  }

  // ----------------------------------------------------------
  // BVN OR NIN
  // ----------------------------------------------------------

  if (
    !bvn &&
    !nin
  ) {
    throw new Error(
      "A verified BVN or NIN is required to create the static NGN virtual account."
    );
  }

  // ----------------------------------------------------------
  // PAYLOAD
  // ----------------------------------------------------------

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

    // Flutterwave MFB.
    bank_code:
      bankCode ||
      "090567",
  };

  // ----------------------------------------------------------
  // IDENTITY
  // ----------------------------------------------------------

  if (bvn) {
    payload.bvn =
      String(bvn).trim();
  }

  if (nin) {
    payload.nin =
      String(nin).trim();
  }

  // ----------------------------------------------------------
  // IDEMPOTENCY
  // ----------------------------------------------------------
  //
  // IMPORTANT:
  // The same reference always produces the same
  // idempotency key.
  //
  // This prevents KENT from deliberately creating
  // another account when the same operation is retried.
  // ----------------------------------------------------------

  const idempotencyKey =
    `kent-account-${reference}`;

  // ----------------------------------------------------------
  // REQUEST
  // ----------------------------------------------------------

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
// EXPORTS
// ============================================================

module.exports = {
  getFlutterwaveAccessToken,

  flutterwaveRequest,

  createFlutterwaveCustomer,

  createStaticVirtualAccount,
};
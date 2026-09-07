const express = require("express");

const { auth, db } = require("../../firebaseAdmin");

const {
  ensureKentPayVirtualAccount,
  getKentPayVirtualAccount,
} = require("../services/kentPayService");

const router = express.Router();

// ============================================================
// FIREBASE AUTH MIDDLEWARE
// ============================================================

async function requireAuth(req, res, next) {
  try {
    const authorization =
      req.headers.authorization || "";

    if (!authorization.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Authentication token is required.",
      });
    }

    const token =
      authorization.substring(7).trim();

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Authentication token is missing.",
      });
    }

    const decodedToken =
      await auth.verifyIdToken(token);

    req.user = decodedToken;

    return next();
  } catch (error) {
    console.error(
      "KENT AUTH ERROR:",
      error.message
    );

    return res.status(401).json({
      success: false,
      message:
        "Invalid or expired authentication token.",
    });
  }
}

// ============================================================
// GET KENT PAY ACCOUNT
// ============================================================

router.get(
  "/me",
  requireAuth,
  async (req, res) => {
    try {
      const uid = req.user.uid;

      const userSnapshot = await db
        .collection("users")
        .doc(uid)
        .get();

      if (!userSnapshot.exists) {
        return res.status(404).json({
          success: false,
          message:
            "KENT user account was not found.",
        });
      }

      const userData =
        userSnapshot.data() || {};

      const kentPayAccount =
        userData.kentPayAccount || null;

      const bvnVerified =
        userData.bvnVerified === true ||
        userData.bvnVerification?.verified === true;

      const ninVerified =
        userData.ninVerified === true ||
        userData.ninVerification?.verified === true;

      const kentPayActivated =
        userData.kentPayActivated === true ||
        userData.kentPay?.activated === true;

      const kentPayAccountReady =
        userData.kentPayAccountReady === true ||
        !!(
          kentPayAccount &&
          kentPayAccount.accountNumber
        );

      return res.status(200).json({
        success: true,

        bvnVerified,

        ninVerified,

        kentPayActivated,

        kentPayAccountReady,

        kentPayAccount,

        walletBalance:
          typeof userData.walletBalance === "number"
            ? userData.walletBalance
            : 0,

        accountName:
          userData.displayName ||
          userData.fullName ||
          userData.name ||
          `${userData.firstName || ""} ${
            userData.lastName || ""
          }`.trim() ||
          "KENT User",
      });
    } catch (error) {
      console.error(
        "KENT PAY GET ACCOUNT ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to load KENT Pay account.",
      });
    }
  }
);

// ============================================================
// CREATE KENT PAY VIRTUAL ACCOUNT
// ============================================================
//
// POST /api/kent-pay/create-account
//
// NORMAL CASE:
// Flutter sends only the Firebase auth token.
//
// If encrypted BVN already exists in Firestore,
// kentPayService.js uses it directly.
//
// LEGACY / REPAIR CASE:
// Some users were verified before encryptedIdentity
// was introduced.
//
// In that case Flutter may send the SAME BVN that was
// already verified:
//
// {
//   "bvn": "12345678901"
// }
//
// The service will:
//   1. confirm BVN verification exists
//   2. compare SHA-256 hash against the stored identityHash
//   3. encrypt the BVN
//   4. save encryptedIdentity
//   5. create the Flutterwave virtual account
//
// IMPORTANT:
//
// - BVN is NEVER logged.
// - BVN is NEVER returned.
// - BVN is NEVER stored as plaintext.
// - Ninja is NOT called again.
// ============================================================

router.post(
  "/create-account",
  requireAuth,
  async (req, res) => {
    try {
      const uid = req.user.uid;

      console.log(
        "KENT CREATE ACCOUNT REQUEST:",
        {
          uid,
        }
      );

      // --------------------------------------------------------
      // LOAD USER
      // --------------------------------------------------------

      const userRef = db
        .collection("users")
        .doc(uid);

      const userSnapshot =
        await userRef.get();

      if (!userSnapshot.exists) {
        return res.status(404).json({
          success: false,
          message:
            "KENT user account was not found.",
        });
      }

      const userData =
        userSnapshot.data() || {};

      // --------------------------------------------------------
      // CHECK BVN
      // --------------------------------------------------------

      const bvnVerified =
        userData.bvnVerified === true ||
        userData.bvnVerification?.verified === true;

      if (!bvnVerified) {
        return res.status(403).json({
          success: false,
          message:
            "Your BVN must be verified before creating a KENT Pay account.",
        });
      }

      // --------------------------------------------------------
      // CHECK NIN
      // --------------------------------------------------------

      const ninVerified =
        userData.ninVerified === true ||
        userData.ninVerification?.verified === true;

      if (!ninVerified) {
        return res.status(403).json({
          success: false,
          message:
            "Your NIN must be verified before creating a KENT Pay account.",
        });
      }

      // --------------------------------------------------------
      // CHECK EXISTING ACCOUNT
      // --------------------------------------------------------

      const existingAccount =
        userData.kentPayAccount || null;

      if (
        existingAccount &&
        existingAccount.accountNumber
      ) {
        console.log(
          "KENT PAY ACCOUNT ALREADY EXISTS:",
          {
            uid,
            accountNumber:
              existingAccount.accountNumber,
            bankName:
              existingAccount.bankName || null,
          }
        );

        return res.status(200).json({
          success: true,

          created: false,

          alreadyExists: true,

          bvnVerified: true,

          ninVerified: true,

          kentPayActivated:
            userData.kentPayActivated === true ||
            userData.kentPay?.activated === true,

          kentPayAccountReady: true,

          kentPayAccount:
            existingAccount,

          account:
            existingAccount,

          walletBalance:
            typeof userData.walletBalance ===
              "number"
              ? userData.walletBalance
              : 0,
        });
      }

      // --------------------------------------------------------
      // CHECK WHETHER ENCRYPTED BVN ALREADY EXISTS
      // --------------------------------------------------------

      const encryptedBvn =
        userData.bvnVerification?.encryptedIdentity ||
        userData.bvnEncrypted ||
        null;

      // --------------------------------------------------------
      // LEGACY RECORD REPAIR
      // --------------------------------------------------------
      //
      // Only require BVN from the client when the old verified
      // record does not yet contain encryptedIdentity.
      //
      // The actual verification against identityHash is performed
      // inside kentPayService.js.
      // --------------------------------------------------------

      let suppliedBvn = null;

      if (!encryptedBvn) {
        const incomingBvn =
          typeof req.body?.bvn === "string"
            ? req.body.bvn.trim()
            : "";

        if (!/^\d{11}$/.test(incomingBvn)) {
          return res.status(400).json({
            success: false,

            bvnRequired: true,

            message:
              "Your verified BVN record needs secure recovery. Please provide the same BVN that was previously verified.",
          });
        }

        suppliedBvn = incomingBvn;
      }

      // --------------------------------------------------------
      // CREATE ACCOUNT
      // --------------------------------------------------------

      console.log(
        "KENT CREATING VIRTUAL ACCOUNT:",
        {
          uid,
          bvnVerified,
          ninVerified,
          needsBvnRecovery:
            !encryptedBvn,
        }
      );

      const result =
        await ensureKentPayVirtualAccount({
          uid,

          idType:
            suppliedBvn
              ? "bvn"
              : undefined,

          rawId:
            suppliedBvn ||
            undefined,
        });

      // --------------------------------------------------------
      // LOAD UPDATED USER
      // --------------------------------------------------------

      const updatedSnapshot =
        await userRef.get();

      const updatedData =
        updatedSnapshot.exists
          ? updatedSnapshot.data() || {}
          : {};

      const account =
        result?.account ||
        updatedData.kentPayAccount ||
        null;

      // --------------------------------------------------------
      // SAFETY CHECK
      // --------------------------------------------------------

      if (
        !account ||
        !account.accountNumber
      ) {
        console.error(
          "KENT ACCOUNT CREATION RETURNED NO ACCOUNT:",
          {
            uid,
            result,
          }
        );

        return res.status(500).json({
          success: false,
          message:
            "KENT Pay account creation did not return a valid virtual account.",
        });
      }

      // --------------------------------------------------------
      // SUCCESS
      // --------------------------------------------------------

      console.log(
        "KENT PAY ACCOUNT READY:",
        {
          uid,
          accountNumber:
            account.accountNumber,
          bankName:
            account.bankName || null,
        }
      );

      return res.status(200).json({
        success: true,

        created:
          result?.created === true,

        alreadyExists:
          result?.alreadyExists === true,

        bvnVerified: true,

        ninVerified: true,

        kentPayActivated:
          updatedData.kentPayActivated === true ||
          updatedData.kentPay?.activated === true,

        kentPayAccountReady: true,

        kentPayAccount:
          account,

        account,

        walletBalance:
          typeof updatedData.walletBalance ===
            "number"
            ? updatedData.walletBalance
            : 0,
      });
    } catch (error) {
      console.error(
        "KENT CREATE ACCOUNT ERROR:",
        {
          message:
            error?.message || "Unknown error",

          name:
            error?.name || null,

          status:
            error?.response?.status || null,

          providerResponse:
            error?.response?.data || null,
        }
      );

      let safeMessage =
        "Unable to create your KENT Pay account.";

      const message =
        typeof error?.message === "string"
          ? error.message.trim()
          : "";

      if (
        message ===
        "Your BVN has not been verified."
      ) {
        safeMessage = message;
      } else if (
        message ===
        "Your verified BVN is not available for KENT Pay account creation. Please complete BVN verification again."
      ) {
        safeMessage =
          "Your verified BVN record needs secure recovery. Please enter the same BVN that was previously verified.";
      } else if (
        message ===
        "The stored verified BVN is invalid."
      ) {
        safeMessage = message;
      } else if (
        message ===
        "The supplied BVN does not match the BVN that was previously verified."
      ) {
        safeMessage =
          "The BVN entered does not match the BVN that was previously verified.";
      } else if (
        message ===
        "The verified BVN supplied for KENT Pay account creation is invalid."
      ) {
        safeMessage =
          "The BVN supplied for KENT Pay account creation is invalid.";
      } else if (
        message ===
        "A verified email address is required before creating the KENT Pay account."
      ) {
        safeMessage = message;
      } else if (
        message ===
        "Flutterwave customer creation did not return a customer ID."
      ) {
        safeMessage =
          "KENT could not create your payment profile. Please try again.";
      } else if (
        message ===
        "Flutterwave did not return a valid virtual account."
      ) {
        safeMessage =
          "KENT could not create your virtual account. Please try again.";
      }

      return res.status(500).json({
        success: false,
        message: safeMessage,
      });
    }
  }
);

// ============================================================
// GET ONLY THE VIRTUAL ACCOUNT
// ============================================================

router.get(
  "/account",
  requireAuth,
  async (req, res) => {
    try {
      const uid = req.user.uid;

      const account =
        await getKentPayVirtualAccount(uid);

      if (!account) {
        return res.status(404).json({
          success: false,
          message:
            "KENT Pay virtual account has not been created yet.",
        });
      }

      return res.status(200).json({
        success: true,
        account,
      });
    } catch (error) {
      console.error(
        "KENT GET VIRTUAL ACCOUNT ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to retrieve KENT Pay virtual account.",
      });
    }
  }
);

// ============================================================
// EXPORT
// ============================================================

module.exports = router;
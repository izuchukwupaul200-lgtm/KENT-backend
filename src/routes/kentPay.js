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
    const authorization = req.headers.authorization || "";

    if (!authorization.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Authentication token is required.",
      });
    }

    const token = authorization.substring(7).trim();

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Authentication token is missing.",
      });
    }

    const decodedToken = await auth.verifyIdToken(token);

    req.user = decodedToken;

    next();
  } catch (error) {
    console.error("KENT AUTH ERROR:", error.message);

    return res.status(401).json({
      success: false,
      message: "Invalid or expired authentication token.",
    });
  }
}

// ============================================================
// GET KENT PAY ACCOUNT
// ============================================================

router.get("/me", requireAuth, async (req, res) => {
  try {
    const uid = req.user.uid;

    const userSnapshot = await db
      .collection("users")
      .doc(uid)
      .get();

    if (!userSnapshot.exists) {
      return res.status(404).json({
        success: false,
        message: "KENT user account was not found.",
      });
    }

    const userData = userSnapshot.data() || {};

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
      message: "Unable to load KENT Pay account.",
    });
  }
});

// ============================================================
// CREATE KENT PAY VIRTUAL ACCOUNT
//
// IMPORTANT:
// Flutter does NOT send BVN or NIN here.
//
// The authenticated Firebase UID identifies the user.
// The backend verifies KYC status and kentPayService.js
// retrieves the encrypted BVN from Firestore.
//
// NEVER trust a BVN/NIN supplied by the Flutter app.
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

      const userSnapshot = await userRef.get();

      if (!userSnapshot.exists) {
        return res.status(404).json({
          success: false,
          message: "KENT user account was not found.",
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
      // CHECK IF ACCOUNT ALREADY EXISTS
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
              existingAccount.bankName,
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
      // CREATE ACCOUNT
      //
      // NO BVN/NIN FROM CLIENT
      //
      // kentPayService.js will:
      //
      // 1. Load the user
      // 2. Retrieve encrypted verified BVN
      // 3. Decrypt BVN on the backend
      // 4. Create Flutterwave customer
      // 5. Create static virtual account
      // 6. Save account to Firestore
      //
      // --------------------------------------------------------

      console.log(
        "KENT CREATING VIRTUAL ACCOUNT:",
        {
          uid,
          bvnVerified,
          ninVerified,
        }
      );

      const result =
        await ensureKentPayVirtualAccount({
          uid,
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
            account.bankName,
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
        error
      );

      let safeMessage =
        "Unable to create your KENT Pay account.";

      if (
        error &&
        typeof error.message === "string"
      ) {
        const message =
          error.message.trim();

        if (
          message ===
            "Your BVN has not been verified." ||
          message ===
            "Your verified BVN is not available for KENT Pay account creation. Please complete BVN verification again." ||
          message ===
            "The stored verified BVN is invalid." ||
          message ===
            "A verified email address is required before creating the KENT Pay account."
        ) {
          safeMessage = message;
        }
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

module.exports = router;
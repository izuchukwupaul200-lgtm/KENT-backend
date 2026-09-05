const express = require("express");
const crypto = require("crypto");

const { auth, db } = require("../../firebaseAdmin");

const {
  ensureKentPayVirtualAccount,
  getKentPayVirtualAccount,
} = require("../services/kentPayService");

const router = express.Router();

// ============================================================
// KENT PAY ROUTES
// ============================================================
//
// Mounted from server.js as:
//
// app.use("/api/kent-pay", kentPayRouter);
//
// Endpoints:
//
// POST /api/kent-pay/create-account
// GET  /api/kent-pay/me
//
// ============================================================


// ============================================================
// FIRESTORE USER REFERENCE
// ============================================================

function getUserRef(uid) {
  return db.collection("users").doc(uid);
}


// ============================================================
// FIREBASE AUTHENTICATION
// ============================================================

async function requireAuth(req, res, next) {
  try {
    const authorization =
      req.headers.authorization || "";

    if (!authorization.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Authentication required.",
      });
    }

    const idToken =
      authorization.substring(7).trim();

    if (!idToken) {
      return res.status(401).json({
        success: false,
        message: "Authentication token is missing.",
      });
    }

    const decodedToken =
      await auth.verifyIdToken(idToken);

    req.user = decodedToken;

    return next();
  } catch (error) {
    console.error(
      "KENT PAY AUTH ERROR:",
      error.message
    );

    return res.status(401).json({
      success: false,
      message:
        "Your login session is invalid or expired.",
    });
  }
}


// ============================================================
// CLEAN STRING
// ============================================================

function cleanString(value) {
  if (typeof value !== "string") {
    return "";
  }

  return value.trim();
}


// ============================================================
// VALIDATE BVN / NIN
// ============================================================

function isValidIdentityNumber(value) {
  return /^\d{11}$/.test(value);
}


// ============================================================
// HASH ID
// ============================================================
//
// This MUST match the hashing method used in kyc.js.
//
// kyc.js uses:
//
// sha256(`${idType}:${idNumber}`)
//
// ============================================================

function hashIdentity(idType, idNumber) {
  return crypto
    .createHash("sha256")
    .update(`${idType}:${idNumber}`)
    .digest("hex");
}


// ============================================================
// VERIFY THAT THE PROVIDED ID WAS ALREADY VERIFIED
// ============================================================
//
// We do NOT blindly trust the BVN/NIN supplied to this route.
//
// We compare its hash against the verified KYC record already
// stored in Firestore.
//
// Raw BVN/NIN is never saved here.
// ============================================================

function isPreviouslyVerifiedIdentity({
  userData,
  idType,
  rawId,
}) {
  const identityHash =
    hashIdentity(
      idType,
      rawId
    );

  const verification =
    idType === "bvn"
      ? userData.bvnVerification
      : userData.ninVerification;

  if (!verification) {
    return false;
  }

  if (verification.verified !== true) {
    return false;
  }

  if (
    verification.identityHash !==
    identityHash
  ) {
    return false;
  }

  return true;
}


// ============================================================
// GET KENT PAY ACCOUNT
// ============================================================
//
// GET /api/kent-pay/me
//
// ============================================================

router.get(
  "/me",
  requireAuth,
  async (req, res) => {
    try {
      const uid =
        req.user.uid;

      const userSnapshot =
        await getUserRef(uid).get();

      if (!userSnapshot.exists) {
        return res.status(404).json({
          success: false,
          message:
            "KENT user account was not found.",
        });
      }

      const userData =
        userSnapshot.data() || {};

      const bvnVerified =
        userData.bvnVerified === true;

      const ninVerified =
        userData.ninVerified === true;

      const kentPayActivated =
        bvnVerified &&
        ninVerified;

      const kentPayAccount =
        await getKentPayVirtualAccount(
          uid
        );

      return res.status(200).json({
        success: true,

        bvnVerified,

        ninVerified,

        kentPayActivated,

        kentPayAccountReady:
          !!kentPayAccount,

        kentPayAccount:
          kentPayAccount || null,
      });
    } catch (error) {
      console.error(
        "KENT PAY GET ACCOUNT ERROR:",
        error.message
      );

      return res.status(500).json({
        success: false,
        message:
          "Could not load your KENT Pay account.",
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
// Body:
//
// {
//   "bvn": "XXXXXXXXXXX"
// }
//
// OR:
//
// {
//   "nin": "XXXXXXXXXXX"
// }
//
// The supplied identity number must already have a matching
// VERIFIED hash in Firestore.
//
// ============================================================

router.post(
  "/create-account",
  requireAuth,
  async (req, res) => {
    const uid =
      req.user.uid;

    try {
      // ======================================================
      // READ USER
      // ======================================================

      const userSnapshot =
        await getUserRef(uid).get();

      if (!userSnapshot.exists) {
        return res.status(404).json({
          success: false,
          message:
            "KENT user account was not found.",
        });
      }

      const userData =
        userSnapshot.data() || {};


      // ======================================================
      // CHECK KYC
      // ======================================================

      const bvnVerified =
        userData.bvnVerified === true;

      const ninVerified =
        userData.ninVerified === true;

      if (
        !bvnVerified ||
        !ninVerified
      ) {
        return res.status(403).json({
          success: false,

          kentPayActivated: false,

          kentPayAccountReady: false,

          message:
            "Complete BVN and NIN verification before creating your KENT Pay account.",
        });
      }


      // ======================================================
      // CHECK IF ACCOUNT ALREADY EXISTS
      // ======================================================

      const existingAccount =
        await getKentPayVirtualAccount(
          uid
        );

      if (
        existingAccount &&
        existingAccount.accountNumber
      ) {
        return res.status(200).json({
          success: true,

          created: false,

          alreadyExists: true,

          kentPayActivated: true,

          kentPayAccountReady: true,

          kentPayAccount:
            existingAccount,

          message:
            "Your KENT Pay virtual account already exists.",
        });
      }


      // ======================================================
      // DETERMINE WHICH VERIFIED ID TO USE
      // ======================================================

      const suppliedBvn =
        cleanString(
          req.body?.bvn
        );

      const suppliedNin =
        cleanString(
          req.body?.nin
        );

      let idType = null;
      let rawId = null;


      // ------------------------------------------------------
      // Prefer BVN when supplied.
      // ------------------------------------------------------

      if (suppliedBvn) {
        if (
          !isValidIdentityNumber(
            suppliedBvn
          )
        ) {
          return res.status(400).json({
            success: false,
            message:
              "BVN must contain exactly 11 digits.",
          });
        }

        if (
          !isPreviouslyVerifiedIdentity({
            userData,
            idType: "bvn",
            rawId: suppliedBvn,
          })
        ) {
          return res.status(403).json({
            success: false,
            message:
              "The supplied BVN does not match the BVN that was previously verified.",
          });
        }

        idType = "bvn";
        rawId = suppliedBvn;
      }


      // ------------------------------------------------------
      // Otherwise use NIN.
      // ------------------------------------------------------

      if (
        !rawId &&
        suppliedNin
      ) {
        if (
          !isValidIdentityNumber(
            suppliedNin
          )
        ) {
          return res.status(400).json({
            success: false,
            message:
              "NIN must contain exactly 11 digits.",
          });
        }

        if (
          !isPreviouslyVerifiedIdentity({
            userData,
            idType: "nin",
            rawId: suppliedNin,
          })
        ) {
          return res.status(403).json({
            success: false,
            message:
              "The supplied NIN does not match the NIN that was previously verified.",
          });
        }

        idType = "nin";
        rawId = suppliedNin;
      }


      // ======================================================
      // NO ID PROVIDED
      // ======================================================

      if (!idType || !rawId) {
        return res.status(400).json({
          success: false,

          message:
            "Provide the BVN or NIN that was previously verified.",
        });
      }


      // ======================================================
      // CREATE FLUTTERWAVE ACCOUNT
      // ======================================================

      console.log(
        "KENT PAY ACCOUNT CREATION STARTED:",
        {
          uid,
          idType,
        }
      );

      const accountResult =
        await ensureKentPayVirtualAccount({
          uid,

          idType,

          rawId,
        });


      // ======================================================
      // CHECK RESULT
      // ======================================================

      if (
        !accountResult ||
        !accountResult.account
      ) {
        console.error(
          "KENT PAY ACCOUNT CREATION RETURNED NO ACCOUNT:",
          {
            uid,
            idType,
          }
        );

        return res.status(502).json({
          success: false,

          kentPayActivated: true,

          kentPayAccountReady: false,

          message:
            "KENT Pay is activated, but Flutterwave did not return a virtual account. Please try again.",
        });
      }


      // ======================================================
      // VERIFY ACCOUNT NUMBER
      // ======================================================

      const account =
        accountResult.account;

      if (
        !account.accountNumber
      ) {
        console.error(
          "KENT PAY ACCOUNT HAS NO ACCOUNT NUMBER:",
          {
            uid,
            idType,

            provider:
              account.provider || null,

            reference:
              account.reference || null,
          }
        );

        return res.status(502).json({
          success: false,

          kentPayActivated: true,

          kentPayAccountReady: false,

          message:
            "Flutterwave did not return an account number. Please try again.",
        });
      }


      // ======================================================
      // SUCCESS
      // ======================================================

      console.log(
        "KENT PAY ACCOUNT CREATED:",
        {
          uid,

          accountNumber:
            account.accountNumber,

          bankName:
            account.bankName,

          accountName:
            account.accountName,
        }
      );

      return res.status(200).json({
        success: true,

        created:
          accountResult.created === true,

        alreadyExists:
          accountResult.alreadyExists === true,

        kentPayActivated: true,

        kentPayAccountReady: true,

        kentPayAccount:
          account,

        message:
          "Your KENT Pay virtual account has been created successfully.",
      });
    } catch (error) {
      console.error(
        "KENT PAY CREATE ACCOUNT ERROR:",
        {
          uid,

          message:
            error.message,

          providerStatus:
            error.response?.status || null,

          providerData:
            error.response?.data || null,
        }
      );

      return res.status(500).json({
        success: false,

        kentPayActivated: true,

        kentPayAccountReady: false,

        message:
          "We could not create your KENT Pay virtual account right now. Please try again.",
      });
    }
  }
);


// ============================================================
// ROUTE NOT FOUND
// ============================================================

router.use(
  (req, res) => {
    return res.status(404).json({
      success: false,

      message:
        "KENT Pay endpoint not found.",

      path:
        req.originalUrl,
    });
  }
);


// ============================================================
// EXPORT
// ============================================================

module.exports = router;
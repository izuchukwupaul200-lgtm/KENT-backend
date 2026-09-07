const express = require("express");

const { auth } = require("../../firebaseAdmin");

const {
  listNigerianBanks,
  resolveBankAccount,
  createKentTransfer,
  getKentTransferStatus,
  createTransferPin,
  changeTransferPin,
  getTransferPinStatus,
} = require("../services/transferService");

const router = express.Router();

// ============================================================
// FIREBASE AUTHENTICATION
// ============================================================

async function requireAuth(
  req,
  res,
  next
) {
  try {
    const authorization =
      req.headers.authorization ||
      "";

    if (
      !authorization.startsWith(
        "Bearer "
      )
    ) {
      return res.status(401).json({
        success: false,
        message:
          "Authentication required.",
      });
    }

    const token =
      authorization
        .substring(7)
        .trim();

    if (!token) {
      return res.status(401).json({
        success: false,
        message:
          "Authentication token is missing.",
      });
    }

    const decodedToken =
      await auth.verifyIdToken(
        token
      );

    req.user =
      decodedToken;

    return next();
  } catch (error) {
    console.error(
      "KENT TRANSFER AUTH ERROR:",
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
// GET NIGERIAN BANKS
// ============================================================
//
// GET /api/transfers/banks
// ============================================================

router.get(
  "/banks",
  requireAuth,
  async (
    req,
    res
  ) => {
    try {
      const banks =
        await listNigerianBanks();

      return res.status(200).json({
        success: true,
        banks,
      });
    } catch (error) {
      console.error(
        "KENT GET BANKS ERROR:",
        error.response?.data ||
          error.message
      );

      return res.status(502).json({
        success: false,
        message:
          "Unable to load Nigerian banks right now.",
      });
    }
  }
);

// ============================================================
// RESOLVE BANK ACCOUNT
// ============================================================
//
// POST /api/transfers/resolve-account
// ============================================================

router.post(
  "/resolve-account",
  requireAuth,
  async (
    req,
    res
  ) => {
    try {
      const bankCode =
        String(
          req.body?.bankCode ||
            ""
        ).trim();

      const accountNumber =
        String(
          req.body?.accountNumber ||
            ""
        ).trim();

      const account =
        await resolveBankAccount({
          bankCode,
          accountNumber,
        });

      return res.status(200).json({
        success: true,
        account,
      });
    } catch (error) {
      console.error(
        "KENT RESOLVE ACCOUNT ERROR:",
        error.response?.data ||
          error.message
      );

      return res.status(400).json({
        success: false,
        message:
          error.message ||
          "Unable to verify the recipient account.",
      });
    }
  }
);

// ============================================================
// GET TRANSFER PIN STATUS
// ============================================================
//
// GET /api/transfers/pin/status
// ============================================================

router.get(
  "/pin/status",
  requireAuth,
  async (
    req,
    res
  ) => {
    try {
      const {
        getTransferPinStatus,
      } = require("../services/transferService");

      const result =
        await getTransferPinStatus(
          req.user.uid
        );

      return res.status(200).json({
        success: true,
        ...result,
      });
    } catch (error) {
      console.error(
        "KENT TRANSFER PIN STATUS ERROR:",
        error.message
      );

      return res.status(500).json({
        success: false,
        message:
          "Unable to check transfer PIN status.",
      });
    }
  }
);

// ============================================================
// CREATE TRANSFER PIN
// ============================================================
//
// POST /api/transfers/pin/create
//
// BODY:
//
// {
//   "pin": "1234"
// }
//
// ============================================================

router.post(
  "/pin/create",
  requireAuth,
  async (
    req,
    res
  ) => {
    try {
      const pin =
        typeof req.body?.pin ===
        "string"
          ? req.body.pin.trim()
          : "";

      const result =
        await createTransferPin({
          uid:
            req.user.uid,

          pin,
        });

      return res.status(201).json({
        success: true,

        message:
          "Your KENT Pay transfer PIN has been created.",

        ...result,
      });
    } catch (error) {
      console.error(
        "KENT CREATE TRANSFER PIN ERROR:",
        error.message
      );

      const message =
        error.message ||
        "Unable to create transfer PIN.";

      const status =
        message.includes(
          "already exists"
        )
          ? 409
          : 400;

      return res.status(status).json({
        success: false,
        message,
      });
    }
  }
);

// ============================================================
// CHANGE TRANSFER PIN
// ============================================================
//
// POST /api/transfers/pin/change
//
// BODY:
//
// {
//   "currentPin": "1234",
//   "newPin": "5678"
// }
//
// ============================================================

router.post(
  "/pin/change",
  requireAuth,
  async (
    req,
    res
  ) => {
    try {
      const currentPin =
        typeof req.body?.currentPin ===
        "string"
          ? req.body.currentPin.trim()
          : "";

      const newPin =
        typeof req.body?.newPin ===
        "string"
          ? req.body.newPin.trim()
          : "";

      const {
        changeTransferPin,
      } = require("../services/transferService");

      const result =
        await changeTransferPin({
          uid:
            req.user.uid,

          currentPin,

          newPin,
        });

      return res.status(200).json({
        success: true,

        message:
          "Your KENT Pay transfer PIN has been changed.",

        ...result,
      });
    } catch (error) {
      console.error(
        "KENT CHANGE TRANSFER PIN ERROR:",
        error.message
      );

      const status =
        error.message.includes(
          "temporarily locked"
        )
          ? 423
          : error.message.includes(
                "incorrect"
              )
            ? 401
            : 400;

      return res.status(status).json({
        success: false,
        message:
          error.message ||
          "Unable to change transfer PIN.",
      });
    }
  }
);

// ============================================================
// SEND MONEY
// ============================================================
//
// POST /api/transfers/send
//
// BODY:
//
// {
//   "bankCode": "044",
//   "accountNumber": "0690000031",
//   "amount": 1000,
//   "narration": "KENT transfer",
//   "pin": "1234"
// }
//
// ============================================================

router.post(
  "/send",
  requireAuth,
  async (
    req,
    res
  ) => {
    try {
      const uid =
        req.user.uid;

      const bankCode =
        String(
          req.body?.bankCode ||
            ""
        ).trim();

      const accountNumber =
        String(
          req.body?.accountNumber ||
            ""
        ).trim();

      const amount =
        Number(
          req.body?.amount
        );

      const narration =
        typeof req.body?.narration ===
        "string"
          ? req.body.narration
              .trim()
              .substring(
                0,
                180
              )
          : "KENT Pay transfer";

      const pin =
        typeof req.body?.pin ===
        "string"
          ? req.body.pin.trim()
          : "";

      const result =
        await createKentTransfer({
          uid,

          bankCode,

          accountNumber,

          amount,

          narration,

          pin,
        });

      return res.status(201).json({
        success: true,

        message:
          "Transfer has been initiated.",

        transfer:
          result,
      });
    } catch (error) {
      console.error(
        "KENT SEND MONEY ERROR:",
        {
          message:
            error?.message ||
            "Unknown error",

          code:
            error?.code ||
            null,

          status:
            error?.response?.status ||
            null,
        }
      );

      const code =
        error?.code ||
        "";

      if (
        code ===
        "TRANSFER_PIN_NOT_SET"
      ) {
        return res.status(409).json({
          success: false,

          code:
            "TRANSFER_PIN_NOT_SET",

          message:
            "Create your KENT Pay transfer PIN before sending money.",
        });
      }

      if (
        code ===
        "TRANSFER_PIN_LOCKED"
      ) {
        return res.status(423).json({
          success: false,

          code:
            "TRANSFER_PIN_LOCKED",

          message:
            "Your transfer PIN is temporarily locked. Please try again later.",
        });
      }

      if (
        code ===
        "TRANSFER_PIN_INCORRECT"
      ) {
        return res.status(401).json({
          success: false,

          code:
            "TRANSFER_PIN_INCORRECT",

          message:
            "Incorrect transfer PIN.",
        });
      }

      const message =
        error?.message ||
        "Unable to initiate transfer.";

      let statusCode =
        400;

      if (
        message.includes(
          "Complete BVN"
        )
      ) {
        statusCode =
          403;
      }

      if (
        message.includes(
          "KENT Pay account is not ready"
        )
      ) {
        statusCode =
          403;
      }

      return res
        .status(statusCode)
        .json({
          success: false,
          message,
        });
    }
  }
);

// ============================================================
// GET TRANSFER STATUS
// ============================================================
//
// GET /api/transfers/status/:transferId
// ============================================================

router.get(
  "/status/:transferId",
  requireAuth,
  async (
    req,
    res
  ) => {
    try {
      const transferId =
        String(
          req.params.transferId ||
            ""
        ).trim();

      if (!transferId) {
        return res.status(400).json({
          success: false,
          message:
            "Transfer ID is required.",
        });
      }

      const result =
        await getKentTransferStatus({
          uid:
            req.user.uid,

          transferId,
        });

      return res.status(200).json({
        success: true,

        transfer:
          result,
      });
    } catch (error) {
      console.error(
        "KENT TRANSFER STATUS ERROR:",
        error.response?.data ||
          error.message
      );

      return res.status(404).json({
        success: false,

        message:
          error.message ||
          "Transfer could not be found.",
      });
    }
  }
);

// ============================================================
// EXPORT
// ============================================================

module.exports =
  router;

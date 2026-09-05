const {
  getKentPayVirtualAccount,
} = require("../services/kentPayService");

// ============================================================
// GET MY KENT PAY ACCOUNT
// ============================================================
//
// GET /api/kent-pay/me
//
// Returns the authenticated user's permanent
// Flutterwave virtual account.
// ============================================================

async function getMyKentPayAccount(req, res) {
  try {
    const uid = req.user.uid;

    const account =
      await getKentPayVirtualAccount(uid);

    if (!account) {
      return res.status(404).json({
        success: false,
        accountReady: false,
        message:
          "Your KENT Pay virtual account has not been created yet.",
      });
    }

    return res.status(200).json({
      success: true,
      accountReady: true,

      account: {
        provider:
          account.provider,

        providerAccountId:
          account.providerAccountId,

        reference:
          account.reference,

        accountNumber:
          account.accountNumber,

        accountName:
          account.accountName,

        bankName:
          account.bankName,

        accountType:
          account.accountType,

        currency:
          account.currency,

        status:
          account.status,
      },
    });
  } catch (error) {
    console.error(
      "GET KENT PAY ACCOUNT ERROR:",
      error
    );

    return res.status(500).json({
      success: false,
      accountReady: false,
      message:
        "Unable to retrieve your KENT Pay account.",
    });
  }
}

// ============================================================
// GET MY KENT PAY STATUS
// ============================================================
//
// GET /api/kent-pay/status
//
// Used by the Flutter application to determine
// whether KENT Pay is ready.
// ============================================================

async function getMyKentPayStatus(req, res) {
  try {
    const uid = req.user.uid;

    const account =
      await getKentPayVirtualAccount(uid);

    if (!account) {
      return res.status(200).json({
        success: true,

        kentPayActivated: false,

        accountReady: false,

        account: null,
      });
    }

    const accountReady =
      account.status === "active";

    return res.status(200).json({
      success: true,

      kentPayActivated:
        accountReady,

      accountReady,

      account: {
        accountNumber:
          account.accountNumber,

        accountName:
          account.accountName,

        bankName:
          account.bankName,

        accountType:
          account.accountType,

        currency:
          account.currency,

        status:
          account.status,
      },
    });
  } catch (error) {
    console.error(
      "GET KENT PAY STATUS ERROR:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Unable to retrieve KENT Pay status.",
    });
  }
}

// ============================================================
// EXPORTS
// ============================================================

module.exports = {
  getMyKentPayAccount,
  getMyKentPayStatus,
};
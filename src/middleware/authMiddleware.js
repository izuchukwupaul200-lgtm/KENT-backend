const { auth } = require("../../firebaseAdmin");

// ============================================================
// FIREBASE AUTHENTICATION MIDDLEWARE
// ============================================================
//
// Expects:
// Authorization: Bearer <Firebase ID token>
//
// After successful verification:
// req.user = decoded Firebase user
// ============================================================

async function authenticateUser(req, res, next) {
  try {
    const authorization =
      req.headers.authorization;

    if (
      !authorization ||
      !authorization.startsWith("Bearer ")
    ) {
      return res.status(401).json({
        success: false,
        message:
          "Authentication required.",
      });
    }

    const idToken =
      authorization.substring(7).trim();

    if (!idToken) {
      return res.status(401).json({
        success: false,
        message:
          "Authentication token is missing.",
      });
    }

    const decodedToken =
      await auth.verifyIdToken(idToken);

    req.user = decodedToken;

    next();
  } catch (error) {
    console.error(
      "AUTHENTICATION ERROR:",
      error.message
    );

    return res.status(401).json({
      success: false,
      message:
        "Invalid or expired authentication token.",
    });
  }
}

module.exports = authenticateUser;
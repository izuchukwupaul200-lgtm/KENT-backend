const axios = require("axios");

const SENDCHAMP_BASE_URL =
  process.env.SENDCHAMP_BASE_URL || "https://api.sendchamp.com/api/v1";

const SENDCHAMP_API_KEY = process.env.SENDCHAMP_API_KEY;

async function sendSMS({
  phoneNumber,
  message,
  route = "non_dnd",
}) {
  if (!SENDCHAMP_API_KEY) {
    throw new Error("SENDCHAMP_API_KEY is not configured");
  }

  if (!phoneNumber) {
    throw new Error("Phone number is required");
  }

  if (!message) {
    throw new Error("SMS message is required");
  }

  console.log("======================================");
  console.log("KENT SENDCHAMP OTP REQUEST");
  console.log("======================================");
  console.log("Phone:", phoneNumber);
  console.log("Route:", route);
  console.log("Message:", message);

  try {
    const url = SENDCHAMP_BASE_URL + "/sms/send";

    const response = await axios.post(
      url,
      {
        to: [phoneNumber],
        message: message,
        sender_name: "KentPay",
        route: route,
      },
      {
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          Authorization: "Bearer " + SENDCHAMP_API_KEY,
        },
        timeout: 10000,
      }
    );

    console.log("SENDCHAMP STATUS:", response.status);
    console.log("SENDCHAMP RESPONSE:", response.data);
    console.log("======================================");

    return response.data;
  } catch (error) {
    console.error("======================================");
    console.error("SENDCHAMP SMS ERROR");
    console.error("======================================");

    if (error.response) {
      console.error("STATUS:", error.response.status);
      console.error("RESPONSE:", error.response.data);
      console.error("HEADERS:", error.response.headers);
    } else if (error.request) {
      console.error(
        "SENDCHAMP REQUEST WAS SENT BUT NO RESPONSE WAS RECEIVED."
      );
      console.error("REQUEST ERROR:", error.message);
    } else {
      console.error("REQUEST SETUP ERROR:", error.message);
    }

    console.error("======================================");

    throw error;
  }
}

module.exports = {
  sendSMS,
};
const dotenv = require('dotenv');

dotenv.config();

const PORT = process.env.PORT || 5000;
const GNEWS_API_KEY = process.env.GNEWS_API_KEY;

if (!GNEWS_API_KEY) {
  throw new Error('GNEWS_API_KEY is missing from .env');
}

module.exports = {
  PORT,
  GNEWS_API_KEY,
};
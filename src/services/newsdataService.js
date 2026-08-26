const axios = require('axios');

const NEWSDATA_API_KEY = process.env.NEWSDATA_API_KEY;

const NEWSDATA_URL = 'https://newsdata.io/api/1';

async function getTopHeadlines({
  country = 'ng',
  lang = 'en',
  max = 10,
}) {
  const response = await axios.get(
    `${NEWSDATA_URL}/latest`,
    {
      params: {
        apikey: NEWSDATA_API_KEY,
        country,
        language: lang,
        size: max,
      },
      timeout: 15000,
    }
  );

  return response.data;
}

async function searchNews({
  query,
  lang = 'en',
  max = 10,
}) {
  const response = await axios.get(
    `${NEWSDATA_URL}/latest`,
    {
      params: {
        apikey: NEWSDATA_API_KEY,
        q: query,
        language: lang,
        size: max,
      },
      timeout: 15000,
    }
  );

  return response.data;
}

module.exports = {
  getTopHeadlines,
  searchNews,
};

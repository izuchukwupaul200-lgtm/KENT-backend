const axios = require('axios');

const CURRENTS_API_KEY = process.env.CURRENTS_API_KEY;

const CURRENTS_URL = 'https://api.currentsapi.services/v1';

async function getTopHeadlines({
  country = 'ng',
  lang = 'en',
  max = 10,
}) {
  const response = await axios.get(
    `${CURRENTS_URL}/latest-news`,
    {
      params: {
        language: lang,
        country,
        page_size: max,
      },
      headers: {
        Authorization: CURRENTS_API_KEY,
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
    `${CURRENTS_URL}/search`,
    {
      params: {
        keywords: query,
        language: lang,
        page_size: max,
      },
      headers: {
        Authorization: CURRENTS_API_KEY,
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

const axios = require('axios');
const { GNEWS_API_KEY } = require('../config/env');

const GNEWS_URL = 'https://gnews.io/api/v4';

async function getTopHeadlines({
  category = 'general',
  country = 'ng',
  lang = 'en',
  max = 10,
}) {
  const response = await axios.get(`${GNEWS_URL}/top-headlines`, {
    params: {
      category,
      country,
      lang,
      max,
      apikey: GNEWS_API_KEY,
    },
  });

  return response.data;
}

async function searchNews({
  query,
  lang = 'en',
  max = 10,
}) {
  const response = await axios.get(`${GNEWS_URL}/search`, {
    params: {
      q: query,
      lang,
      max,
      apikey: GNEWS_API_KEY,
    },
  });

  return response.data;
}

module.exports = {
  getTopHeadlines,
  searchNews,
};
const gnewsService = require('../services/gnewsService');

async function getNews(req, res) {
  try {
    const {
      category = 'general',
      country = 'ng',
      lang = 'en',
      max = 10,
    } = req.query;

    const data = await gnewsService.getTopHeadlines({
      category,
      country,
      lang,
      max: Number(max),
    });

    res.json({
      success: true,
      totalArticles: data.totalArticles || 0,
      articles: data.articles || [],
    });
  } catch (error) {
    console.error(
      'News error:',
      error.response?.data || error.message
    );

    res.status(error.response?.status || 500).json({
      success: false,
      message: 'Unable to retrieve news',
    });
  }
}

async function searchNews(req, res) {
  try {
    const { q, lang = 'en', max = 10 } = req.query;

    if (!q || !q.trim()) {
      return res.status(400).json({
        success: false,
        message: 'Search query is required',
      });
    }

    const data = await gnewsService.searchNews({
      query: q.trim(),
      lang,
      max: Number(max),
    });

    res.json({
      success: true,
      totalArticles: data.totalArticles || 0,
      articles: data.articles || [],
    });
  } catch (error) {
    console.error(
      'Search error:',
      error.response?.data || error.message
    );

    res.status(error.response?.status || 500).json({
      success: false,
      message: 'Unable to search news',
    });
  }
}

module.exports = {
  getNews,
  searchNews,
};
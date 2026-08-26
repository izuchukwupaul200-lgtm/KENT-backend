const gnewsService = require('../services/gnewsService');
const currentsService = require('../services/currentsService');
const newsdataService = require('../services/newsdataService');

function normalizeGNews(article) {
  return {
    title: article.title || '',
    description: article.description || '',
    content: article.content || '',
    url: article.url || '',
    image: article.image || '',
    publishedAt: article.publishedAt || '',
    source: article.source || {
      name: 'GNews',
      url: '',
    },
  };
}

function normalizeCurrents(article) {
  return {
    title: article.title || '',
    description: article.description || '',
    content: article.description || '',
    url: article.url || '',
    image: article.image || '',
    publishedAt: article.published || '',
    source: {
      name: article.author || 'Currents',
      url: article.url || '',
    },
  };
}

function normalizeNewsData(article) {
  return {
    title: article.title || '',
    description: article.description || '',
    content: article.content || article.description || '',
    url: article.link || '',
    image: article.image_url || '',
    publishedAt: article.pubDate || '',
    source: {
      name:
        article.source_name ||
        article.source_id ||
        'NewsData.io',
      url: article.source_url || '',
    },
  };
}

function removeDuplicates(articles) {
  const seen = new Set();

  return articles.filter((article) => {
    const key =
      article.url?.trim().toLowerCase() ||
      article.title?.trim().toLowerCase();

    if (!key || seen.has(key)) {
      return false;
    }

    seen.add(key);
    return true;
  });
}

async function getNews(req, res) {
  const {
    category = 'general',
    country = 'ng',
    lang = 'en',
    max = 10,
  } = req.query;

  const requestedMax = Number(max) || 10;

  const results = await Promise.allSettled([
    gnewsService.getTopHeadlines({
      category,
      country,
      lang,
      max: requestedMax,
    }),

    currentsService.getTopHeadlines({
      country,
      lang,
      max: requestedMax,
    }),

    newsdataService.getTopHeadlines({
      country,
      lang,
      max: requestedMax,
    }),
  ]);

  let articles = [];

  if (results[0].status === 'fulfilled') {
    const data = results[0].value;

    const gnewsArticles = (data.articles || [])
      .map(normalizeGNews);

    articles.push(...gnewsArticles);

    console.log(
      `KENT: GNews returned ${gnewsArticles.length} articles`
    );
  } else {
    console.error(
      'KENT: GNews failed:',
      results[0].reason?.response?.data ||
        results[0].reason?.message
    );
  }

  if (results[1].status === 'fulfilled') {
    const data = results[1].value;

    const currentsArticles = (data.news || [])
      .map(normalizeCurrents);

    articles.push(...currentsArticles);

    console.log(
      `KENT: Currents returned ${currentsArticles.length} articles`
    );
  } else {
    console.error(
      'KENT: Currents failed:',
      results[1].reason?.response?.data ||
        results[1].reason?.message
    );
  }

  if (results[2].status === 'fulfilled') {
    const data = results[2].value;

    const newsDataArticles = (data.results || [])
      .map(normalizeNewsData);

    articles.push(...newsDataArticles);

    console.log(
      `KENT: NewsData.io returned ${newsDataArticles.length} articles`
    );
  } else {
    console.error(
      'KENT: NewsData.io failed:',
      results[2].reason?.response?.data ||
        results[2].reason?.message
    );
  }

  const uniqueArticles = removeDuplicates(articles);

  console.log(
    `KENT: Combined ${uniqueArticles.length} unique articles`
  );

  return res.status(200).json({
    success: true,
    totalArticles: uniqueArticles.length,
    articles: uniqueArticles.slice(0, requestedMax),
  });
}

async function searchNews(req, res) {
  const {
    q,
    lang = 'en',
    max = 10,
  } = req.query;

  if (!q || !q.trim()) {
    return res.status(400).json({
      success: false,
      message: 'Search query is required',
    });
  }

  const requestedMax = Number(max) || 10;

  const results = await Promise.allSettled([
    gnewsService.searchNews({
      query: q.trim(),
      lang,
      max: requestedMax,
    }),

    currentsService.searchNews({
      query: q.trim(),
      lang,
      max: requestedMax,
    }),

    newsdataService.searchNews({
      query: q.trim(),
      lang,
      max: requestedMax,
    }),
  ]);

  let articles = [];

  if (results[0].status === 'fulfilled') {
    articles.push(
      ...(results[0].value?.articles || [])
        .map(normalizeGNews)
    );
  } else {
    console.error(
      'KENT: GNews search failed:',
      results[0].reason?.response?.data ||
        results[0].reason?.message
    );
  }

  if (results[1].status === 'fulfilled') {
    articles.push(
      ...(results[1].value?.news || [])
        .map(normalizeCurrents)
    );
  } else {
    console.error(
      'KENT: Currents search failed:',
      results[1].reason?.response?.data ||
        results[1].reason?.message
    );
  }

  if (results[2].status === 'fulfilled') {
    articles.push(
      ...(results[2].value?.results || [])
        .map(normalizeNewsData)
    );
  } else {
    console.error(
      'KENT: NewsData.io search failed:',
      results[2].reason?.response?.data ||
        results[2].reason?.message
    );
  }

  const uniqueArticles = removeDuplicates(articles);

  return res.status(200).json({
    success: true,
    totalArticles: uniqueArticles.length,
    articles: uniqueArticles.slice(0, requestedMax),
  });
}

module.exports = {
  getNews,
  searchNews,
};
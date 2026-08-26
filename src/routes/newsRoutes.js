const express = require('express');
const {
  getNews,
  searchNews,
} = require('../controllers/newsController');

const router = express.Router();

router.get('/', getNews);

router.get('/search', searchNews);

module.exports = router;
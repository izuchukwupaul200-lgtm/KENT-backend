const express = require('express');
const cors = require('cors');

const { PORT } = require('./config/env');
const newsRoutes = require('./routes/newsRoutes');

const app = express();

app.use(cors());
app.use(express.json());

app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    service: 'KENT News API',
    status: 'online',
  });
});

app.use('/api/news', newsRoutes);

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found',
  });
});

app.listen(PORT, () => {
  console.log(`KENT News API running on port ${PORT}`);
});
import 'dotenv/config';

import express from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { analyze } from './services/analyze.js';

const app = express();
const PORT = process.env.PORT || 5000;

app.set('trust proxy', 1);
app.use(cors({ origin: process.env.CLIENT_ORIGIN || '*' }));
app.use(express.json({ limit: '20kb' }));

// There is no signup, so anyone can call the API. Rate limiting keeps AI costs under control.
app.use(
  '/api',
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 60,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests. Please try again in a few minutes.' },
  })
);

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    ai: process.env.ANTHROPIC_API_KEY ? 'enabled' : 'rules-only',
    safeBrowsing: process.env.GOOGLE_SAFE_BROWSING_KEY ? 'enabled' : 'off',
  });
});

const MAX_MESSAGE_CHARS = 3000;

// Paste a message, get a verdict. Nothing is saved.
app.post('/api/check', async (req, res, next) => {
  try {
    const message = typeof req.body?.message === 'string' ? req.body.message.trim() : '';
    if (message.length < 3) {
      return res.status(400).json({ error: 'Please paste the message you want to check.' });
    }
    if (message.length > MAX_MESSAGE_CHARS) {
      return res.status(400).json({
        error: `That message is too long. Please paste up to ${MAX_MESSAGE_CHARS} characters.`,
      });
    }
    res.json(await analyze(message));
  } catch (err) {
    next(err);
  }
});

app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(err);
  const status = err.status && err.status < 500 ? err.status : 500;
  res.status(status).json({
    error: status < 500 ? err.message : 'Something went wrong on our side. Please try again.',
  });
});

app.listen(PORT, () => {
  console.log(`ScamShield API running on http://localhost:${PORT}`);
});

export default app;

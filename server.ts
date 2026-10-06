/**
 * CYBERNEXUS SOC - Full-Stack Express Server & Vite Dev Server Mount
 * Listens on port 3000 (0.0.0.0).
 */

import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { apiRouter } from './server/routes';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = parseInt(process.env.PORT || '3000', 10);

  // Parse JSON payloads up to 5MB
  app.use(express.json({ limit: '5mb' }));

  // Security Headers
  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    next();
  });

  // Mount API Router
  app.use('/api', apiRouter);

  // Mount Vite development middlewares or static files
  if (process.env.NODE_ENV === 'production') {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (_req, res) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  } else {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[CYBERNEXUS SOC] Server listening on http://0.0.0.0:${PORT}`);
    console.log(`[CYBERNEXUS SOC] Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`[CYBERNEXUS SOC] Tagline: Detect. Investigate. Explain. Respond.`);
  });
}

startServer().catch(err => {
  console.error('[CYBERNEXUS SOC] Failed to start server:', err);
  process.exit(1);
});

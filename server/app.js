import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import {
  captureRequestInspection,
  injectInspectionIntoHtml,
  parseTrustProxySetting,
} from './headerInspector.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEFAULT_ROOT_DIR = path.resolve(__dirname, '..');

/**
 * Create an Express application configured for live document HTTP header inspection.
 * Serves only static frontend assets (index.html, css/, js/, favicon.svg) and never persists or logs headers.
 */
export function createApp({
  rootDir = DEFAULT_ROOT_DIR,
  trustProxy = process.env.TRUST_PROXY,
  corsOrigin = process.env.CORS_ORIGIN || '',
} = {}) {
  const app = express();
  app.disable('x-powered-by');

  const trustProxySetting = parseTrustProxySetting(trustProxy);
  app.set('trust proxy', trustProxySetting);

  const indexPath = path.join(rootDir, 'index.html');
  const htmlTemplate = fs.readFileSync(indexPath, 'utf8');

  // Shared security headers for HTML and JSON responses
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('X-Frame-Options', 'DENY');
    next();
  });

  // Document navigation routes: capture initial HTTP request headers and inject safely into HTML
  const serveInspectedDocument = (req, res) => {
    const payload = captureRequestInspection(req, {
      mode: 'server-document',
      trustProxySetting,
    });
    const renderedHtml = injectInspectionIntoHtml(htmlTemplate, payload);

    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' https://ipwho.is https://get.geojs.io https://freeipapi.com https://api64.ipify.org; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    );
    res.status(200).send(renderedHtml);
  };

  app.get('/', serveInspectedDocument);
  app.get('/index.html', serveInspectedDocument);

  // Optional secondary XHR/fetch inspection endpoint (explicitly labeled as api-endpoint, not document load)
  const allowedOrigins = String(corsOrigin)
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean);

  app.options('/api/headers', (req, res) => {
    const reqOrigin = req.get('origin');
    if (reqOrigin && allowedOrigins.includes(reqOrigin)) {
      res.setHeader('Access-Control-Allow-Origin', reqOrigin);
      res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Accept');
      res.setHeader('Vary', 'Origin');
    }
    res.status(204).end();
  });

  app.get('/api/headers', (req, res) => {
    const reqOrigin = req.get('origin');
    if (reqOrigin && allowedOrigins.includes(reqOrigin)) {
      res.setHeader('Access-Control-Allow-Origin', reqOrigin);
      res.setHeader('Vary', 'Origin');
    }

    const payload = captureRequestInspection(req, {
      mode: 'api-endpoint',
      trustProxySetting,
    });
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.status(200).json(payload);
  });

  app.get('/health', (_req, res) => {
    res.status(200).json({ status: 'ok', mode: 'server-header-inspector' });
  });

  // Explicitly expose ONLY public frontend static assets (never server/, tests/, package.json, or .env)
  app.use('/css', express.static(path.join(rootDir, 'css')));
  app.use('/js', express.static(path.join(rootDir, 'js')));
  app.get('/favicon.svg', (_req, res) => {
    res.sendFile(path.join(rootDir, 'favicon.svg'));
  });

  app.use((_req, res) => {
    res.status(404).json({ error: 'Not found' });
  });

  return app;
}

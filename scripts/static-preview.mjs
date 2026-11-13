/**
 * Lightweight zero-dependency static file server for testing Static GitHub Pages Mode locally.
 * Serves index.html unmodified (without server-side header injection) just like GitHub Pages.
 */
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');
const PORT = Number.parseInt(process.env.STATIC_PORT || '4173', 10);
const HOST = process.env.HOST || '127.0.0.1';

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json; charset=utf-8',
};

const ALLOWED_STATIC_PATHS = new Set(['/', '/index.html', '/favicon.svg']);
const ALLOWED_PREFIXES = ['/css/', '/js/'];

const server = http.createServer((req, res) => {
  const reqUrl = new URL(req.url || '/', `http://${HOST}:${PORT}`);
  const pathname = reqUrl.pathname;

  const allowed =
    ALLOWED_STATIC_PATHS.has(pathname) ||
    ALLOWED_PREFIXES.some((prefix) => pathname.startsWith(prefix));

  if (!allowed) {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not found');
    return;
  }

  const relativePath = pathname === '/' ? 'index.html' : pathname.slice(1);
  const fullPath = path.resolve(ROOT_DIR, relativePath);
  if (!fullPath.startsWith(ROOT_DIR)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  fs.readFile(fullPath, (err, content) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Not found');
      return;
    }
    const ext = path.extname(fullPath).toLowerCase();
    res.writeHead(200, {
      'Content-Type': MIME_TYPES[ext] || 'application/octet-stream',
      'Cache-Control': 'no-store',
    });
    res.end(content);
  });
});

server.listen(PORT, HOST, () => {
  console.log(`Static GitHub Pages preview server running at http://${HOST}:${PORT}`);
});

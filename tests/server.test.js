import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createApp } from '../server/app.js';
import { REDACTED_VALUE } from '../server/headerInspector.js';
import { parseInjectedInspectionPayload } from '../js/lib/headerUtils.js';

function startTestServer(appOptions = {}) {
  const app = createApp(appOptions);
  const server = http.createServer(app);
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      resolve({
        server,
        baseUrl: `http://127.0.0.1:${addr.port}`,
      });
    });
  });
}

test('Express server injects captured GET / headers, redacts Cookie/Authorization, and prevents leaking server files', async (t) => {
  const { server, baseUrl } = await startTestServer({ trustProxy: false });
  t.after(() => server.close());

  const res = await fetch(`${baseUrl}/`, {
    headers: {
      'User-Agent': 'SecurityLabTestAgent/2.0 </script><img src=x onerror=alert(1)>',
      'Accept-Language': 'en-GB,en;q=0.8',
      Cookie: 'secret_session=abc123',
      Authorization: 'Bearer top-secret',
      'X-Forwarded-For': '203.0.113.199',
    },
  });

  assert.equal(res.status, 200);
  assert.equal(res.headers.get('cache-control'), 'no-store, no-cache, must-revalidate');
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');

  const html = await res.text();
  // Ensure raw unescaped XSS tag never landed in HTML
  assert.equal(html.includes('</script><img'), false);

  const match = html.match(/<script id="__INITIAL_REQUEST_INSPECTION__" type="application\/json">([\s\S]*?)<\/script>/);
  assert.ok(match, 'Should embed JSON inspection payload script');

  const payload = parseInjectedInspectionPayload(match[1]);
  assert.ok(payload);
  assert.equal(payload.mode, 'server-document');
  assert.equal(payload.method, 'GET');
  assert.equal(payload.path, '/');
  assert.equal(payload.trustProxyEnabled, false);
  // Since TRUST_PROXY is false, remoteAddress must NOT trust arbitrary X-Forwarded-For
  assert.notEqual(payload.remoteAddress, '203.0.113.199');

  const cookieHeader = payload.headers.find((h) => h.name.toLowerCase() === 'cookie');
  const authHeader = payload.headers.find((h) => h.name.toLowerCase() === 'authorization');
  assert.equal(cookieHeader.redacted, true);
  assert.equal(cookieHeader.value, REDACTED_VALUE);
  assert.equal(authHeader.redacted, true);
  assert.equal(authHeader.value, REDACTED_VALUE);

  const uaHeader = payload.headers.find((h) => h.name.toLowerCase() === 'user-agent');
  assert.match(uaHeader.value, /SecurityLabTestAgent\/2\.0/);

  // Ensure server code & package.json are NOT served publicly
  const pkgRes = await fetch(`${baseUrl}/package.json`);
  assert.equal(pkgRes.status, 404);
  const srvRes = await fetch(`${baseUrl}/server/app.js`);
  assert.equal(srvRes.status, 404);

  // Ensure public CSS/JS assets are served cleanly
  const cssRes = await fetch(`${baseUrl}/css/tokens.css`);
  assert.equal(cssRes.status, 200);
});

test('GET /api/headers labels itself as api-endpoint and respects CORS_ORIGIN configuration', async (t) => {
  const { server, baseUrl } = await startTestServer({
    trustProxy: '1',
    corsOrigin: 'https://abhimanyu-wrk.github.io',
  });
  t.after(() => server.close());

  const res = await fetch(`${baseUrl}/api/headers`, {
    headers: {
      Origin: 'https://abhimanyu-wrk.github.io',
      'X-Forwarded-For': '198.51.100.25',
      Cookie: 'private=xyz',
    },
  });

  assert.equal(res.status, 200);
  assert.equal(res.headers.get('access-control-allow-origin'), 'https://abhimanyu-wrk.github.io');

  const json = await res.json();
  assert.equal(json.mode, 'api-endpoint');
  assert.equal(json.trustProxyEnabled, true);
  assert.equal(json.remoteAddress, '198.51.100.25');
  const cookie = json.headers.find((h) => h.name.toLowerCase() === 'cookie');
  assert.equal(cookie.redacted, true);
  assert.equal(cookie.value, REDACTED_VALUE);
});

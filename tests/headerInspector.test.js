import test from 'node:test';
import assert from 'node:assert/strict';
import {
  REDACTED_VALUE,
  captureRequestInspection,
  extractSanitizedHeaders,
  injectInspectionIntoHtml,
  parseTrustProxySetting,
  serializeSafeHtmlJson,
} from '../server/headerInspector.js';
import { parseInjectedInspectionPayload } from '../js/lib/headerUtils.js';

test('extractSanitizedHeaders preserves casing and redacts sensitive headers by default', () => {
  const rawHeaders = [
    'User-Agent',
    'Mozilla/5.0 TestBrowser',
    'Accept-Language',
    'en-US,en;q=0.9',
    'Cookie',
    'session=secret123',
    'Authorization',
    'Bearer super-secret-token',
    'Proxy-Authorization',
    'Basic Zm9vOmJhcg==',
    'Sec-Fetch-Mode',
    'navigate',
  ];

  const { headers, redactedHeaders } = extractSanitizedHeaders(rawHeaders);
  assert.deepEqual(redactedHeaders, ['Cookie', 'Authorization', 'Proxy-Authorization']);

  const ua = headers.find((h) => h.name === 'User-Agent');
  assert.equal(ua.value, 'Mozilla/5.0 TestBrowser');
  assert.equal(ua.redacted, false);

  const cookie = headers.find((h) => h.name === 'Cookie');
  assert.equal(cookie.value, REDACTED_VALUE);
  assert.equal(cookie.redacted, true);

  const auth = headers.find((h) => h.name === 'Authorization');
  assert.equal(auth.value, REDACTED_VALUE);
  assert.equal(auth.redacted, true);
});

test('serializeSafeHtmlJson and injectInspectionIntoHtml neutralize </script> XSS payloads and $ tokens', () => {
  const template =
    '<html><body><script id="__INITIAL_REQUEST_INSPECTION__" type="application/json">null</script></body></html>';

  const maliciousPayload = captureRequestInspection(
    {
      method: 'GET',
      originalUrl: '/',
      httpVersion: '1.1',
      socket: { remoteAddress: '127.0.0.1' },
      rawHeaders: ['User-Agent', '</script><script>alert(1)</script> $& $$ $1'],
    },
    { mode: 'server-document', trustProxySetting: false }
  );

  const serialized = serializeSafeHtmlJson(maliciousPayload);
  assert.equal(serialized.includes('</script>'), false);
  assert.equal(serialized.includes('\\u003c/script\\u003e'), true);

  const html = injectInspectionIntoHtml(template, maliciousPayload);
  const match = html.match(/<script id="__INITIAL_REQUEST_INSPECTION__" type="application\/json">([\s\S]*?)<\/script>/);
  assert.ok(match);

  const parsed = parseInjectedInspectionPayload(match[1]);
  assert.ok(parsed);
  assert.equal(parsed.headers[0].value, '</script><script>alert(1)</script> $& $$ $1');
});

test('parseTrustProxySetting defaults to false and parses proxy values cleanly', () => {
  assert.equal(parseTrustProxySetting(undefined), false);
  assert.equal(parseTrustProxySetting('false'), false);
  assert.equal(parseTrustProxySetting('true'), true);
  assert.equal(parseTrustProxySetting('1'), 1);
  assert.equal(parseTrustProxySetting('loopback'), 'loopback');
  assert.deepEqual(parseTrustProxySetting('127.0.0.1, 10.0.0.0/8'), ['127.0.0.1', '10.0.0.0/8']);
});

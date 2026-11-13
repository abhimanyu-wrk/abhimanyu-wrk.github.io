import test from 'node:test';
import assert from 'node:assert/strict';
import { parseUserAgent } from '../js/lib/uaParser.js';

test('parseUserAgent detects Chrome, Edge, Firefox, Safari, and mobile OSes accurately', () => {
  const edgeWin = parseUserAgent(
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
    { platform: 'Windows', platformVersion: '15.0.0' }
  );
  assert.equal(edgeWin.browserName, 'Microsoft Edge');
  assert.equal(edgeWin.browserVersion, '131.0.0.0');
  assert.equal(edgeWin.osName, 'Windows 11');
  assert.equal(edgeWin.uaReductionDetected, true);

  const firefoxLinux = parseUserAgent(
    'Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0'
  );
  assert.equal(firefoxLinux.browserName, 'Firefox');
  assert.equal(firefoxLinux.browserVersion, '132.0');
  assert.equal(firefoxLinux.osName, 'Linux');

  const safariMac = parseUserAgent(
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15'
  );
  assert.equal(safariMac.browserName, 'Safari');
  assert.equal(safariMac.browserVersion, '18.1');
  assert.match(safariMac.osName, /macOS/);

  const iosSafari = parseUserAgent(
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1'
  );
  assert.equal(iosSafari.browserName, 'Safari');
  assert.equal(iosSafari.osName, 'iOS 18.0');

  const emptyUa = parseUserAgent('');
  assert.equal(emptyUa.browserName, 'Unknown');
  assert.equal(emptyUa.osName, 'Unknown');
});

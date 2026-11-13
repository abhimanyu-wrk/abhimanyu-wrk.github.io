import test from 'node:test';
import assert from 'node:assert/strict';
import {
  formatBatterySeconds,
  normalizeBatteryInfo,
  normalizeFreeIpApiPayload,
  normalizeGeoJsPayload,
  normalizeIpWhoIsPayload,
  normalizeIpifyPayload,
} from '../js/lib/fingerprintUtils.js';

test('normalizeBatteryInfo never fabricates 0 for unsupported or Infinity values', () => {
  const unsupported = normalizeBatteryInfo(null, { supported: false });
  assert.equal(unsupported.supported, false);
  assert.equal(unsupported.percentage, 'Not supported by this browser');
  assert.equal(unsupported.chargingStatus, 'Not supported by this browser');

  const charging = normalizeBatteryInfo({
    level: 0.78,
    charging: true,
    chargingTime: 1800,
    dischargingTime: Infinity,
  });
  assert.equal(charging.supported, true);
  assert.equal(charging.percentage, '78%');
  assert.equal(charging.chargingTime, '30m');
  assert.equal(charging.dischargingTime, 'N/A (currently charging)');

  const full = normalizeBatteryInfo({
    level: 1,
    charging: true,
    chargingTime: 0,
    dischargingTime: Infinity,
  });
  assert.equal(full.chargingTime, 'Fully charged');
  assert.equal(formatBatterySeconds(Infinity, 'Not exposed'), 'Not exposed');
  assert.equal(formatBatterySeconds(0, 'Not exposed'), 'Not exposed');
  assert.equal(formatBatterySeconds(5400), '1h 30m');
});

test('normalizeIpWhoIsPayload and normalizeIpifyPayload handle valid, partial, and error payloads', () => {
  const valid = normalizeIpWhoIsPayload({
    success: true,
    ip: '198.51.100.42',
    type: 'IPv4',
    country: 'India',
    country_code: 'IN',
    region: 'Karnataka',
    city: 'Bengaluru',
    latitude: 12.9716,
    longitude: 77.5946,
    connection: { asn: 12345, isp: 'Example Fiber' },
  });
  assert.equal(valid.ok, true);
  assert.equal(valid.ip, '198.51.100.42');
  assert.equal(valid.country, 'India (IN)');
  assert.match(valid.isp, /Example Fiber/);
  assert.match(valid.coordinates, /12\.9716, 77\.5946/);

  const rateLimited = normalizeIpWhoIsPayload({
    success: false,
    message: 'You have hit the monthly limit',
  });
  assert.equal(rateLimited.ok, false);
  assert.equal(rateLimited.errorType, 'rate-limit');

  const invalid = normalizeIpWhoIsPayload({ foo: 'bar' });
  assert.equal(invalid.ok, false);
  assert.equal(invalid.errorType, 'invalid-response');

  const fallback = normalizeIpifyPayload({ ip: '203.0.113.9' });
  assert.equal(fallback.ok, true);
  assert.equal(fallback.partial, true);
  assert.equal(fallback.ip, '203.0.113.9');

  const geojs = normalizeGeoJsPayload({
    ip: '198.51.100.42',
    country: 'India',
    country_code: 'IN',
    region: 'Tamil Nadu',
    city: 'Chennai',
    latitude: '13.0895',
    longitude: '80.2739',
    asn: 53813,
    organization_name: 'Example Net',
    timezone: 'Asia/Kolkata',
  });
  assert.equal(geojs.ok, true);
  assert.equal(geojs.provider, 'get.geojs.io');
  assert.equal(geojs.city, 'Chennai');
  assert.match(geojs.coordinates, /13\.0895, 80\.2739/);

  const freeip = normalizeFreeIpApiPayload({
    ipVersion: 4,
    ipAddress: '198.51.100.42',
    countryName: 'India',
    countryCode: 'IN',
    regionName: 'Tamil Nadu',
    cityName: 'Chennai',
    latitude: 13.0827,
    longitude: 80.2707,
    asn: '53813',
    asnOrganization: 'Example Net',
    timeZones: ['Asia/Kolkata'],
  });
  assert.equal(freeip.ok, true);
  assert.equal(freeip.provider, 'freeipapi.com');
  assert.equal(freeip.country, 'India (IN)');
});

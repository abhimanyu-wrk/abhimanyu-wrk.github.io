/**
 * Pure formatting and normalization utilities for the Browser Fingerprinting Simulator.
 * Handles missing/unsupported browser capabilities strictly without fabricating zero values.
 */

/**
 * Format duration in seconds from Battery Status API (`chargingTime` / `dischargingTime`).
 * Never returns "0" for Infinity or unavailable values.
 * @param {number|null|undefined} seconds
 * @param {string} unavailableLabel
 * @returns {string}
 */
export function formatBatterySeconds(seconds, unavailableLabel = 'Unavailable / Not applicable') {
  if (typeof seconds !== 'number' || !Number.isFinite(seconds) || seconds < 0) {
    return unavailableLabel;
  }
  if (seconds === 0) {
    return unavailableLabel;
  }
  const totalMinutes = Math.round(seconds / 60);
  if (totalMinutes < 1) {
    return `${Math.round(seconds)}s`;
  }
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  if (hours === 0) {
    return `${minutes}m`;
  }
  return `${hours}h ${minutes}m`;
}

/**
 * Normalize BatteryManager-like object into displayable fields.
 * @param {object|null} battery
 * @param {object} [options]
 * @param {boolean} [options.supported]
 * @param {string|null} [options.errorReason]
 */
export function normalizeBatteryInfo(battery, { supported = true, errorReason = null } = {}) {
  if (!supported) {
    return {
      supported: false,
      status: 'unsupported',
      percentage: 'Not supported by this browser',
      chargingStatus: 'Not supported by this browser',
      chargingTime: 'Not supported by this browser',
      dischargingTime: 'Not supported by this browser',
      note:
        errorReason ||
        'Many browsers (including Firefox and Safari) intentionally removed the Battery Status API because battery level and drain timing can act as short-term tracking identifiers.',
    };
  }

  if (!battery || typeof battery.level !== 'number' || Number.isNaN(battery.level)) {
    return {
      supported: false,
      status: 'unavailable',
      percentage: 'Unavailable',
      chargingStatus: 'Unavailable',
      chargingTime: 'Unavailable',
      dischargingTime: 'Unavailable',
      note: errorReason || 'Battery API returned incomplete telemetry.',
    };
  }

  const pct = `${Math.round(Math.min(1, Math.max(0, battery.level)) * 100)}%`;
  const isCharging = typeof battery.charging === 'boolean' ? battery.charging : null;
  const chargingStatus =
    isCharging === null ? 'Unknown' : isCharging ? 'Charging / AC Power' : 'Discharging (On Battery)';

  const chargingTime =
    isCharging === true
      ? battery.level >= 1
        ? 'Fully charged'
        : formatBatterySeconds(battery.chargingTime, 'Time to full not exposed')
      : 'N/A (not charging)';

  const dischargingTime =
    isCharging === false
      ? formatBatterySeconds(battery.dischargingTime, 'Remaining time not exposed')
      : 'N/A (currently charging)';

  return {
    supported: true,
    status: 'available',
    percentage: pct,
    chargingStatus,
    chargingTime,
    dischargingTime,
    note:
      'Desktop systems or privacy-hardened browsers often report 100% and "Charging" continuously.',
  };
}

/**
 * Normalize an `ipwho.is` JSON payload into our structured Network Info format.
 * Validates payload carefully and handles missing fields cleanly.
 * @param {unknown} data
 */
export function normalizeIpWhoIsPayload(data) {
  if (!data || typeof data !== 'object') {
    return { ok: false, errorType: 'invalid-response', message: 'IP lookup returned a non-object response.' };
  }

  if (data.success === false) {
    const msg = typeof data.message === 'string' && data.message ? data.message : 'Lookup provider rejected the request.';
    const isRateLimit = /limit|quota|too many/i.test(msg);
    return {
      ok: false,
      errorType: isRateLimit ? 'rate-limit' : 'api-error',
      message: msg,
    };
  }

  if (typeof data.ip !== 'string' || !data.ip.trim()) {
    return { ok: false, errorType: 'invalid-response', message: 'IP lookup response did not include an IP address.' };
  }

  const country = typeof data.country === 'string' && data.country.trim() ? data.country.trim() : 'Unavailable';
  const countryCode = typeof data.country_code === 'string' && data.country_code.trim() ? data.country_code.trim() : null;
  const region = typeof data.region === 'string' && data.region.trim() ? data.region.trim() : 'Unavailable';
  const city = typeof data.city === 'string' && data.city.trim() ? data.city.trim() : 'Unavailable';

  const ispRaw = data.connection?.isp || data.connection?.org || '';
  const isp = typeof ispRaw === 'string' && ispRaw.trim() ? ispRaw.trim() : 'Unavailable';
  const asn = data.connection?.asn ? `AS${data.connection.asn}` : null;

  const hasCoords =
    typeof data.latitude === 'number' &&
    Number.isFinite(data.latitude) &&
    typeof data.longitude === 'number' &&
    Number.isFinite(data.longitude);

  const locationParts = [city, region, country].filter((part) => part && part !== 'Unavailable');
  const approxLocation = locationParts.length > 0 ? locationParts.join(', ') : 'Unavailable';

  return {
    ok: true,
    provider: 'ipwho.is',
    ip: data.ip.trim(),
    ipType: typeof data.type === 'string' ? data.type : null,
    approxLocation,
    country: countryCode && country !== 'Unavailable' ? `${country} (${countryCode})` : country,
    region,
    city,
    isp: asn && isp !== 'Unavailable' ? `${isp} (${asn})` : isp,
    coordinates: hasCoords ? `${data.latitude.toFixed(4)}, ${data.longitude.toFixed(4)} (approx. IP-based)` : 'Unavailable',
    latitude: hasCoords ? data.latitude : null,
    longitude: hasCoords ? data.longitude : null,
    timezone: typeof data.timezone?.id === 'string' ? data.timezone.id : null,
    partial: !hasCoords || country === 'Unavailable' || isp === 'Unavailable',
  };
}

/**
 * Normalize a `get.geojs.io/v1/ip/geo.json` payload into our structured Network Info format.
 * @param {unknown} data
 */
export function normalizeGeoJsPayload(data) {
  if (!data || typeof data !== 'object' || typeof data.ip !== 'string' || !data.ip.trim()) {
    return { ok: false, errorType: 'invalid-response', message: 'GeoJS lookup returned invalid JSON.' };
  }

  const country = typeof data.country === 'string' && data.country.trim() ? data.country.trim() : 'Unavailable';
  const countryCode = typeof data.country_code === 'string' && data.country_code.trim() ? data.country_code.trim() : null;
  const region = typeof data.region === 'string' && data.region.trim() ? data.region.trim() : 'Unavailable';
  const city = typeof data.city === 'string' && data.city.trim() ? data.city.trim() : 'Unavailable';
  const ispRaw = data.organization_name || data.organization || '';
  const isp = typeof ispRaw === 'string' && ispRaw.trim() ? ispRaw.trim() : 'Unavailable';
  const asn = data.asn ? `AS${data.asn}` : null;

  const lat = Number.parseFloat(data.latitude);
  const lon = Number.parseFloat(data.longitude);
  const hasCoords = Number.isFinite(lat) && Number.isFinite(lon);

  const locationParts = [city, region, country].filter((part) => part && part !== 'Unavailable');
  const approxLocation = locationParts.length > 0 ? locationParts.join(', ') : 'Unavailable';

  return {
    ok: true,
    provider: 'get.geojs.io',
    ip: data.ip.trim(),
    ipType: data.ip.includes(':') ? 'IPv6' : 'IPv4',
    approxLocation,
    country: countryCode && country !== 'Unavailable' ? `${country} (${countryCode})` : country,
    region,
    city,
    isp: asn && isp !== 'Unavailable' && !isp.includes(asn) ? `${isp} (${asn})` : isp,
    coordinates: hasCoords ? `${lat.toFixed(4)}, ${lon.toFixed(4)} (approx. IP-based)` : 'Unavailable',
    latitude: hasCoords ? lat : null,
    longitude: hasCoords ? lon : null,
    timezone: typeof data.timezone === 'string' ? data.timezone : null,
    partial: !hasCoords || country === 'Unavailable' || isp === 'Unavailable',
  };
}

/**
 * Normalize a `freeipapi.com/api/json` payload into our structured Network Info format.
 * @param {unknown} data
 */
export function normalizeFreeIpApiPayload(data) {
  if (!data || typeof data !== 'object' || typeof data.ipAddress !== 'string' || !data.ipAddress.trim()) {
    return { ok: false, errorType: 'invalid-response', message: 'FreeIPAPI lookup returned invalid JSON.' };
  }

  const country = typeof data.countryName === 'string' && data.countryName.trim() ? data.countryName.trim() : 'Unavailable';
  const countryCode = typeof data.countryCode === 'string' && data.countryCode.trim() ? data.countryCode.trim() : null;
  const region = typeof data.regionName === 'string' && data.regionName.trim() ? data.regionName.trim() : 'Unavailable';
  const city = typeof data.cityName === 'string' && data.cityName.trim() ? data.cityName.trim() : 'Unavailable';
  const ispRaw = data.asnOrganization || '';
  const isp = typeof ispRaw === 'string' && ispRaw.trim() ? ispRaw.trim() : 'Unavailable';
  const asn = data.asn ? `AS${data.asn}` : null;

  const lat = Number.parseFloat(data.latitude);
  const lon = Number.parseFloat(data.longitude);
  const hasCoords = Number.isFinite(lat) && Number.isFinite(lon);

  const locationParts = [city, region, country].filter((part) => part && part !== 'Unavailable');
  const approxLocation = locationParts.length > 0 ? locationParts.join(', ') : 'Unavailable';

  return {
    ok: true,
    provider: 'freeipapi.com',
    ip: data.ipAddress.trim(),
    ipType: data.ipVersion === 6 ? 'IPv6' : 'IPv4',
    approxLocation,
    country: countryCode && country !== 'Unavailable' ? `${country} (${countryCode})` : country,
    region,
    city,
    isp: asn && isp !== 'Unavailable' ? `${isp} (${asn})` : isp,
    coordinates: hasCoords ? `${lat.toFixed(4)}, ${lon.toFixed(4)} (approx. IP-based)` : 'Unavailable',
    latitude: hasCoords ? lat : null,
    longitude: hasCoords ? lon : null,
    timezone: Array.isArray(data.timeZones) && data.timeZones[0] ? data.timeZones[0] : null,
    partial: !hasCoords || country === 'Unavailable' || isp === 'Unavailable',
  };
}

/**
 * Normalize fallback IP-only response (e.g. api64.ipify.org).
 * @param {unknown} data
 */
export function normalizeIpifyPayload(data) {
  if (!data || typeof data !== 'object' || typeof data.ip !== 'string' || !data.ip.trim()) {
    return { ok: false, errorType: 'invalid-response', message: 'Fallback IP lookup returned invalid JSON.' };
  }
  return {
    ok: true,
    provider: 'api64.ipify.org (IP-only fallback)',
    ip: data.ip.trim(),
    ipType: data.ip.includes(':') ? 'IPv6' : 'IPv4',
    approxLocation: 'Unavailable (geolocation provider unreachable)',
    country: 'Unavailable',
    region: 'Unavailable',
    city: 'Unavailable',
    isp: 'Unavailable',
    coordinates: 'Unavailable',
    latitude: null,
    longitude: null,
    timezone: null,
    partial: true,
  };
}

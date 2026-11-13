/**
 * Pure User-Agent and User-Agent Client Hints parser.
 * Designed for transparent educational reporting, accounting for modern UA reduction/freezing.
 */

function formatMacVersion(raw) {
  return raw ? raw.replace(/_/g, '.') : '';
}

function mapWindowsNtVersion(ntVersion, uaDataPlatformVersion) {
  if (ntVersion === '10.0') {
    if (uaDataPlatformVersion) {
      const major = Number.parseInt(String(uaDataPlatformVersion).split('.')[0], 10);
      if (!Number.isNaN(major) && major >= 13) {
        return 'Windows 11';
      }
      if (!Number.isNaN(major) && major >= 1) {
        return 'Windows 10';
      }
    }
    return 'Windows 10 / 11 (UA frozen at NT 10.0)';
  }
  const map = {
    '6.3': 'Windows 8.1',
    '6.2': 'Windows 8',
    '6.1': 'Windows 7',
    '6.0': 'Windows Vista',
    '5.1': 'Windows XP',
  };
  return map[ntVersion] || `Windows (NT ${ntVersion})`;
}

/**
 * Parse browser name, version, and OS from navigator.userAgent and optional navigator.userAgentData.
 * @param {string} userAgent
 * @param {object|null} [userAgentData]
 * @param {string} [platform]
 */
export function parseUserAgent(userAgent, userAgentData = null, platform = '') {
  const ua = typeof userAgent === 'string' ? userAgent.trim() : '';

  if (!ua && !userAgentData) {
    return {
      browserName: 'Unknown',
      browserVersion: 'Unavailable',
      browserSummary: 'Unavailable (User-Agent empty)',
      osName: 'Unknown',
      osSummary: 'Unavailable',
      uaReductionDetected: false,
    };
  }

  // Extract Client Hints brands if available (excluding "Not*A*Brand" grease entries)
  const realBrands = Array.isArray(userAgentData?.brands)
    ? userAgentData.brands.filter((b) => b?.brand && !/not.*brand/i.test(b.brand))
    : [];

  let browserName = 'Unknown';
  let browserVersion = 'Unavailable';

  const matchers = [
    { name: 'Microsoft Edge', regex: /\b(?:Edg|EdgA|EdgiOS)\/([\d.]+)/ },
    { name: 'Opera', regex: /\b(?:OPR|Opera)\/([\d.]+)/ },
    { name: 'Vivaldi', regex: /\bVivaldi\/([\d.]+)/ },
    { name: 'Samsung Internet', regex: /\bSamsungBrowser\/([\d.]+)/ },
    { name: 'Firefox', regex: /\b(?:Firefox|FxiOS)\/([\d.]+)/ },
    { name: 'Chrome / Chromium', regex: /\b(?:Chrome|CriOS)\/([\d.]+)/ },
    { name: 'Safari', regex: /\bVersion\/([\d.]+).*?\bSafari\// },
  ];

  for (const matcher of matchers) {
    const m = ua.match(matcher.regex);
    if (m) {
      browserName = matcher.name;
      browserVersion = m[1];
      break;
    }
  }

  // Refine Chrome vs Brave/Chromium via UA Client Hints if available
  const braveBrand = realBrands.find((b) => /brave/i.test(b.brand));
  if (braveBrand && browserName === 'Chrome / Chromium') {
    browserName = 'Brave';
    browserVersion = braveBrand.version || browserVersion;
  } else if (browserName === 'Unknown' && realBrands.length > 0) {
    const primary = realBrands.find((b) => !/chromium/i.test(b.brand)) || realBrands[0];
    browserName = primary.brand;
    browserVersion = primary.version || 'Unavailable';
  }

  // Operating System detection
  let osName = 'Unknown';
  const uaDataPlatform = userAgentData?.platform || '';

  const iosMatch = ua.match(/\b(?:iPhone|iPad|iPod).*?\bOS\s+([\d_]+)/);
  const androidMatch = ua.match(/\bAndroid\s+([\d.]+)/);
  const winMatch = ua.match(/\bWindows NT\s+([\d.]+)/);
  const macMatch = ua.match(/\bMac OS X\s+([\d_]+)/);

  if (iosMatch) {
    const device = /iPad/.test(ua) ? 'iPadOS' : 'iOS';
    osName = `${device} ${formatMacVersion(iosMatch[1])}`;
  } else if (androidMatch) {
    osName = `Android ${androidMatch[1]}`;
  } else if (winMatch) {
    osName = mapWindowsNtVersion(winMatch[1], userAgentData?.platformVersion);
  } else if (macMatch) {
    const ver = formatMacVersion(macMatch[1]);
    osName = ver === '10.15.7' ? 'macOS (UA frozen at 10.15.7)' : `macOS ${ver}`;
  } else if (/\bCrOS\b/.test(ua)) {
    osName = 'ChromeOS';
  } else if (/\bLinux\b/i.test(ua)) {
    osName = /\bAndroid\b/i.test(ua) ? 'Android' : 'Linux';
  } else if (uaDataPlatform) {
    osName = uaDataPlatform;
  } else if (platform) {
    osName = platform;
  }

  // Check if UA appears to be reduced (e.g. Chrome's `.0.0.0` minor/patch freezing)
  const uaReductionDetected = /\b(?:Chrome|Edg)\/\d+\.0\.0\.0\b/.test(ua);

  const browserSummary =
    browserVersion && browserVersion !== 'Unavailable'
      ? `${browserName} ${browserVersion}`
      : browserName;

  return {
    browserName,
    browserVersion,
    browserSummary,
    osName,
    osSummary: osName,
    uaReductionDetected,
  };
}

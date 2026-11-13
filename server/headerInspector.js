/**
 * Server-side HTTP request header inspection, sensitive header redaction,
 * trusted proxy configuration parsing, and XSS-safe HTML JSON injection.
 */

export const SENSITIVE_HEADERS = new Set([
  'cookie',
  'set-cookie',
  'authorization',
  'proxy-authorization',
  'x-api-key',
  'x-auth-token',
  'x-csrf-token',
  'x-xsrf-token',
]);

export const REDACTED_VALUE = '[REDACTED — Hidden by default for visitor privacy]';

/**
 * Parse TRUST_PROXY configuration safely.
 * Defaults to false so arbitrary X-Forwarded-For headers are never trusted without explicit opt-in.
 * @param {string|boolean|number|undefined} raw
 */
export function parseTrustProxySetting(raw) {
  if (raw === undefined || raw === null || raw === '') return false;
  if (typeof raw === 'boolean') return raw;
  if (typeof raw === 'number') return Number.isInteger(raw) && raw >= 0 ? raw : false;

  const trimmed = String(raw).trim();
  const lower = trimmed.toLowerCase();
  if (lower === 'false' || lower === '0' || lower === 'off' || lower === 'no') return false;
  if (lower === 'true' || lower === 'on' || lower === 'yes') return true;
  if (/^\d+$/.test(trimmed)) return Number.parseInt(trimmed, 10);

  // Express accepts comma-separated IP/CIDR or named presets like 'loopback'
  if (trimmed.includes(',')) {
    return trimmed.split(',').map((s) => s.trim()).filter(Boolean);
  }
  return trimmed;
}

/**
 * Extract headers while preserving original wire casing from `req.rawHeaders`.
 * Sensitive headers are redacted by default without logging or storing raw values.
 * @param {string[]|undefined} rawHeaders
 * @param {Record<string, string|string[]>|undefined} fallbackHeaders
 */
export function extractSanitizedHeaders(rawHeaders, fallbackHeaders = {}) {
  const orderedMap = new Map();
  const redactedSet = new Set();

  const addPair = (rawName, rawVal) => {
    if (!rawName) return;
    const lower = String(rawName).toLowerCase();
    const isSensitive = SENSITIVE_HEADERS.has(lower);

    if (isSensitive) {
      redactedSet.add(rawName);
      orderedMap.set(lower, {
        name: rawName,
        value: REDACTED_VALUE,
        redacted: true,
      });
      return;
    }

    const stringVal = Array.isArray(rawVal) ? rawVal.join(', ') : String(rawVal ?? '');
    if (orderedMap.has(lower)) {
      const existing = orderedMap.get(lower);
      existing.value = `${existing.value}, ${stringVal}`;
    } else {
      orderedMap.set(lower, {
        name: rawName,
        value: stringVal,
        redacted: false,
      });
    }
  };

  if (Array.isArray(rawHeaders) && rawHeaders.length >= 2) {
    for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
      addPair(rawHeaders[i], rawHeaders[i + 1]);
    }
  } else if (fallbackHeaders && typeof fallbackHeaders === 'object') {
    for (const [k, v] of Object.entries(fallbackHeaders)) {
      addPair(k, v);
    }
  }

  return {
    headers: Array.from(orderedMap.values()),
    redactedHeaders: Array.from(redactedSet.values()),
  };
}

/**
 * Capture sanitized HTTP request inspection metadata in memory for the current response only.
 */
export function captureRequestInspection(req, { mode = 'server-document', trustProxySetting = false } = {}) {
  const trustProxyEnabled = Boolean(trustProxySetting);
  const { headers, redactedHeaders } = extractSanitizedHeaders(req.rawHeaders, req.headers);

  const socketIp = req.socket?.remoteAddress || 'Unavailable';
  const remoteAddress = trustProxyEnabled ? req.ip || socketIp : socketIp;
  const remoteAddressNote = trustProxyEnabled
    ? 'Derived via Express trusted proxy setting (TRUST_PROXY configured).'
    : 'Direct TCP socket peer address (TRUST_PROXY is disabled; forwarded IP headers are not trusted for identity).';

  return {
    mode,
    method: req.method || 'GET',
    path: req.originalUrl || req.url || '/',
    httpVersion: req.httpVersion || '1.1',
    timestamp: new Date().toISOString(),
    remoteAddress,
    remoteAddressNote,
    trustProxyEnabled,
    headers,
    redactedHeaders,
  };
}

/**
 * Serialize JSON safely for embedding inside an HTML `<script type="application/json">` element.
 * Escapes `<`, `>`, `&`, U+2028, and U+2029 so crafted header strings cannot break out of `<script>`.
 */
export function serializeSafeHtmlJson(data) {
  return JSON.stringify(data)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

const SCRIPT_MARKER = '<script id="__INITIAL_REQUEST_INSPECTION__" type="application/json">null</script>';

/**
 * Inject sanitized request metadata safely into `index.html`.
 */
export function injectInspectionIntoHtml(htmlTemplate, inspectionPayload) {
  if (!htmlTemplate.includes(SCRIPT_MARKER)) {
    throw new Error('HTML template is missing the __INITIAL_REQUEST_INSPECTION__ script placeholder.');
  }
  const safeJson = serializeSafeHtmlJson(inspectionPayload);
  const replacement = `<script id="__INITIAL_REQUEST_INSPECTION__" type="application/json">${safeJson}</script>`;
  // Function replacer avoids special `$` pattern interpolation from arbitrary header values
  return htmlTemplate.replace(SCRIPT_MARKER, () => replacement);
}

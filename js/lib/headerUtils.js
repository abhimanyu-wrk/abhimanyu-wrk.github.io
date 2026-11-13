/**
 * HTTP header categorization, presentation normalization, and educational descriptions.
 */

const HEADER_CATALOG = {
  'user-agent': {
    category: 'Client & Fingerprinting',
    description: 'Identifies browser engine, version, and OS family (modern browsers reduce some fields).',
  },
  accept: {
    category: 'Content Negotiation',
    description: 'Lists MIME content types the browser expects for this request (e.g. text/html vs application/json).',
  },
  'accept-language': {
    category: 'Locale & Fingerprinting',
    description: 'Reveals ordered user language preferences, often used for localization and fingerprinting entropy.',
  },
  'accept-encoding': {
    category: 'Content Negotiation',
    description: 'Lists compression algorithms supported by the browser (gzip, deflate, br, zstd).',
  },
  host: {
    category: 'Routing & Transport',
    description: 'Specifies the target hostname and port requested by the client.',
  },
  connection: {
    category: 'Routing & Transport',
    description: 'Controls hop-by-hop connection behavior such as keep-alive or upgrade.',
  },
  'cache-control': {
    category: 'Caching',
    description: 'Directives controlling intermediate and browser cache freshness (e.g. max-age=0 on hard reload).',
  },
  pragma: {
    category: 'Caching',
    description: 'Legacy HTTP/1.0 cache directive still sent by some clients on forced reloads.',
  },
  'sec-fetch-site': {
    category: 'Fetch Metadata',
    description: 'Indicates relationship between request origin and target (none for direct navigation, same-origin, cross-site).',
  },
  'sec-fetch-mode': {
    category: 'Fetch Metadata',
    description: 'Shows how the request was initiated: navigate (page load), cors, no-cors, or same-origin.',
  },
  'sec-fetch-dest': {
    category: 'Fetch Metadata',
    description: 'Reveals the destination resource type: document (HTML page) vs empty (fetch/XHR), script, style, etc.',
  },
  'sec-fetch-user': {
    category: 'Fetch Metadata',
    description: '?1 indicates navigation was triggered directly by a user activation (click or typing URL).',
  },
  'sec-ch-ua': {
    category: 'Client Hints',
    description: 'Low-entropy User-Agent Client Hint listing browser brands and major versions.',
  },
  'sec-ch-ua-mobile': {
    category: 'Client Hints',
    description: 'Indicates whether the browser is on a mobile form factor (?1) or desktop (?0).',
  },
  'sec-ch-ua-platform': {
    category: 'Client Hints',
    description: 'Low-entropy Client Hint exposing the operating system platform name.',
  },
  'upgrade-insecure-requests': {
    category: 'Security Policy',
    description: 'Signals the server that the browser prefers HTTPS upgrades for navigation.',
  },
  referer: {
    category: 'Navigation Context',
    description: 'Shows the previous page or origin that linked to this request (subject to Referrer-Policy).',
  },
  origin: {
    category: 'Security Policy',
    description: 'Sent on CORS or state-changing requests to identify the initiating scheme, host, and port.',
  },
  dnt: {
    category: 'Privacy Signal',
    description: 'Legacy Do Not Track preference signal (deprecated in modern standards in favor of GPC).',
  },
  'sec-gpc': {
    category: 'Privacy Signal',
    description: 'Global Privacy Control signal requesting websites not to sell or share personal data.',
  },
  cookie: {
    category: 'Sensitive / Credentials',
    description: 'Session or tracking cookies attached to the origin. Redacted by default for visitor safety.',
  },
  authorization: {
    category: 'Sensitive / Credentials',
    description: 'Authentication credentials (Bearer/Basic tokens). Redacted by default for visitor safety.',
  },
  'proxy-authorization': {
    category: 'Sensitive / Credentials',
    description: 'Proxy authentication credentials. Redacted by default for visitor safety.',
  },
  'x-forwarded-for': {
    category: 'Proxy Metadata',
    description: 'Added by proxies/tunnels (such as ngrok or load balancers); ignored for trust decisions unless proxy is configured.',
  },
  'x-forwarded-proto': {
    category: 'Proxy Metadata',
    description: 'Protocol used between the client and an upstream reverse proxy (http or https).',
  },
  'x-forwarded-host': {
    category: 'Proxy Metadata',
    description: 'Original Host header before an upstream reverse proxy forwarded the request.',
  },
};

/**
 * Return metadata and educational description for an HTTP header name.
 * @param {string} name
 */
export function describeHeader(name) {
  const lower = String(name || '').toLowerCase();
  if (HEADER_CATALOG[lower]) {
    return HEADER_CATALOG[lower];
  }
  if (lower.startsWith('sec-ch-')) {
    return {
      category: 'Client Hints',
      description: 'User-Agent Client Hint providing structured browser or device characteristics.',
    };
  }
  if (lower.startsWith('sec-fetch-')) {
    return {
      category: 'Fetch Metadata',
      description: 'Fetch Metadata request header describing request origin, mode, or destination.',
    };
  }
  if (lower.startsWith('x-forwarded-') || lower === 'forwarded') {
    return {
      category: 'Proxy Metadata',
      description: 'Proxy-added routing header. Only authoritative when received from an explicitly trusted reverse proxy.',
    };
  }
  return {
    category: 'Other Request Header',
    description: 'HTTP request header sent by the browser, client, or intermediary proxy.',
  };
}

/**
 * Safely parse the server-injected `<script id="__INITIAL_REQUEST_INSPECTION__" type="application/json">` payload.
 * Returns null if missing, empty, invalid, or in static mode.
 * @param {string|null} rawJsonText
 */
export function parseInjectedInspectionPayload(rawJsonText) {
  if (typeof rawJsonText !== 'string') return null;
  const trimmed = rawJsonText.trim();
  if (!trimmed || trimmed === 'null') return null;
  try {
    const parsed = JSON.parse(trimmed);
    if (!parsed || typeof parsed !== 'object' || parsed.mode !== 'server-document') {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

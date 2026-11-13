import { parseUserAgent } from '../lib/uaParser.js';
import {
  normalizeBatteryInfo,
  normalizeFreeIpApiPayload,
  normalizeGeoJsPayload,
  normalizeIpWhoIsPayload,
  normalizeIpifyPayload,
} from '../lib/fingerprintUtils.js';
import {
  clearNode,
  createCopyButton,
  createTooltip,
  el,
  formatTimestamp,
} from '../lib/dom.js';

const IP_LOOKUP_TIMEOUT_MS = 7000;

async function fetchJsonWithTimeout(url, timeoutMs = IP_LOOKUP_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      cache: 'no-store',
      signal: controller.signal,
    });
    if (response.status === 429) {
      return { ok: false, errorType: 'rate-limit', message: `Rate limited (HTTP 429) by ${new URL(url).hostname}.` };
    }
    if (!response.ok) {
      return { ok: false, errorType: 'http-error', message: `Lookup HTTP ${response.status} from ${new URL(url).hostname}.` };
    }
    let data;
    try {
      data = await response.json();
    } catch {
      return { ok: false, errorType: 'invalid-response', message: `Invalid JSON returned by ${new URL(url).hostname}.` };
    }
    return { ok: true, data };
  } catch (err) {
    if (err?.name === 'AbortError') {
      return { ok: false, errorType: 'timeout', message: `Request to ${new URL(url).hostname} timed out after ${timeoutMs / 1000}s.` };
    }
    return {
      ok: false,
      errorType: 'network',
      message: `Network request to ${new URL(url).hostname} failed (offline, CORS, or blocked by a privacy extension).`,
    };
  } finally {
    clearTimeout(timer);
  }
}

async function lookupPublicNetworkInfo() {
  const providers = [
    { url: 'https://ipwho.is/', normalize: normalizeIpWhoIsPayload },
    { url: 'https://get.geojs.io/v1/ip/geo.json', normalize: normalizeGeoJsPayload },
    { url: 'https://freeipapi.com/api/json', normalize: normalizeFreeIpApiPayload },
    { url: 'https://api64.ipify.org?format=json', normalize: normalizeIpifyPayload },
  ];

  let firstFailure = null;
  for (let i = 0; i < providers.length; i += 1) {
    const provider = providers[i];
    const res = await fetchJsonWithTimeout(provider.url);
    if (!res.ok) {
      if (!firstFailure) firstFailure = res;
      continue;
    }

    const normalized = provider.normalize(res.data);
    if (normalized.ok) {
      if (i > 0 && firstFailure) {
        return {
          ...normalized,
          warning: `Primary lookup unavailable (${firstFailure.message}); resolved via fallback provider (${normalized.provider}).`,
        };
      }
      return normalized;
    }

    if (!firstFailure) firstFailure = normalized;
  }

  return (
    firstFailure || {
      ok: false,
      errorType: 'network',
      message: 'All public IP lookup providers failed or were blocked.',
    }
  );
}

function collectBrowserInfo() {
  const ua = typeof navigator.userAgent === 'string' ? navigator.userAgent : '';
  const uaData = navigator.userAgentData || null;
  const platform = typeof navigator.platform === 'string' && navigator.platform.trim()
    ? navigator.platform.trim()
    : 'Not exposed by browser';

  const parsed = parseUserAgent(ua, uaData, platform);
  const language = typeof navigator.language === 'string' && navigator.language.trim()
    ? navigator.language.trim()
    : 'Not exposed';
  const preferredLanguages = Array.isArray(navigator.languages) && navigator.languages.length > 0
    ? navigator.languages.join(', ')
    : language;

  const hwCores = typeof navigator.hardwareConcurrency === 'number' && Number.isFinite(navigator.hardwareConcurrency)
    ? `${navigator.hardwareConcurrency} logical core(s)`
    : 'Not exposed by this browser';

  const devMemory = typeof navigator.deviceMemory === 'number' && Number.isFinite(navigator.deviceMemory)
    ? `~${navigator.deviceMemory} GB (browser-capped)`
    : 'Not supported by this browser';

  const cookiesEnabled = typeof navigator.cookieEnabled === 'boolean'
    ? (navigator.cookieEnabled ? 'Enabled' : 'Disabled')
    : 'Unavailable';

  return {
    userAgent: ua || 'Not exposed by browser',
    browserSummary: parsed.browserSummary,
    osSummary: parsed.osSummary,
    uaReductionDetected: parsed.uaReductionDetected,
    platform,
    language,
    preferredLanguages,
    cookiesEnabled,
    javascriptStatus: 'Enabled (Required to execute this analysis)',
    hardwareConcurrency: hwCores,
    deviceMemory: devMemory,
  };
}

function collectDisplayInfo() {
  const scr = window.screen;
  const width = typeof scr?.width === 'number' ? scr.width : null;
  const height = typeof scr?.height === 'number' ? scr.height : null;
  const availW = typeof scr?.availWidth === 'number' ? scr.availWidth : null;
  const availH = typeof scr?.availHeight === 'number' ? scr.availHeight : null;

  const vpW = typeof window.innerWidth === 'number' ? window.innerWidth : null;
  const vpH = typeof window.innerHeight === 'number' ? window.innerHeight : null;
  const dpr = typeof window.devicePixelRatio === 'number' && Number.isFinite(window.devicePixelRatio)
    ? `${window.devicePixelRatio}x`
    : 'Unavailable';
  const colorDepth = typeof scr?.colorDepth === 'number' && Number.isFinite(scr.colorDepth)
    ? `${scr.colorDepth}-bit`
    : 'Unavailable';

  let orientation = 'Not supported by this browser';
  if (scr?.orientation && typeof scr.orientation.type === 'string') {
    const angle = typeof scr.orientation.angle === 'number' ? ` (${scr.orientation.angle}°)` : '';
    orientation = `${scr.orientation.type}${angle}`;
  }

  return {
    screenDimensions: width !== null && height !== null ? `${width} × ${height} px` : 'Unavailable',
    availableScreen: availW !== null && availH !== null ? `${availW} × ${availH} px` : 'Unavailable',
    viewportDimensions: vpW !== null && vpH !== null ? `${vpW} × ${vpH} px` : 'Unavailable',
    devicePixelRatio: dpr,
    colorDepth,
    orientation,
  };
}

async function collectBatteryInfo() {
  if (typeof navigator.getBattery !== 'function') {
    return normalizeBatteryInfo(null, { supported: false });
  }
  try {
    const battery = await navigator.getBattery();
    return normalizeBatteryInfo(battery, { supported: true });
  } catch {
    return normalizeBatteryInfo(null, {
      supported: false,
      errorReason: 'Battery Status API call was rejected or blocked by browser permissions policy.',
    });
  }
}

function renderDataRow({ label, value, tooltip, copyValue, muted = false }) {
  const displayVal = value ?? 'Unavailable';
  return el(
    'div',
    { className: 'data-row' },
    el(
      'div',
      { className: 'data-label-wrap' },
      el('span', { className: 'data-label', text: label }),
      tooltip ? createTooltip(label, tooltip) : null
    ),
    el(
      'div',
      { className: 'data-value-wrap' },
      el('code', { className: `data-value${muted ? ' is-muted' : ''}`, text: displayVal }),
      createCopyButton(() => String(copyValue ?? displayVal), `Copy ${label}`)
    )
  );
}

/**
 * Initialize Module 1: Browser Fingerprinting Simulator.
 */
export function initFingerprintModule(container, { onNetworkResult } = {}) {
  let state = {
    status: 'idle', // idle | scanning | complete | partial
    timestamp: null,
    network: null,
    browser: null,
    display: null,
    battery: null,
    preciseGeo: { status: 'idle', data: null, error: null },
  };
  let scanRunId = 0;

  const statusBadge = el('span', { className: 'status-pill status-idle', text: 'Ready' });
  const timestampNode = el('span', { className: 'meta-timestamp', text: 'Not yet scanned' });
  const scanBtn = el('button', { type: 'button', className: 'btn btn-primary' }, el('span', { text: 'Scan Browser' }));
  const copyAllBtn = el('button', { type: 'button', className: 'btn btn-secondary', disabled: true, text: 'Copy All JSON' });
  const bodySlot = el('div', { className: 'module-body' });

  let copyAllResetTimer = null;
  copyAllBtn.addEventListener('click', async () => {
    if (!state.browser) return;
    const payload = {
      scannedAt: state.timestamp?.iso || null,
      note: 'Generated locally in browser memory. No persistent ID created and no data stored.',
      network: state.network,
      browser: state.browser,
      display: state.display,
      battery: state.battery,
      preciseGeolocation: state.preciseGeo.data || null,
    };
    const { copyToClipboard } = await import('../lib/dom.js');
    const ok = await copyToClipboard(JSON.stringify(payload, null, 2));
    if (copyAllResetTimer) clearTimeout(copyAllResetTimer);
    copyAllBtn.textContent = ok ? 'Copied JSON' : 'Copy Failed';
    copyAllResetTimer = setTimeout(() => {
      copyAllBtn.textContent = 'Copy All JSON';
    }, 1800);
  });

  function setStatus(kind, text) {
    statusBadge.className = `status-pill status-${kind}`;
    statusBadge.textContent = text;
  }

  function requestPreciseGeolocation() {
    if (!('geolocation' in navigator)) {
      state.preciseGeo = {
        status: 'error',
        data: null,
        error: 'Geolocation API is not supported by this browser.',
      };
      render();
      return;
    }

    state.preciseGeo = { status: 'loading', data: null, error: null };
    render();

    navigator.geolocation.getCurrentPosition(
      (position) => {
        state.preciseGeo = {
          status: 'granted',
          data: {
            latitude: position.coords.latitude,
            longitude: position.coords.longitude,
            accuracyMeters: Math.round(position.coords.accuracy),
            timestamp: new Date(position.timestamp).toISOString(),
          },
          error: null,
        };
        render();
      },
      (err) => {
        const messages = {
          1: 'Permission denied by user (PERMISSION_DENIED).',
          2: 'Location information unavailable from OS/hardware (POSITION_UNAVAILABLE).',
          3: 'Location request timed out (TIMEOUT).',
        };
        state.preciseGeo = {
          status: 'error',
          data: null,
          error: messages[err.code] || err.message || 'Geolocation failed.',
        };
        render();
      },
      { enableHighAccuracy: true, timeout: 10000, maximumAge: 0 }
    );
  }

  function renderIdle() {
    clearNode(bodySlot);
    bodySlot.appendChild(
      el(
        'div',
        { className: 'empty-state-box' },
        el('p', {
          className: 'empty-state-title',
          text: 'Ready to inspect local browser properties and public IP metadata.',
        }),
        el('p', {
          className: 'empty-state-desc',
          text: 'Nothing is probed until you click "Scan Browser" or "Run Privacy Analysis". No persistent ID, canvas fingerprint, or audio fingerprint is created.',
        })
      )
    );
  }

  function render() {
    clearNode(bodySlot);

    if (state.status === 'idle') {
      renderIdle();
      return;
    }

    if (state.status === 'scanning') {
      bodySlot.appendChild(
        el(
          'div',
          { className: 'loading-banner', role: 'status', 'aria-live': 'polite' },
          el('span', { className: 'spinner', 'aria-hidden': 'true' }),
          el('span', { text: 'Collecting browser, display, battery APIs and querying ipwho.is for public IP metadata...' })
        )
      );
      return;
    }

    const grid = el('div', { className: 'subgrid-2' });

    // 1. Network Information Card
    const netCard = el('section', { className: 'subcard', 'aria-label': 'Network Information' });
    netCard.appendChild(
      el(
        'div',
        { className: 'subcard-head' },
        el('h3', { className: 'subcard-title', text: 'Network & IP Geolocation' }),
        el('span', {
          className: `mini-badge ${state.network?.ok ? (state.network.partial ? 'is-warn' : 'is-info') : 'is-error'}`,
          text: state.network?.ok ? state.network.provider : 'Lookup Failed',
        })
      )
    );

    netCard.appendChild(
      el('p', {
        className: 'subcard-note',
        text: 'IP geolocation is approximate (derived from ISP routing records, not GPS). External request sent to ipwho.is (with fallback providers if rate-limited) when scanned.',
      })
    );

    if (!state.network?.ok) {
      netCard.appendChild(
        el(
          'div',
          { className: 'inline-alert is-error', role: 'alert' },
          el('strong', { text: 'Public IP Lookup Unavailable: ' }),
          el('span', { text: state.network?.message || 'Unable to retrieve public IP information.' })
        )
      );
    } else {
      if (state.network.warning) {
        netCard.appendChild(
          el(
            'div',
            { className: 'inline-alert is-warn', role: 'status' },
            el('span', { text: state.network.warning })
          )
        );
      }
      const rows = el('div', { className: 'data-list' });
      rows.appendChild(
        renderDataRow({
          label: 'Public IP Address',
          value: state.network.ip,
          tooltip: 'Every server you connect to sees your active egress IP (or your VPN/proxy exit IP).',
        })
      );
      rows.appendChild(
        renderDataRow({
          label: 'Approximate Location',
          value: state.network.approxLocation,
          tooltip: 'Best-effort city/region/country estimate inferred from public IP registry databases.',
          muted: state.network.approxLocation.startsWith('Unavailable'),
        })
      );
      rows.appendChild(
        renderDataRow({
          label: 'Country',
          value: state.network.country,
          tooltip: 'Country associated with the IP block.',
          muted: state.network.country === 'Unavailable',
        })
      );
      rows.appendChild(
        renderDataRow({
          label: 'Region / State',
          value: state.network.region,
          tooltip: 'Administrative region/state mapped to the IP allocation.',
          muted: state.network.region === 'Unavailable',
        })
      );
      rows.appendChild(
        renderDataRow({
          label: 'City',
          value: state.network.city,
          tooltip: 'Approximate city; often reflects ISP PoP or VPN gateway location rather than your street.',
          muted: state.network.city === 'Unavailable',
        })
      );
      rows.appendChild(
        renderDataRow({
          label: 'ISP / Organization',
          value: state.network.isp,
          tooltip: 'Autonomous System / ISP operating the IP address block.',
          muted: state.network.isp === 'Unavailable',
        })
      );
      rows.appendChild(
        renderDataRow({
          label: 'Approx. Coordinates',
          value: state.network.coordinates,
          tooltip: 'Rough IP-database centroid coordinates — significantly less accurate than GPS.',
          muted: state.network.coordinates === 'Unavailable',
        })
      );
      netCard.appendChild(rows);
    }

    // Optional Opt-In Precise Geolocation Box
    const geoBox = el('div', { className: 'optin-box' });
    geoBox.appendChild(
      el(
        'div',
        { className: 'optin-head' },
        el('strong', { text: 'Optional Precise Geolocation (Opt-In)' }),
        el('span', { className: 'optin-sub', text: 'Uses navigator.geolocation only when you click below.' })
      )
    );
    const geoBtn = el('button', {
      type: 'button',
      className: 'btn btn-small btn-secondary',
      disabled: state.preciseGeo.status === 'loading',
      text: state.preciseGeo.status === 'loading' ? 'Requesting Permission...' : 'Request Precise Location',
      onClick: requestPreciseGeolocation,
    });
    geoBox.appendChild(geoBtn);

    if (state.preciseGeo.status === 'granted' && state.preciseGeo.data) {
      const g = state.preciseGeo.data;
      geoBox.appendChild(
        el(
          'div',
          { className: 'optin-result' },
          renderDataRow({
            label: 'GPS / Wi-Fi Coordinates',
            value: `${g.latitude.toFixed(6)}, ${g.longitude.toFixed(6)} (±${g.accuracyMeters}m)`,
            tooltip: 'High-accuracy location returned after explicit user permission.',
          })
        )
      );
    } else if (state.preciseGeo.status === 'error') {
      geoBox.appendChild(
        el('p', { className: 'optin-msg is-warn', text: state.preciseGeo.error })
      );
    }
    netCard.appendChild(geoBox);
    grid.appendChild(netCard);

    // 2. Browser & Hardware Card
    const brCard = el('section', { className: 'subcard', 'aria-label': 'Browser Information' });
    brCard.appendChild(
      el(
        'div',
        { className: 'subcard-head' },
        el('h3', { className: 'subcard-title', text: 'Browser & Hardware Signals' }),
        el('span', {
          className: 'mini-badge is-info',
          text: state.browser.uaReductionDetected ? 'UA Reduction Active' : 'Navigator APIs',
        })
      )
    );
    brCard.appendChild(
      el('p', {
        className: 'subcard-note',
        text: 'Read locally from window.navigator. Modern browsers freeze or omit certain fields to reduce fingerprinting entropy.',
      })
    );

    const brRows = el('div', { className: 'data-list' });
    brRows.appendChild(renderDataRow({
      label: 'Browser',
      value: state.browser.browserSummary,
      tooltip: 'Parsed from User-Agent / Client Hints. Reveals browser engine and major version.',
    }));
    brRows.appendChild(renderDataRow({
      label: 'Operating System',
      value: state.browser.osSummary,
      tooltip: 'OS family parsed from User-Agent tokens (Windows 10/11 often both report NT 10.0).',
    }));
    brRows.appendChild(renderDataRow({
      label: 'User-Agent',
      value: state.browser.userAgent,
      tooltip: 'Full navigator.userAgent string exposed to scripts and sent in HTTP requests.',
    }));
    brRows.appendChild(renderDataRow({
      label: 'Platform',
      value: state.browser.platform,
      tooltip: 'Hardware/OS compilation target exposed via navigator.platform.',
    }));
    brRows.appendChild(renderDataRow({
      label: 'Language',
      value: state.browser.language,
      tooltip: 'Primary UI language reported by navigator.language.',
    }));
    brRows.appendChild(renderDataRow({
      label: 'Preferred Languages',
      value: state.browser.preferredLanguages,
      tooltip: 'Ordered accept-language list; unusual multi-language combinations add strong uniqueness.',
    }));
    brRows.appendChild(renderDataRow({
      label: 'Cookies Enabled',
      value: state.browser.cookiesEnabled,
      tooltip: 'Indicates whether cookie storage is enabled in browser settings.',
    }));
    brRows.appendChild(renderDataRow({
      label: 'JavaScript',
      value: state.browser.javascriptStatus,
      tooltip: 'Confirms active client-side script execution.',
    }));
    brRows.appendChild(renderDataRow({
      label: 'CPU Cores (Concurrency)',
      value: state.browser.hardwareConcurrency,
      tooltip: 'Logical CPU thread count exposed via navigator.hardwareConcurrency (may be capped by privacy browsers).',
      muted: state.browser.hardwareConcurrency.startsWith('Not '),
    }));
    brRows.appendChild(renderDataRow({
      label: 'Device Memory',
      value: state.browser.deviceMemory,
      tooltip: 'Approximate RAM tier in GB (Chromium-only; unsupported in Firefox and Safari).',
      muted: state.browser.deviceMemory.startsWith('Not '),
    }));
    brCard.appendChild(brRows);
    grid.appendChild(brCard);

    // 3. Display Card
    const dispCard = el('section', { className: 'subcard', 'aria-label': 'Display Information' });
    dispCard.appendChild(
      el(
        'div',
        { className: 'subcard-head' },
        el('h3', { className: 'subcard-title', text: 'Display & Viewport Geometry' }),
        el('span', { className: 'mini-badge is-info', text: 'Screen API' })
      )
    );
    dispCard.appendChild(
      el('p', {
        className: 'subcard-note',
        text: 'Monitor size, OS taskbar offsets (availWidth/Height), zoom-affected viewport, and scaling ratio.',
      })
    );
    const dispRows = el('div', { className: 'data-list' });
    dispRows.appendChild(renderDataRow({
      label: 'Screen Size',
      value: state.display.screenDimensions,
      tooltip: 'Physical CSS pixel dimensions of your display (window.screen.width × height).',
    }));
    dispRows.appendChild(renderDataRow({
      label: 'Available Screen Area',
      value: state.display.availableScreen,
      tooltip: 'Usable desktop dimensions minus OS taskbars/docks, revealing OS bar layout.',
    }));
    dispRows.appendChild(renderDataRow({
      label: 'Browser Viewport',
      value: state.display.viewportDimensions,
      tooltip: 'Inner browser window size; changes with window resizing and page zoom.',
    }));
    dispRows.appendChild(renderDataRow({
      label: 'Device Pixel Ratio',
      value: state.display.devicePixelRatio,
      tooltip: 'Ratio of physical pixels to CSS pixels (e.g. 2x on Retina/HiDPI displays or browser zoom).',
    }));
    dispRows.appendChild(renderDataRow({
      label: 'Color Depth',
      value: state.display.colorDepth,
      tooltip: 'Bits per pixel used for color rendering (typically 24-bit or 30-bit on wide-gamut displays).',
    }));
    dispRows.appendChild(renderDataRow({
      label: 'Orientation',
      value: state.display.orientation,
      tooltip: 'Current screen orientation type and angle via Screen Orientation API.',
      muted: state.display.orientation.startsWith('Not '),
    }));
    dispCard.appendChild(dispRows);
    grid.appendChild(dispCard);

    // 4. Battery Card
    const batCard = el('section', { className: 'subcard', 'aria-label': 'Battery Status' });
    batCard.appendChild(
      el(
        'div',
        { className: 'subcard-head' },
        el('h3', { className: 'subcard-title', text: 'Battery Status API' }),
        el('span', {
          className: `mini-badge ${state.battery.supported ? 'is-info' : 'is-warn'}`,
          text: state.battery.supported ? 'Supported' : 'Not Supported',
        })
      )
    );
    batCard.appendChild(
      el('p', {
        className: 'subcard-note',
        text: state.battery.note,
      })
    );
    const batRows = el('div', { className: 'data-list' });
    const batMuted = !state.battery.supported;
    batRows.appendChild(renderDataRow({
      label: 'Battery Percentage',
      value: state.battery.percentage,
      tooltip: 'Current charge percentage; unavailable values are never reported as 0%.',
      muted: batMuted,
    }));
    batRows.appendChild(renderDataRow({
      label: 'Charging Status',
      value: state.battery.chargingStatus,
      tooltip: 'Whether AC power is connected.',
      muted: batMuted,
    }));
    batRows.appendChild(renderDataRow({
      label: 'Charging Time',
      value: state.battery.chargingTime,
      tooltip: 'Estimated time until full charge, if exposed by the OS and browser.',
      muted: batMuted || state.battery.chargingTime.startsWith('N/A'),
    }));
    batRows.appendChild(renderDataRow({
      label: 'Discharging Time',
      value: state.battery.dischargingTime,
      tooltip: 'Estimated remaining battery life, which previously enabled cross-origin short-term correlation.',
      muted: batMuted || state.battery.dischargingTime.startsWith('N/A'),
    }));
    batCard.appendChild(batRows);
    grid.appendChild(batCard);

    bodySlot.appendChild(grid);

    // Educational explanation accordion
    const details = el(
      'details',
      { className: 'tech-details' },
      el('summary', { text: 'Educational Note: How combining harmless attributes distinguishes browsers' }),
      el(
        'div',
        { className: 'tech-details-body' },
        el('p', {
          text: 'Individually, attributes like 24-bit color depth, English language, or 8 CPU cores are shared by millions of people. When websites combine 15–30 independent signals (OS, screen geometry, timezone, preferred language order, hardware concurrency, and public IP subnet), the joint probability shrinks dramatically.',
        }),
        el('p', {
          text: 'Privacy safeguard in this lab: This simulator computes NO persistent visitor ID, runs NO canvas or WebAudio rendering probes, and keeps all results purely inside this browser tab.',
        })
      )
    );
    bodySlot.appendChild(details);
  }

  async function runScan() {
    scanRunId += 1;
    const currentRun = scanRunId;

    state.status = 'scanning';
    copyAllBtn.disabled = true;
    scanBtn.disabled = true;
    scanBtn.textContent = 'Scanning...';
    setStatus('scanning', 'Scanning');
    render();

    const browser = collectBrowserInfo();
    const display = collectDisplayInfo();
    const [battery, network] = await Promise.all([
      collectBatteryInfo(),
      lookupPublicNetworkInfo(),
    ]);

    if (currentRun !== scanRunId) return null;

    const ts = formatTimestamp(new Date());
    state = {
      ...state,
      status: network.ok ? 'complete' : 'partial',
      timestamp: ts,
      network,
      browser,
      display,
      battery,
    };

    timestampNode.textContent = `Scanned: ${ts.local}`;
    scanBtn.disabled = false;
    scanBtn.textContent = 'Re-scan Browser';
    copyAllBtn.disabled = false;
    setStatus(network.ok ? 'complete' : 'warn', network.ok ? 'Complete' : 'Partial (IP Lookup Failed)');
    render();

    if (typeof onNetworkResult === 'function') {
      onNetworkResult(network);
    }
    return state;
  }

  function reset() {
    scanRunId += 1;
    state = {
      status: 'idle',
      timestamp: null,
      network: null,
      browser: null,
      display: null,
      battery: null,
      preciseGeo: { status: 'idle', data: null, error: null },
    };
    timestampNode.textContent = 'Not yet scanned';
    scanBtn.disabled = false;
    scanBtn.textContent = 'Scan Browser';
    copyAllBtn.disabled = true;
    setStatus('idle', 'Ready');
    renderIdle();
  }

  scanBtn.addEventListener('click', () => {
    runScan();
  });

  // Assemble module structure
  clearNode(container);
  container.appendChild(
    el(
      'div',
      { className: 'module-header' },
      el(
        'div',
        { className: 'module-title-block' },
        el('div', { className: 'module-kicker', text: 'MODULE 01 // CLIENT & NETWORK SIGNALS' }),
        el('h2', { className: 'module-title', text: 'Browser Fingerprinting Simulator' }),
        el('p', {
          className: 'module-desc',
          text: 'Inspects standard JavaScript browser APIs (navigator, screen, battery) alongside an external IP geolocation lookup—without creating a persistent ID or storing results.',
        })
      ),
      el(
        'div',
        { className: 'module-controls' },
        el('div', { className: 'module-meta-row' }, statusBadge, timestampNode),
        el('div', { className: 'module-btn-row' }, scanBtn, copyAllBtn)
      )
    )
  );
  container.appendChild(bodySlot);
  renderIdle();

  return {
    runScan,
    reset,
    getPublicIp: () => (state.network?.ok ? state.network.ip : null),
    getState: () => state,
  };
}

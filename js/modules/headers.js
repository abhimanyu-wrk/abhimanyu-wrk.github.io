import { describeHeader, parseInjectedInspectionPayload } from '../lib/headerUtils.js';
import { clearNode, createCopyButton, createTooltip, el } from '../lib/dom.js';

function normalizeEndpointUrl(rawInput) {
  const trimmed = String(rawInput || '').trim();
  if (!trimmed) return null;
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return null;
  }
  const base = parsed.origin + parsed.pathname.replace(/\/+$/, '');
  return base.endsWith('/api/headers') ? base : `${base}/api/headers`;
}

function renderMetadataTiles(meta) {
  const grid = el('div', { className: 'metrics-grid' });
  const items = [
    {
      label: 'HTTP Method & Path',
      value: `${meta.method || 'GET'} ${meta.path || '/'}`,
      tip: 'HTTP method and request target received by the Node.js server.',
    },
    {
      label: 'HTTP Version',
      value: `HTTP/${meta.httpVersion || '1.1'}`,
      tip: 'Negotiated HTTP wire protocol version.',
    },
    {
      label: 'Request Timestamp',
      value: meta.timestamp || 'Unavailable',
      tip: 'Exact server timestamp when this HTTP request arrived.',
    },
    {
      label: 'Remote Address',
      value: meta.remoteAddress || 'Unavailable',
      tip: meta.remoteAddressNote || 'Client IP address as observed by the server socket or configured trusted proxy.',
    },
  ];

  for (const item of items) {
    grid.appendChild(
      el(
        'div',
        { className: 'metric-tile' },
        el(
          'div',
          { className: 'metric-label-row' },
          el('span', { className: 'metric-label', text: item.label }),
          createTooltip(item.label, item.tip)
        ),
        el('code', { className: 'metric-value', text: item.value })
      )
    );
  }
  return grid;
}

function renderHeadersTable(headers, titleLabel, badgeText) {
  const section = el('section', { className: 'subcard' });
  section.appendChild(
    el(
      'div',
      { className: 'subcard-head' },
      el('h3', { className: 'subcard-title', text: titleLabel }),
      el('span', { className: 'mini-badge is-info', text: badgeText })
    )
  );

  if (!Array.isArray(headers) || headers.length === 0) {
    section.appendChild(el('p', { className: 'empty-group-msg', text: 'No request headers present.' }));
    return section;
  }

  const tableWrap = el('div', { className: 'table-scroll' });
  const table = el('table', { className: 'data-table headers-table' });
  table.appendChild(
    el(
      'thead',
      null,
      el(
        'tr',
        null,
        el('th', { scope: 'col', text: 'Header Name' }),
        el('th', { scope: 'col', text: 'Value' }),
        el('th', { scope: 'col', text: 'Category & Meaning' }),
        el('th', { scope: 'col', text: 'Copy' })
      )
    )
  );

  const tbody = el('tbody');
  for (const h of headers) {
    const info = describeHeader(h.name);
    const valNode = h.redacted
      ? el('span', { className: 'scope-tag tag-danger', text: h.value })
      : el('code', { className: 'mono-cell wrap-anywhere', text: h.value });

    tbody.appendChild(
      el(
        'tr',
        null,
        el('td', null, el('code', { className: 'mono-cell header-name-cell', text: h.name })),
        el('td', null, valNode),
        el(
          'td',
          null,
          el(
            'div',
            { className: 'header-meaning-cell' },
            el('span', { className: 'scope-tag tag-neutral', text: info.category }),
            el('span', { className: 'header-desc-text', text: info.description })
          )
        ),
        el(
          'td',
          null,
          h.redacted
            ? el('span', { className: 'is-muted mono-cell', text: 'Redacted' })
            : createCopyButton(() => `${h.name}: ${h.value}`, `Copy ${h.name} header`)
        )
      )
    );
  }

  table.appendChild(tbody);
  tableWrap.appendChild(table);
  section.appendChild(tableWrap);
  return section;
}

/**
 * Initialize Module 3: HTTP Header Inspector.
 * Supports:
 *   Mode A: Static GitHub Pages (cannot inspect original document headers)
 *   Mode B: Server-Side Document Inspection (captures initial GET / headers safely injected into HTML)
 */
export function initHeadersModule(container, { onModeDetected } = {}) {
  const rawScript = document.getElementById('__INITIAL_REQUEST_INSPECTION__');
  const serverPayload = parseInjectedInspectionPayload(rawScript ? rawScript.textContent : null);
  const isServerMode = Boolean(serverPayload);

  if (typeof onModeDetected === 'function') {
    onModeDetected(isServerMode ? 'server' : 'static');
  }

  let state = {
    isServerMode,
    cleared: false,
    documentCapture: serverPayload,
    endpointInspection: {
      status: 'idle', // idle | loading | success | error
      data: null,
      error: null,
      url: isServerMode ? '/api/headers' : '',
    },
  };

  const statusBadge = el('span', {
    className: `status-pill ${isServerMode ? 'status-complete' : 'status-warn'}`,
    text: isServerMode ? 'Server Capture Active' : 'Static Mode (GitHub Pages)',
  });
  const timestampNode = el('span', {
    className: 'meta-timestamp',
    text: isServerMode && serverPayload.timestamp ? `Captured: ${serverPayload.timestamp}` : 'No server capture in static mode',
  });
  const copyAllBtn = el('button', {
    type: 'button',
    className: 'btn btn-secondary',
    disabled: !isServerMode,
    text: 'Copy Captured JSON',
  });
  const bodySlot = el('div', { className: 'module-body' });

  let copyResetTimer = null;
  copyAllBtn.addEventListener('click', async () => {
    if (!state.documentCapture || state.cleared) return;
    const { copyToClipboard } = await import('../lib/dom.js');
    const ok = await copyToClipboard(JSON.stringify(state.documentCapture, null, 2));
    if (copyResetTimer) clearTimeout(copyResetTimer);
    copyAllBtn.textContent = ok ? 'Copied JSON' : 'Copy Failed';
    copyResetTimer = setTimeout(() => {
      copyAllBtn.textContent = 'Copy Captured JSON';
    }, 1800);
  });

  async function inspectSecondaryEndpoint(targetUrl) {
    state.endpointInspection = {
      status: 'loading',
      data: null,
      error: null,
      url: targetUrl,
    };
    render();

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 7000);
    try {
      const res = await fetch(targetUrl, {
        method: 'GET',
        headers: { Accept: 'application/json' },
        cache: 'no-store',
        signal: controller.signal,
      });
      if (!res.ok) {
        throw new Error(`Endpoint returned HTTP ${res.status}.`);
      }
      const data = await res.json();
      if (!data || !Array.isArray(data.headers)) {
        throw new Error('Endpoint response did not match expected header inspection schema.');
      }
      state.endpointInspection = {
        status: 'success',
        data,
        error: null,
        url: targetUrl,
      };
    } catch (err) {
      const msg =
        err?.name === 'AbortError'
          ? 'Endpoint request timed out.'
          : err?.message || 'Unable to reach endpoint (check server status, URL, or CORS configuration).';
      state.endpointInspection = {
        status: 'error',
        data: null,
        error: msg,
        url: targetUrl,
      };
    } finally {
      clearTimeout(timer);
      render();
    }
  }

  function renderSecondaryEndpointSection() {
    const box = el('section', { className: 'subcard secondary-endpoint-card' });
    box.appendChild(
      el(
        'div',
        { className: 'subcard-head' },
        el('h3', { className: 'subcard-title', text: 'Optional Secondary Fetch Endpoint Check (/api/headers)' }),
        el('span', { className: 'mini-badge is-warn', text: 'Not Original Page Load' })
      )
    );
    box.appendChild(
      el('p', {
        className: 'subcard-note',
        text: isServerMode
          ? 'Compare how a background JavaScript fetch() request sends different headers (e.g. Sec-Fetch-Mode: cors, Sec-Fetch-Dest: empty) than the original HTML document navigation above.'
          : 'If you have the optional Node.js backend running locally or behind ngrok with CORS enabled, you can probe its /api/headers endpoint. Note: That endpoint ONLY sees the headers of this secondary fetch() request—never the original GitHub Pages HTML navigation headers.',
      })
    );

    const formRow = el('form', { className: 'endpoint-form' });
    if (!isServerMode) {
      const input = el('input', {
        type: 'url',
        className: 'text-input',
        placeholder: 'http://localhost:3000 or https://your-tunnel.ngrok-free.app',
        value: state.endpointInspection.url || '',
        'aria-label': 'Optional backend base URL for /api/headers test',
      });
      const submitBtn = el('button', {
        type: 'submit',
        className: 'btn btn-secondary btn-small',
        disabled: state.endpointInspection.status === 'loading',
        text: state.endpointInspection.status === 'loading' ? 'Probing...' : 'Probe /api/headers',
      });
      formRow.appendChild(input);
      formRow.appendChild(submitBtn);
      formRow.addEventListener('submit', (e) => {
        e.preventDefault();
        const endpoint = normalizeEndpointUrl(input.value);
        if (!endpoint) {
          state.endpointInspection = {
            status: 'error',
            data: null,
            error: 'Please enter a valid http:// or https:// backend URL.',
            url: input.value,
          };
          render();
          return;
        }
        inspectSecondaryEndpoint(endpoint);
      });
    } else {
      const probeBtn = el('button', {
        type: 'button',
        className: 'btn btn-secondary btn-small',
        disabled: state.endpointInspection.status === 'loading',
        text: state.endpointInspection.status === 'loading' ? 'Probing /api/headers...' : 'Inspect Secondary fetch() to /api/headers',
        onClick: () => inspectSecondaryEndpoint('/api/headers'),
      });
      formRow.appendChild(probeBtn);
    }
    box.appendChild(formRow);

    if (state.endpointInspection.status === 'error') {
      box.appendChild(
        el(
          'div',
          { className: 'inline-alert is-error', role: 'alert' },
          el('strong', { text: 'Endpoint Probe Failed: ' }),
          el('span', { text: state.endpointInspection.error })
        )
      );
    } else if (state.endpointInspection.status === 'success' && state.endpointInspection.data) {
      const d = state.endpointInspection.data;
      box.appendChild(
        el(
          'div',
          { className: 'inline-alert is-warn' },
          el('strong', { text: 'Secondary Fetch Headers Only: ' }),
          el('span', {
            text: `Received by ${state.endpointInspection.url} during a JS fetch() call—NOT the original HTML document navigation request.`,
          })
        )
      );
      box.appendChild(renderMetadataTiles(d));
      box.appendChild(renderHeadersTable(d.headers, 'Headers Received by /api/headers', `${d.headers.length} headers`));
    }

    return box;
  }

  function render() {
    clearNode(bodySlot);

    if (state.cleared) {
      bodySlot.appendChild(
        el(
          'div',
          { className: 'empty-state-box' },
          el('p', { className: 'empty-state-title', text: 'HTTP Header Inspector results cleared from view.' }),
          el('p', {
            className: 'empty-state-desc',
            text: state.isServerMode
              ? 'No headers were persisted. Reload the page to trigger a fresh server-captured HTML document request.'
              : 'Static mode active. Reload or switch to the optional Node.js server to capture initial document headers.',
          })
        )
      );
      return;
    }

    if (!state.isServerMode || !state.documentCapture) {
      // Mode A: Static GitHub Pages Mode
      bodySlot.appendChild(
        el(
          'div',
          { className: 'verdict-banner verdict-yellow' },
          el(
            'div',
            { className: 'verdict-top' },
            el('span', { className: 'verdict-dot dot-yellow', 'aria-hidden': 'true' }),
            el('span', { className: 'verdict-badge', text: 'MODE A — STATIC GITHUB PAGES HOSTING' })
          ),
          el('h3', { className: 'verdict-title', text: 'Original Document Request Headers Cannot Be Read in Static Mode' }),
          el('p', {
            className: 'verdict-summary',
            text: 'Because this page is served statically without a capturing application server, frontend JavaScript has no API to access the HTTP headers your browser sent when downloading index.html. This module refuses to fabricate headers from navigator properties.',
          }),
          el(
            'ul',
            { className: 'verdict-notes' },
            el('li', {
              text: 'Static hosting flow: Browser → GitHub Pages CDN → Static HTML/JS (server-side request headers are discarded by the CDN and never exposed to client JS).',
            }),
            el('li', {
              text: 'Server inspection flow: Browser → [Optional ngrok tunnel] → Node.js/Express server → Injects safe request metadata directly into the served HTML.',
            })
          )
        )
      );

      bodySlot.appendChild(renderSecondaryEndpointSection());
      return;
    }

    // Mode B: Server-Side Document Inspection
    const cap = state.documentCapture;
    bodySlot.appendChild(
      el(
        'div',
        { className: 'verdict-banner verdict-green' },
        el(
          'div',
          { className: 'verdict-top' },
          el('span', { className: 'verdict-dot dot-green', 'aria-hidden': 'true' }),
          el('span', { className: 'verdict-badge', text: 'MODE B — SERVER-SIDE DOCUMENT CAPTURE' })
        ),
        el('h3', { className: 'verdict-title', text: 'Actual Initial HTML Navigation Request Headers Captured' }),
        el('p', {
          className: 'verdict-summary',
          text: 'These exact headers were received by the Node.js/Express server when your browser navigated to load this page, injected into the HTML response in memory, and never logged or saved.',
        })
      )
    );

    // Redaction disclosure
    const redactedList = Array.isArray(cap.redactedHeaders) ? cap.redactedHeaders : [];
    bodySlot.appendChild(
      el(
        'div',
        { className: `inline-alert ${redactedList.length > 0 ? 'is-warn' : 'is-info'}` },
        el('strong', { text: 'Sensitive Header Redaction Policy: ' }),
        el('span', {
          text:
            redactedList.length > 0
              ? `Redacted ${redactedList.length} sensitive header(s) by default: ${redactedList.join(', ')}.`
              : 'Sensitive headers (Cookie, Authorization, Proxy-Authorization, X-API-Key) are redacted automatically; none were present on this navigation request.',
        })
      )
    );

    bodySlot.appendChild(renderMetadataTiles(cap));
    bodySlot.appendChild(
      renderHeadersTable(
        cap.headers,
        'Original HTML Document Request Headers',
        `${cap.headers.length} headers captured`
      )
    );

    bodySlot.appendChild(renderSecondaryEndpointSection());
  }

  function reset() {
    state.cleared = true;
    state.endpointInspection = {
      status: 'idle',
      data: null,
      error: null,
      url: isServerMode ? '/api/headers' : '',
    };
    copyAllBtn.disabled = true;
    statusBadge.className = 'status-pill status-idle';
    statusBadge.textContent = 'Cleared';
    render();
  }

  function restoreOrHighlight() {
    if (state.cleared) {
      state.cleared = false;
      copyAllBtn.disabled = !state.isServerMode;
      statusBadge.className = `status-pill ${state.isServerMode ? 'status-complete' : 'status-warn'}`;
      statusBadge.textContent = state.isServerMode ? 'Server Capture Active' : 'Static Mode (GitHub Pages)';
      render();
    }
  }

  clearNode(container);
  container.appendChild(
    el(
      'div',
      { className: 'module-header' },
      el(
        'div',
        { className: 'module-title-block' },
        el('div', { className: 'module-kicker', text: 'MODULE 03 // WIRE-LEVEL HTTP METADATA' }),
        el('h2', { className: 'module-title', text: 'HTTP Header Inspector' }),
        el('p', {
          className: 'module-desc',
          text: 'Demonstrates the architectural boundary between static CDN hosting and server-side request inspection of the initial HTML document load.',
        })
      ),
      el(
        'div',
        { className: 'module-controls' },
        el('div', { className: 'module-meta-row' }, statusBadge, timestampNode),
        el('div', { className: 'module-btn-row' }, copyAllBtn)
      )
    )
  );
  container.appendChild(bodySlot);
  render();

  return {
    reset,
    restoreOrHighlight,
    isServerMode: () => state.isServerMode,
  };
}

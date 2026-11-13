import { assessWebRtcPrivacy, parseIceCandidate } from '../lib/ipUtils.js';
import { WEBRTC_SCENARIOS } from '../data/education.js';
import {
  clearNode,
  createCopyButton,
  createTooltip,
  el,
  formatTimestamp,
} from '../lib/dom.js';

const STUN_SERVERS = [{ urls: 'stun:stun.l.google.com:19302' }];
const GATHER_TIMEOUT_MS = 5500;

function candidateDedupeKey(c) {
  return [
    c.type,
    c.protocol,
    c.address,
    c.port ?? '',
    c.relatedAddress ?? '',
  ].join('|');
}

function buildSummaryCard(label, value, tooltip, toneClass = '') {
  return el(
    'div',
    { className: `metric-tile ${toneClass}` },
    el(
      'div',
      { className: 'metric-label-row' },
      el('span', { className: 'metric-label', text: label }),
      tooltip ? createTooltip(label, tooltip) : null
    ),
    el('code', { className: 'metric-value', text: value })
  );
}

function renderCandidateGroup(title, subtitle, candidates) {
  const section = el('section', { className: 'subcard' });
  section.appendChild(
    el(
      'div',
      { className: 'subcard-head' },
      el('h3', { className: 'subcard-title', text: title }),
      el('span', { className: 'mini-badge is-info', text: `${candidates.length} found` })
    )
  );
  section.appendChild(el('p', { className: 'subcard-note', text: subtitle }));

  if (candidates.length === 0) {
    section.appendChild(
      el('p', { className: 'empty-group-msg', text: 'No candidates of this type were observed during this scan.' })
    );
    return section;
  }

  const tableWrap = el('div', { className: 'table-scroll' });
  const table = el('table', { className: 'data-table' });
  const thead = el(
    'thead',
    null,
    el(
      'tr',
      null,
      el('th', { scope: 'col', text: 'Address / Hostname' }),
      el('th', { scope: 'col', text: 'Classification' }),
      el('th', { scope: 'col', text: 'Protocol & Port' }),
      el('th', { scope: 'col', text: 'Related Addr (raddr)' }),
      el('th', { scope: 'col', text: 'Copy' })
    )
  );

  const tbody = el('tbody');
  for (const cand of candidates) {
    const scopeClass =
      cand.addressInfo.kind === 'mdns'
        ? 'tag-warn'
        : cand.addressInfo.isPrivateOrLocal
          ? 'tag-danger'
          : cand.addressInfo.isPublicIp
            ? 'tag-cyan'
            : 'tag-neutral';

    const raddrDisplay = cand.relatedAddress
      ? `${cand.relatedAddress}${cand.relatedPort !== null ? `:${cand.relatedPort}` : ''} (${cand.relatedAddressInfo?.label || 'unknown'})`
      : '—';

    tbody.appendChild(
      el(
        'tr',
        null,
        el('td', null, el('code', { className: 'mono-cell', text: cand.address || 'Unknown' })),
        el('td', null, el('span', { className: `scope-tag ${scopeClass}`, text: cand.addressInfo.label })),
        el(
          'td',
          null,
          el('code', {
            className: 'mono-cell',
            text: `${cand.protocol.toUpperCase()}${cand.tcpType ? ` (${cand.tcpType})` : ''} : ${cand.port ?? '—'}`,
          })
        ),
        el('td', null, el('code', { className: 'mono-cell is-muted', text: raddrDisplay })),
        el('td', null, createCopyButton(() => cand.address || cand.raw, `Copy candidate ${cand.address}`))
      )
    );
  }

  table.appendChild(thead);
  table.appendChild(tbody);
  tableWrap.appendChild(table);
  section.appendChild(tableWrap);
  return section;
}

/**
 * Initialize Module 2: WebRTC Leak Tester.
 */
export function initWebRtcModule(container, { getHttpPublicIp } = {}) {
  let state = {
    status: 'idle', // idle | scanning | complete
    progressText: '',
    candidates: [],
    supported: true,
    gatheringTimedOut: false,
    error: null,
    timestamp: null,
    assessment: null,
    cleanedUp: false,
  };

  let activeCleanup = null;
  let activeScanId = 0;

  const statusBadge = el('span', { className: 'status-pill status-idle', text: 'Ready' });
  const timestampNode = el('span', { className: 'meta-timestamp', text: 'Not yet scanned' });
  const runBtn = el('button', { type: 'button', className: 'btn btn-primary', text: 'Run WebRTC Test' });
  const copyAllBtn = el('button', { type: 'button', className: 'btn btn-secondary', disabled: true, text: 'Copy Report' });
  const bodySlot = el('div', { className: 'module-body' });

  let copyResetTimer = null;
  copyAllBtn.addEventListener('click', async () => {
    if (!state.assessment) return;
    const { copyToClipboard } = await import('../lib/dom.js');
    const report = {
      scannedAt: state.timestamp?.iso || null,
      verdict: state.assessment.verdict,
      publicComparison: state.assessment.publicComparison,
      counts: state.assessment.counts,
      candidates: state.candidates.map((c) => ({
        type: c.type,
        protocol: c.protocol,
        address: c.address,
        classification: c.addressInfo.label,
        port: c.port,
        relatedAddress: c.relatedAddress,
      })),
    };
    const ok = await copyToClipboard(JSON.stringify(report, null, 2));
    if (copyResetTimer) clearTimeout(copyResetTimer);
    copyAllBtn.textContent = ok ? 'Copied Report' : 'Copy Failed';
    copyResetTimer = setTimeout(() => {
      copyAllBtn.textContent = 'Copy Report';
    }, 1800);
  });

  function setStatus(kind, text) {
    statusBadge.className = `status-pill status-${kind}`;
    statusBadge.textContent = text;
  }

  function renderIdle() {
    clearNode(bodySlot);
    bodySlot.appendChild(
      el(
        'div',
        { className: 'empty-state-box' },
        el('p', {
          className: 'empty-state-title',
          text: 'Ready to inspect WebRTC ICE candidates via RTCDataChannel (no camera/microphone permissions requested).',
        }),
        el('p', {
          className: 'empty-state-desc',
          text: 'When triggered, your browser creates a temporary RTCPeerConnection using stun:stun.l.google.com:19302, collects host/srflx/relay candidates, classifies private vs mDNS vs public addresses, and closes the peer connection immediately.',
        })
      )
    );
  }

  function renderScanning() {
    clearNode(bodySlot);
    bodySlot.appendChild(
      el(
        'div',
        { className: 'loading-banner', role: 'status', 'aria-live': 'polite' },
        el('span', { className: 'spinner', 'aria-hidden': 'true' }),
        el('div', null, el('div', { text: state.progressText }))
      )
    );
  }

  function renderResults() {
    clearNode(bodySlot);
    const { assessment } = state;
    if (!assessment) return;

    const { verdict, publicComparison, counts, exposedLocalIps, mdnsHostnames, publicWebRtcIps, groups } = assessment;

    // 1. Educational Verdict Banner (GREEN / YELLOW / RED)
    const bannerClass = verdict.level === 'green' ? 'verdict-green' : verdict.level === 'red' ? 'verdict-red' : 'verdict-yellow';
    const banner = el(
      'div',
      { className: `verdict-banner ${bannerClass}`, role: 'region', 'aria-label': 'WebRTC Educational Assessment' },
      el(
        'div',
        { className: 'verdict-top' },
        el('span', { className: `verdict-dot dot-${verdict.level}`, 'aria-hidden': 'true' }),
        el('span', { className: 'verdict-badge', text: `${verdict.level.toUpperCase()} — ${verdict.badge}` }),
        el('span', { className: 'verdict-disclaimer', text: 'Educational indicator, not a definitive security verdict' })
      ),
      el('h3', { className: 'verdict-title', text: verdict.title }),
      el('p', { className: 'verdict-summary', text: verdict.summary }),
      verdict.notes?.length
        ? el(
            'ul',
            { className: 'verdict-notes' },
            ...verdict.notes.map((n) => el('li', { text: n }))
          )
        : null
    );
    bodySlot.appendChild(banner);

    // 2. Key Comparison Tiles
    const httpIpText = publicComparison.httpIp || 'Not yet scanned (run Module 1)';
    const webrtcPublicText =
      publicWebRtcIps.length > 0 ? publicWebRtcIps.map((x) => x.address).join(', ') : 'None observed';
    const localIpText =
      exposedLocalIps.length > 0
        ? exposedLocalIps.map((x) => x.address).join(', ')
        : mdnsHostnames.length > 0
          ? `Masked (${mdnsHostnames.length} mDNS .local)`
          : 'None observed';

    const tiles = el(
      'div',
      { className: 'metrics-grid' },
      buildSummaryCard(
        'Public IP (HTTP Lookup)',
        httpIpText,
        'Public IP address observed by the HTTPS lookup API (ipwho.is) in Module 1.'
      ),
      buildSummaryCard(
        'Public IP (WebRTC STUN)',
        webrtcPublicText,
        'Server-reflexive (srflx) public IP returned via STUN binding to stun.l.google.com:19302.'
      ),
      buildSummaryCard(
        'Local / Private Exposure',
        localIpText,
        'Raw RFC 1918 (10/8, 172.16/12, 192.168/16) or IPv6 ULA (fc00::/7) addresses vs mDNS .local obfuscation.',
        exposedLocalIps.length > 0 ? 'is-alert' : mdnsHostnames.length > 0 ? 'is-caution' : ''
      ),
      buildSummaryCard(
        'mDNS Masking',
        mdnsHostnames.length > 0 ? `Active (${mdnsHostnames.length} .local hostnames)` : 'Not observed',
        'Modern browsers replace local interface IPs with temporary UUID.local hostnames when mic/cam permission has not been granted.'
      )
    );
    bodySlot.appendChild(tiles);

    // Public IP comparison detail strip
    bodySlot.appendChild(
      el(
        'div',
        { className: 'inline-alert is-info' },
        el('strong', { text: 'HTTP vs WebRTC Public Address Comparison: ' }),
        el('span', { text: publicComparison.summary })
      )
    );

    // 3. Candidate Groups
    const groupsWrap = el('div', { className: 'stack-md' });
    groupsWrap.appendChild(
      renderCandidateGroup(
        'Host Candidates (Local Interfaces & mDNS)',
        'Represent direct network interfaces on your device. Modern browsers commonly mask raw LAN IPs with .local mDNS hostnames.',
        groups.host
      )
    );
    groupsWrap.appendChild(
      renderCandidateGroup(
        'Server Reflexive Candidates (srflx via STUN)',
        'Represent your NAT-mapped public IP and port as seen by stun:stun.l.google.com:19302.',
        groups.srflx
      )
    );
    if (groups.relay.length > 0 || groups.other.length > 0) {
      groupsWrap.appendChild(
        renderCandidateGroup(
          'Relay & Other Candidates',
          'TURN relay or peer-reflexive candidates if present.',
          [...groups.relay, ...groups.other]
        )
      );
    }
    bodySlot.appendChild(groupsWrap);

    // Resource cleanup confirmation + VPN leak scenarios accordion
    bodySlot.appendChild(
      el(
        'div',
        { className: 'cleanup-bar' },
        el('span', {
          text: `Scan complete: ${counts.total} unique ICE candidate(s) parsed • RTCPeerConnection closed and resources released.`,
        })
      )
    );

    const details = el(
      'details',
      { className: 'tech-details' },
      el('summary', { text: 'Educational Guide: Understanding Candidate Types & VPN Leak Scenarios' }),
      el(
        'div',
        { className: 'tech-details-body' },
        ...WEBRTC_SCENARIOS.map((sc) =>
          el('div', { className: 'scenario-item' }, el('strong', { text: sc.title }), el('p', { text: sc.description }))
        )
      )
    );
    bodySlot.appendChild(details);
  }

  function refreshComparison() {
    if (state.status !== 'complete') return;
    const httpIp = typeof getHttpPublicIp === 'function' ? getHttpPublicIp() : null;
    state.assessment = assessWebRtcPrivacy({
      supported: state.supported,
      candidates: state.candidates,
      httpPublicIp: httpIp,
      gatheringTimedOut: state.gatheringTimedOut,
      error: state.error,
    });
    const v = state.assessment.verdict;
    setStatus(v.level === 'green' ? 'complete' : v.level === 'red' ? 'danger' : 'warn', v.badge);
    renderResults();
  }

  async function runTest() {
    if (activeCleanup) {
      activeCleanup();
      activeCleanup = null;
    }

    activeScanId += 1;
    const myScanId = activeScanId;

    state = {
      status: 'scanning',
      progressText: 'Initializing temporary RTCPeerConnection and RTCDataChannel...',
      candidates: [],
      supported: true,
      gatheringTimedOut: false,
      error: null,
      timestamp: null,
      assessment: null,
      cleanedUp: false,
    };

    runBtn.disabled = true;
    runBtn.textContent = 'Testing WebRTC...';
    copyAllBtn.disabled = true;
    setStatus('scanning', 'Gathering ICE');
    renderScanning();

    const PeerConn = window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection;
    if (typeof PeerConn !== 'function') {
      const ts = formatTimestamp(new Date());
      state.status = 'complete';
      state.supported = false;
      state.error = 'RTCPeerConnection is unavailable or disabled in this browser.';
      state.timestamp = ts;
      state.assessment = assessWebRtcPrivacy({
        supported: false,
        candidates: [],
        httpPublicIp: typeof getHttpPublicIp === 'function' ? getHttpPublicIp() : null,
        error: state.error,
      });
      timestampNode.textContent = `Scanned: ${ts.local}`;
      runBtn.disabled = false;
      runBtn.textContent = 'Run Again';
      copyAllBtn.disabled = false;
      setStatus('warn', 'Unavailable');
      renderResults();
      return state;
    }

    const candidates = [];
    const seenKeys = new Set();

    await new Promise((resolve) => {
      let pc = null;
      let dc = null;
      let timeoutId = null;
      let settled = false;

      const finish = (timedOut = false, errMsg = null) => {
        if (settled) return;
        settled = true;
        if (timeoutId) clearTimeout(timeoutId);
        if (dc) {
          try {
            dc.close();
          } catch {
            // ignore
          }
          dc = null;
        }
        if (pc) {
          pc.onicecandidate = null;
          pc.onicegatheringstatechange = null;
          pc.onicecandidateerror = null;
          try {
            pc.close();
          } catch {
            // ignore
          }
          pc = null;
        }
        activeCleanup = null;
        resolve({ timedOut, errMsg });
      };

      activeCleanup = () => finish(false, 'Scan cancelled.');

      try {
        pc = new PeerConn({ iceServers: STUN_SERVERS });
        dc = pc.createDataChannel('privacy-probe');

        pc.onicecandidate = (event) => {
          if (myScanId !== activeScanId) return;
          if (!event.candidate || !event.candidate.candidate) {
            finish(false, null);
            return;
          }
          const parsed = parseIceCandidate(event.candidate.candidate, event.candidate);
          if (parsed) {
            const key = candidateDedupeKey(parsed);
            if (!seenKeys.has(key)) {
              seenKeys.add(key);
              candidates.push(parsed);
              state.progressText = `Gathering ICE candidates via stun:stun.l.google.com:19302 (${candidates.length} discovered)...`;
              renderScanning();
            }
          }
        };

        pc.onicegatheringstatechange = () => {
          if (myScanId !== activeScanId || !pc) return;
          if (pc.iceGatheringState === 'complete') {
            finish(false, null);
          }
        };

        pc.onicecandidateerror = () => {
          // Non-fatal: individual STUN servers or interfaces may error while others succeed
        };

        timeoutId = setTimeout(() => {
          finish(true, null);
        }, GATHER_TIMEOUT_MS);

        pc.createOffer()
          .then((offer) => {
            if (settled || !pc) return;
            state.progressText = 'Offer created; waiting for ICE candidate gathering...';
            renderScanning();
            return pc.setLocalDescription(offer);
          })
          .catch((err) => {
            finish(false, err?.message || 'Failed to initiate RTCPeerConnection ICE gathering.');
          });
      } catch (err) {
        finish(false, err?.message || 'Unable to instantiate RTCPeerConnection.');
      }
    }).then(({ timedOut, errMsg }) => {
      if (myScanId !== activeScanId) return;

      const ts = formatTimestamp(new Date());
      const httpIp = typeof getHttpPublicIp === 'function' ? getHttpPublicIp() : null;

      state = {
        status: 'complete',
        progressText: '',
        candidates,
        supported: true,
        gatheringTimedOut: timedOut,
        error: errMsg,
        timestamp: ts,
        cleanedUp: true,
        assessment: assessWebRtcPrivacy({
          supported: true,
          candidates,
          httpPublicIp: httpIp,
          gatheringTimedOut: timedOut,
          error: errMsg,
        }),
      };

      const v = state.assessment.verdict;
      timestampNode.textContent = `Scanned: ${ts.local}`;
      runBtn.disabled = false;
      runBtn.textContent = 'Run Again';
      copyAllBtn.disabled = false;
      setStatus(v.level === 'green' ? 'complete' : v.level === 'red' ? 'danger' : 'warn', v.badge);
      renderResults();
    });

    return state;
  }

  function reset() {
    activeScanId += 1;
    if (activeCleanup) {
      activeCleanup();
      activeCleanup = null;
    }
    state = {
      status: 'idle',
      progressText: '',
      candidates: [],
      supported: true,
      gatheringTimedOut: false,
      error: null,
      timestamp: null,
      assessment: null,
      cleanedUp: false,
    };
    timestampNode.textContent = 'Not yet scanned';
    runBtn.disabled = false;
    runBtn.textContent = 'Run WebRTC Test';
    copyAllBtn.disabled = true;
    setStatus('idle', 'Ready');
    renderIdle();
  }

  runBtn.addEventListener('click', () => {
    runTest();
  });

  clearNode(container);
  container.appendChild(
    el(
      'div',
      { className: 'module-header' },
      el(
        'div',
        { className: 'module-title-block' },
        el('div', { className: 'module-kicker', text: 'MODULE 02 // PEER-TO-PEER & STUN DISCOVERY' }),
        el('h2', { className: 'module-title', text: 'WebRTC Leak Tester' }),
        el('p', {
          className: 'module-desc',
          text: 'Uses RTCPeerConnection and a data channel against Google’s public STUN server to inspect exposed host, mDNS, and server-reflexive candidates.',
        })
      ),
      el(
        'div',
        { className: 'module-controls' },
        el('div', { className: 'module-meta-row' }, statusBadge, timestampNode),
        el('div', { className: 'module-btn-row' }, runBtn, copyAllBtn)
      )
    )
  );
  container.appendChild(bodySlot);
  renderIdle();

  return {
    runTest,
    reset,
    refreshComparison,
    getState: () => state,
  };
}

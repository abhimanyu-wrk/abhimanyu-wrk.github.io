import { initFingerprintModule } from './modules/fingerprint.js';
import { initWebRtcModule } from './modules/webrtc.js';
import { initHeadersModule } from './modules/headers.js';
import { EDUCATION_TOPICS } from './data/education.js';
import { clearNode, el } from './lib/dom.js';

function renderEducationSection(container) {
  if (!container) return;
  clearNode(container);

  const grid = el('div', { className: 'education-grid' });
  for (const topic of EDUCATION_TOPICS) {
    const card = el(
      'article',
      { className: 'edu-card', id: `edu-${topic.id}` },
      el('h3', { className: 'edu-title', text: topic.title }),
      el('p', { className: 'edu-summary', text: topic.summary }),
      el('p', { className: 'edu-keypoint' }, el('strong', { text: 'Key takeaway: ' }), topic.keyPoint),
      el(
        'div',
        { className: 'edu-links' },
        ...topic.links.map((link) =>
          el('a', {
            href: link.url,
            target: '_blank',
            rel: 'noopener noreferrer',
            className: 'edu-link',
            text: link.label,
          })
        )
      )
    );
    grid.appendChild(card);
  }
  container.appendChild(grid);
}

function bootstrap() {
  const fpContainer = document.getElementById('module-fingerprint');
  const webrtcContainer = document.getElementById('module-webrtc');
  const headersContainer = document.getElementById('module-headers');
  const eduContainer = document.getElementById('education-grid-slot');

  const modePill = document.getElementById('nav-mode-pill');
  const runAllBtn = document.getElementById('btn-run-all');
  const resetAllBtns = document.querySelectorAll('[data-action="reset-all"]');

  const summaryFp = document.getElementById('summary-fp-status');
  const summaryRtc = document.getElementById('summary-rtc-status');
  const summaryHdr = document.getElementById('summary-hdr-status');

  let webrtcCtrl = null;

  const fpCtrl = initFingerprintModule(fpContainer, {
    onNetworkResult: (net) => {
      if (summaryFp) {
        summaryFp.textContent = net?.ok ? `Public IP: ${net.ip}` : 'Browser scanned (IP lookup failed)';
      }
      if (webrtcCtrl) {
        webrtcCtrl.refreshComparison();
      }
    },
  });

  webrtcCtrl = initWebRtcModule(webrtcContainer, {
    getHttpPublicIp: () => fpCtrl.getPublicIp(),
  });

  const headersCtrl = initHeadersModule(headersContainer, {
    onModeDetected: (mode) => {
      const isServer = mode === 'server';
      if (modePill) {
        modePill.textContent = isServer ? 'Mode: Live Server Capture' : 'Mode: Static (GitHub Pages)';
        modePill.className = `nav-mode-pill ${isServer ? 'is-server' : 'is-static'}`;
      }
      if (summaryHdr) {
        summaryHdr.textContent = isServer ? 'Server Document Capture' : 'Static Hosting (No Header Access)';
      }
    },
  });

  renderEducationSection(eduContainer);

  async function runFullPrivacyAnalysis() {
    if (!runAllBtn) return;
    runAllBtn.disabled = true;
    const labelSpan = runAllBtn.querySelector('.btn-label');
    if (labelSpan) labelSpan.textContent = 'Running Privacy Analysis...';

    if (summaryFp) summaryFp.textContent = 'Scanning...';
    if (summaryRtc) summaryRtc.textContent = 'Gathering ICE...';
    headersCtrl.restoreOrHighlight();

    try {
      await Promise.all([fpCtrl.runScan(), webrtcCtrl.runTest()]);
      const fpState = fpCtrl.getState();
      const rtcState = webrtcCtrl.getState();
      if (summaryFp) {
        summaryFp.textContent = fpState.network?.ok ? `IP: ${fpState.network.ip}` : 'Browser scanned (IP unavailable)';
      }
      if (summaryRtc && rtcState.assessment) {
        const v = rtcState.assessment.verdict;
        summaryRtc.textContent = `${v.level.toUpperCase()}: ${v.badge}`;
      }
    } finally {
      runAllBtn.disabled = false;
      if (labelSpan) labelSpan.textContent = 'Run Privacy Analysis';
    }
  }

  function resetAll() {
    fpCtrl.reset();
    webrtcCtrl.reset();
    headersCtrl.reset();
    if (summaryFp) summaryFp.textContent = 'Idle — Click Run Analysis';
    if (summaryRtc) summaryRtc.textContent = 'Idle — Click Run Analysis';
    if (summaryHdr) {
      summaryHdr.textContent = headersCtrl.isServerMode() ? 'Cleared (Reload for new capture)' : 'Cleared (Static Mode)';
    }
  }

  if (runAllBtn) {
    runAllBtn.addEventListener('click', runFullPrivacyAnalysis);
  }
  for (const btn of resetAllBtns) {
    btn.addEventListener('click', resetAll);
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', bootstrap);
} else {
  bootstrap();
}

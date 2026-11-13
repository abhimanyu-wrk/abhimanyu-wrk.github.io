# What Your Browser Reveals

An interactive browser privacy, fingerprinting, WebRTC leak testing, and HTTP header inspection laboratory built as a cybersecurity portfolio project for [`abhimanyu-wrk.github.io`](https://github.com/abhimanyu-wrk/abhimanyu-wrk.github.io).

> **Zero tracking & zero persistence:** This project runs privacy probes only after explicit visitor actions, computes no persistent visitor IDs, uses no cookies or `localStorage`, performs no canvas/audio fingerprinting, and never stores or logs visitor telemetry.

---

## Architecture & Project Structure

The frontend is built with **zero-dependency vanilla HTML, CSS, and native ES Modules**, allowing it to run directly on GitHub Pages without a build step, while an **optional Node.js/Express backend** provides true server-side capture of initial HTML document navigation headers.

```text
abhimanyu-wrk.github.io/
├── .github/workflows/
│   └── deploy-pages.yml         # GitHub Actions workflow deploying only static frontend files
├── .nojekyll                    # Disables Jekyll processing on GitHub Pages
├── index.html                   # Main dashboard shell & static/server JSON inspection slot
├── favicon.svg                  # Custom SVG shield/node icon
├── css/
│   ├── tokens.css               # Dark security-lab color, typography, and spacing tokens
│   ├── base.css                 # Reset, responsive container, keyboard focus outlines
│   └── components.css           # Cards, status pills, tables, tooltips, educational drawers
├── js/
│   ├── main.js                  # Application bootstrap, full analysis & reset orchestration
│   ├── data/
│   │   └── education.js         # Technical Q&A content and MDN/W3C references
│   ├── lib/
│   │   ├── dom.js               # Safe textContent-only DOM builders, clipboard, accessible tooltips
│   │   ├── fingerprintUtils.js  # Battery & IP geolocation payload normalization
│   │   ├── headerUtils.js       # HTTP header descriptions & safe payload parsing
│   │   ├── ipUtils.js           # IPv4/IPv6/CIDR/mDNS classification & ICE SDP parser
│   │   └── uaParser.js          # User-Agent & Client Hints parser
│   └── modules/
│       ├── fingerprint.js       # Module 1: Browser Fingerprinting Simulator
│       ├── webrtc.js            # Module 2: WebRTC Leak Tester
│       └── headers.js           # Module 3: HTTP Header Inspector (Mode A Static vs Mode B Server)
├── server/
│   ├── app.js                   # Express app factory (serves static assets & injects document headers)
│   ├── headerInspector.js       # Raw header redaction, trust-proxy logic & XSS-safe JSON escaping
│   ├── index.js                 # Node.js server entrypoint
│   └── .env.example             # Optional environment configuration reference
├── scripts/
│   └── static-preview.mjs       # Local static preview server (simulates GitHub Pages Mode A)
├── tests/
│   ├── fingerprintUtils.test.js # Unit tests for Battery & IP lookup error handling
│   ├── headerInspector.test.js  # Unit tests for redaction, XSS escaping, and trust proxy parsing
│   ├── ipUtils.test.js          # Unit tests for RFC 1918, ULA, mDNS, ICE SDP parsing & verdicts
│   ├── server.test.js           # Integration tests against the Express app
│   └── uaParser.test.js         # Unit tests for User-Agent parsing
└── package.json
```

---

## Analysis Modules

### 1. Browser Fingerprinting Simulator (`js/modules/fingerprint.js`)
- **Network & Approximate IP Geolocation:** Queries `https://ipwho.is/` (with resilient CORS fallbacks to `get.geojs.io`, `freeipapi.com`, and IP-only `api64.ipify.org`) only when the visitor triggers a scan. Handles network blocks, HTTP 429 rate limits, timeouts, and malformed payloads gracefully. Clearly states that IP geolocation is approximate and **never** automatically requests `navigator.geolocation` (a separate opt-in button lets visitors test browser GPS/Wi-Fi geolocation manually).
- **Browser & Hardware:** Collects `userAgent`, parsed browser/OS, `platform`, `language`, `languages`, `cookieEnabled`, JS status, `hardwareConcurrency`, and `deviceMemory`, handling unavailable properties without fabricating zero values.
- **Display & Viewport:** Collects `screen.width/height`, `availWidth/availHeight`, `innerWidth/innerHeight`, `devicePixelRatio`, `colorDepth`, and `screen.orientation`.
- **Battery Status API:** Queries `navigator.getBattery()` when available and displays `"Not supported by this browser"` in browsers such as Firefox or Safari without fabricating values.

### 2. WebRTC Leak Tester (`js/modules/webrtc.js`)
- Opens an actual `RTCPeerConnection` with an `RTCDataChannel` (`stun:stun.l.google.com:19302`) — requesting **no** microphone or camera permissions.
- Parses and classifies ICE candidates (`host`, `srflx`, `relay`, `prflx`), distinguishing **IPv4**, **IPv6**, and **mDNS `.local` hostnames** (`<uuid>.local`), and checking RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and IPv6 ULA (`fc00::/7`) ranges.
- Compares HTTP-observed public IP against WebRTC `srflx` public IP, displays an educational **GREEN / YELLOW / RED** indicator, and immediately closes the `RTCDataChannel` and `RTCPeerConnection`.

### 3. HTTP Header Inspector (`js/modules/headers.js`)
Operates in two explicitly distinguished modes:
- **Mode A — Static GitHub Pages:** Frontend JavaScript cannot access the original HTTP headers sent by the browser when loading `index.html`. Mode A explains this architectural boundary instead of fabricating headers.
- **Mode B — Optional Node.js/Express Server:** When the page itself is served by `server/index.js`, Express captures `GET /` headers via `req.rawHeaders`, redacts sensitive values (`Cookie`, `Authorization`, `Proxy-Authorization`, `X-API-Key`, etc.) by default, and injects the sanitized JSON into `<script id="__INITIAL_REQUEST_INSPECTION__" type="application/json">` using XSS-safe unicode escaping (`\u003c`, `\u003e`, `\u0026`).
- **Secondary `/api/headers` Endpoint:** Optional probe button clearly labeled as a *secondary JS `fetch()` request*, illustrating how API fetch headers (`Sec-Fetch-Mode: cors`, `Sec-Fetch-Dest: empty`) differ from initial document navigation headers (`navigate`, `document`).

---

## Local Development & Running

### Prerequisites
- **Node.js 20+** (tested on Node.js 24)
- Dependencies needed only for the optional backend (`express`):

```bash
npm install
```

### Option 1: Run Optional Node.js Server (Mode B — Full HTTP Document Header Capture)
```bash
npm start
```
Then open `http://127.0.0.1:3000` in your browser.

### Option 2: Run Static Preview (Mode A — Simulates GitHub Pages)
```bash
npm run preview:static
```
Then open `http://127.0.0.1:4173` in your browser. This serves `index.html` unmodified to verify Static Mode behavior.

### Run Automated Tests
```bash
npm test
```

---

## Exposing the Optional Backend with `ngrok`

To inspect real browser headers across a public HTTPS URL (Mode B):

1. Start the Node.js backend with `TRUST_PROXY=1` so Express accurately reads the client IP forwarded by ngrok's single reverse-proxy hop:
   - **PowerShell:**
     ```powershell
     $env:TRUST_PROXY="1"; npm start
     ```
   - **bash / zsh:**
     ```bash
     TRUST_PROXY=1 npm start
     ```
2. Start an ngrok tunnel pointing to port `3000`:
   ```bash
   ngrok http 3000
   ```
3. **Visit the ngrok HTTPS URL directly in your browser** (e.g., `https://<random-id>.ngrok-free.app`).

### Important Architectural Note on `ngrok` + GitHub Pages
- **Direct ngrok visit (`Browser -> ngrok -> Node.js server -> Portfolio Page`):** Captures the genuine initial HTML document navigation headers (`Sec-Fetch-Mode: navigate`, `Sec-Fetch-Dest: document`, `Upgrade-Insecure-Requests`, etc.).
- **Calling ngrok from GitHub Pages (`Browser -> GitHub Pages` + separate `fetch(ngrok/api/headers)`):** Because the browser already loaded `index.html` from GitHub Pages, a subsequent background `fetch()` to ngrok only reveals the headers of that secondary CORS request — **not** the original HTML page-load headers. To experiment with this secondary comparison from GitHub Pages, configure `CORS_ORIGIN=https://abhimanyu-wrk.github.io` when starting the Node.js server.

---

## GitHub Pages Deployment

1. Push this repository to `https://github.com/abhimanyu-wrk/abhimanyu-wrk.github.io` on the `main` branch.
2. In GitHub repository settings under **Settings -> Pages -> Source**:
   - **Recommended:** Select **GitHub Actions**. The included workflow `.github/workflows/deploy-pages.yml` stages only `index.html`, `favicon.svg`, `.nojekyll`, `css/`, and `js/` into `_site/` and publishes them cleanly without exposing `server/` or `tests/`.
   - **Alternative:** Select **Deploy from a branch** (`main` / `/ (root)`), which also works directly because `index.html` and assets live at the repository root.

### Static Deployment Limitations
- GitHub Pages hosts static files on a CDN without server-side request execution, so **Mode B (original HTML navigation header capture)** cannot operate solely on GitHub Pages.
- Public IP lookup relies on external CORS-enabled HTTPS providers (`ipwho.is`, fallback `api64.ipify.org`); strict ad-blockers or offline environments may block that external request, in which case local browser/display/battery and WebRTC tests still function.

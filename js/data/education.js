/**
 * Technical educational explanations and authoritative MDN / W3C / RFC reference links.
 */

export const EDUCATION_TOPICS = [
  {
    id: 'fingerprinting',
    title: 'What is browser fingerprinting?',
    summary:
      'Browser fingerprinting is the technique of combining dozens of seemingly ordinary browser, hardware, display, and network attributes—such as user agent, screen resolution, timezone, language list, and CPU cores—to build a statistical profile that distinguishes one device or browser configuration from others without setting cookies.',
    keyPoint:
      'Even when individual properties (like 24-bit color depth) are shared by millions of people, combining many orthogonal signals shrinks the anonymity set rapidly.',
    links: [
      { label: 'MDN: Fingerprinting & Mitigating Browser Fingerprinting', url: 'https://developer.mozilla.org/en-US/docs/Glossary/Fingerprinting' },
      { label: 'W3C: Mitigating Browser Fingerprinting in Web Specifications', url: 'https://www.w3.org/TR/fingerprinting-guidance/' },
    ],
  },
  {
    id: 'public-ip',
    title: 'How can a website learn your public IP?',
    summary:
      'Every TCP/UDP/HTTP connection your browser opens must carry a source IP address so servers know where to send packets back. Websites and embedded third-party resources (APIs, images, CDNs) immediately see the public IP address of your ISP connection—or of your VPN/proxy exit server—at the network layer.',
    keyPoint:
      'IP geolocation maps that address to a city or region using ISP allocation registries, which is approximate and reflects network exit topology rather than physical GPS.',
    links: [
      { label: 'MDN: An overview of HTTP', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Overview' },
      { label: 'W3C: Geolocation API Specification', url: 'https://www.w3.org/TR/geolocation/' },
    ],
  },
  {
    id: 'webrtc-exposure',
    title: 'How does WebRTC potentially expose network information?',
    summary:
      'WebRTC establishes peer-to-peer media or data channels by discovering candidate IP addresses and ports across your network interfaces and querying STUN servers. If a browser exposes raw interface addresses or routes STUN UDP traffic outside an active VPN tunnel, scripts can observe internal LAN addresses or an unexpected public exit IP.',
    keyPoint:
      'Discovering a local RFC 1918 address (e.g. 192.168.x.x) reveals internal network topology, whereas a VPN exit leak specifically occurs if STUN reveals your real ISP public IP instead of your VPN exit IP.',
    links: [
      { label: 'MDN: WebRTC API', url: 'https://developer.mozilla.org/en-US/docs/Web/API/WebRTC_API' },
      { label: 'W3C: WebRTC 1.0 Real-Time Communication Between Browsers', url: 'https://www.w3.org/TR/webrtc/' },
    ],
  },
  {
    id: 'ice-candidates',
    title: 'What are ICE candidates?',
    summary:
      'Interactive Connectivity Establishment (ICE) candidates are potential network address-and-port pairs gathered by RTCPeerConnection to reach a peer. Host candidates represent local interfaces (or mDNS-masked .local aliases), server-reflexive (srflx) candidates represent the public NAT address observed by a STUN server, and relay candidates traverse a TURN server.',
    keyPoint:
      'Modern browsers often replace raw local host IPs with ephemeral .local mDNS hostnames so scripts cannot read your LAN IP without explicit media permissions.',
    links: [
      { label: 'MDN: RTCIceCandidate', url: 'https://developer.mozilla.org/en-US/docs/Web/API/RTCIceCandidate' },
      { label: 'MDN: WebRTC Connectivity & ICE', url: 'https://developer.mozilla.org/en-US/docs/Web/API/WebRTC_API/Connectivity' },
    ],
  },
  {
    id: 'http-headers',
    title: 'What is an HTTP request header?',
    summary:
      'HTTP request headers are key-value metadata sent by your browser alongside every page navigation or API fetch—describing your User-Agent, preferred languages, supported compression, caching posture, Fetch Metadata (Sec-Fetch-*), and Client Hints (Sec-CH-UA). Only the receiving server (not static frontend JavaScript) can read the original HTML document navigation headers.',
    keyPoint:
      'Document navigation requests carry distinct headers (such as Sec-Fetch-Mode: navigate and Sec-Fetch-Dest: document) compared to background fetch() requests.',
    links: [
      { label: 'MDN: HTTP Headers Reference', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers' },
      { label: 'MDN: Fetch Metadata Request Headers', url: 'https://developer.mozilla.org/en-US/docs/Glossary/Fetch_metadata_request_header' },
    ],
  },
  {
    id: 'vpn-effects',
    title: 'How can a VPN affect the information websites observe?',
    summary:
      'A properly configured VPN replaces your visible public IP and approximate IP geolocation with the VPN server’s exit address and location. However, a VPN does not alter client-side browser properties such as screen size, installed language preferences, hardware concurrency, timezone offsets, or User-Agent strings.',
    keyPoint:
      'If your OS timezone or Accept-Language conflicts starkly with your VPN exit country, or if IPv6/STUN traffic bypasses the tunnel (split-tunneling), websites can still notice discrepancies.',
    links: [
      { label: 'MDN: User-Agent Client Hints & Privacy', url: 'https://developer.mozilla.org/en-US/docs/Web/API/User-Agent_Client_Hints_API' },
      { label: 'W3C: Privacy Principles', url: 'https://www.w3.org/TR/privacy-principles/' },
    ],
  },
  {
    id: 'browser-restrictions',
    title: 'Why do modern browsers restrict certain information?',
    summary:
      'Browser vendors and standards bodies have deprecated, reduced, or gated high-entropy APIs to curb passive tracking. Examples include removing navigator.getBattery() in Firefox and Safari, freezing minor OS/version details in User-Agent strings, capping deviceMemory, and obfuscating WebRTC local IPs with mDNS.',
    keyPoint:
      'Different browsers strike different balances—comparing Chrome, Firefox, and Safari in this lab shows how privacy defenses change what APIs expose.',
    links: [
      { label: 'MDN: Battery Status API (Availability & Privacy)', url: 'https://developer.mozilla.org/en-US/docs/Web/API/Battery_Status_API' },
      { label: 'MDN: Navigator.deviceMemory', url: 'https://developer.mozilla.org/en-US/docs/Web/API/Navigator/deviceMemory' },
    ],
  },
];

export const WEBRTC_SCENARIOS = [
  {
    title: 'Consistent Routing (Expected VPN or Direct Connection)',
    description:
      'HTTP lookup public IP and WebRTC srflx public IP are identical, and host candidates are masked via mDNS (.local) or absent.',
  },
  {
    title: 'Dual-Stack IPv4 / IPv6 Split',
    description:
      'If a VPN only tunnels IPv4 traffic while IPv6 remains direct on your ISP, HTTP lookup may report an IPv4 VPN exit while WebRTC STUN observes your native IPv6 address (or vice versa).',
  },
  {
    title: 'Private LAN Exposure vs Public Leak',
    description:
      'Seeing 192.168.x.x or 10.x.x.x means local interface enumeration was not masked by mDNS. It exposes internal subnet info, which is distinct from leaking your real public ISP IP.',
  },
  {
    title: 'STUN / UDP Blocked',
    description:
      'Corporate firewalls, strict VPN kill switches, or hardened browsers may block UDP to STUN servers, yielding zero srflx candidates.',
  },
];

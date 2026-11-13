/**
 * Pure IP address classification, mDNS detection, WebRTC SDP ICE candidate parsing,
 * and educational WebRTC leak assessment helpers.
 * Safe for both browser ES modules and Node.js unit tests.
 */

/**
 * Check whether an address string is an RFC 6762 mDNS obfuscated hostname (e.g. `<uuid>.local`).
 * Must not match IPv4/IPv6 literals.
 * @param {string} value
 * @returns {boolean}
 */
export function isMdnsHostname(value) {
  if (typeof value !== 'string') return false;
  const trimmed = value.trim().toLowerCase();
  if (!trimmed.endsWith('.local')) return false;
  if (trimmed.includes(':')) return false;
  const hostPart = trimmed.slice(0, -'.local'.length);
  if (!hostPart || hostPart.length > 253) return false;
  // Each DNS label: 1..63 chars of [a-z0-9-], cannot start or end with '-'
  const labels = hostPart.split('.');
  return labels.every(
    (label) => label.length >= 1 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
  );
}

/**
 * Parse a strict dotted-quad IPv4 address into an unsigned 32-bit integer, or null if invalid.
 * @param {string} value
 * @returns {number|null}
 */
export function parseIPv4(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  const parts = trimmed.split('.');
  if (parts.length !== 4) return null;

  let num = 0;
  for (const part of parts) {
    if (!/^(0|[1-9]\d{0,2})$/.test(part)) return null;
    const octet = Number(part);
    if (octet < 0 || octet > 255) return null;
    num = (num * 256) + octet;
  }
  return num >>> 0;
}

/**
 * @param {string} value
 * @returns {boolean}
 */
export function isValidIPv4(value) {
  return parseIPv4(value) !== null;
}

/**
 * Classify a valid IPv4 address by network scope.
 * @param {string} value
 */
export function classifyIPv4(value) {
  const num = parseIPv4(value);
  if (num === null) {
    return { valid: false, family: 'IPv4', scope: 'invalid', label: 'Invalid IPv4', isPrivateOrLocal: false };
  }

  const first = (num >>> 24) & 0xff;
  const second = (num >>> 16) & 0xff;

  if (num === 0 || first === 0) {
    return {
      valid: true,
      family: 'IPv4',
      scope: 'unspecified',
      label: 'Unspecified (0.0.0.0/8)',
      isPrivateOrLocal: false,
    };
  }
  if (first === 10) {
    return {
      valid: true,
      family: 'IPv4',
      scope: 'private-rfc1918',
      label: 'Private LAN (RFC 1918: 10.0.0.0/8)',
      isPrivateOrLocal: true,
    };
  }
  if (first === 172 && second >= 16 && second <= 31) {
    return {
      valid: true,
      family: 'IPv4',
      scope: 'private-rfc1918',
      label: 'Private LAN (RFC 1918: 172.16.0.0/12)',
      isPrivateOrLocal: true,
    };
  }
  if (first === 192 && second === 168) {
    return {
      valid: true,
      family: 'IPv4',
      scope: 'private-rfc1918',
      label: 'Private LAN (RFC 1918: 192.168.0.0/16)',
      isPrivateOrLocal: true,
    };
  }
  if (first === 169 && second === 254) {
    return {
      valid: true,
      family: 'IPv4',
      scope: 'link-local',
      label: 'Link-Local (169.254.0.0/16)',
      isPrivateOrLocal: true,
    };
  }
  if (first === 127) {
    return {
      valid: true,
      family: 'IPv4',
      scope: 'loopback',
      label: 'Loopback (127.0.0.0/8)',
      isPrivateOrLocal: true,
    };
  }
  if (first === 100 && second >= 64 && second <= 127) {
    return {
      valid: true,
      family: 'IPv4',
      scope: 'cgnat',
      label: 'Carrier-Grade NAT (RFC 6598: 100.64.0.0/10)',
      isPrivateOrLocal: false,
    };
  }
  if (first >= 224) {
    return {
      valid: true,
      family: 'IPv4',
      scope: 'reserved',
      label: 'Multicast / Reserved IPv4',
      isPrivateOrLocal: false,
    };
  }

  return {
    valid: true,
    family: 'IPv4',
    scope: 'public',
    label: 'Public IPv4',
    isPrivateOrLocal: false,
  };
}

/**
 * Strip optional IPv6 zone identifier (e.g. `fe80::1%eth0` -> `fe80::1`).
 * @param {string} value
 * @returns {string}
 */
export function stripIpv6Zone(value) {
  if (typeof value !== 'string') return '';
  const trimmed = value.trim().replace(/^\[|\]$/g, '');
  const zoneIdx = trimmed.indexOf('%');
  return zoneIdx === -1 ? trimmed : trimmed.slice(0, zoneIdx);
}

/**
 * Parse an IPv6 address into 8 16-bit integer groups, or null if invalid.
 * Supports `::` compression, zone identifiers, and embedded trailing IPv4 (e.g. `::ffff:192.0.2.1`).
 * @param {string} value
 * @returns {number[]|null}
 */
export function parseIPv6(value) {
  if (typeof value !== 'string') return null;
  const cleaned = stripIpv6Zone(value);
  if (!cleaned || !cleaned.includes(':')) return null;

  const doubleColonParts = cleaned.split('::');
  if (doubleColonParts.length > 2) return null;

  const parseSegmentList = (segmentStr) => {
    if (!segmentStr) return [];
    const tokens = segmentStr.split(':');
    const groups = [];
    for (let i = 0; i < tokens.length; i += 1) {
      const token = tokens[i];
      if (!token) return null;
      if (token.includes('.')) {
        // Embedded IPv4 allowed only as final token
        if (i !== tokens.length - 1) return null;
        const ipv4 = parseIPv4(token);
        if (ipv4 === null) return null;
        groups.push((ipv4 >>> 16) & 0xffff, ipv4 & 0xffff);
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(token)) return null;
        groups.push(parseInt(token, 16));
      }
    }
    return groups;
  };

  if (doubleColonParts.length === 1) {
    const groups = parseSegmentList(doubleColonParts[0]);
    if (!groups || groups.length !== 8) return null;
    return groups;
  }

  const head = parseSegmentList(doubleColonParts[0]);
  const tail = parseSegmentList(doubleColonParts[1]);
  if (!head || !tail) return null;
  const missing = 8 - (head.length + tail.length);
  if (missing < 1) return null;

  return [...head, ...new Array(missing).fill(0), ...tail];
}

/**
 * @param {string} value
 * @returns {boolean}
 */
export function isValidIPv6(value) {
  return parseIPv6(value) !== null;
}

/**
 * Classify an IPv6 address by network scope.
 * @param {string} value
 */
export function classifyIPv6(value) {
  const groups = parseIPv6(value);
  if (!groups) {
    return { valid: false, family: 'IPv6', scope: 'invalid', label: 'Invalid IPv6', isPrivateOrLocal: false };
  }

  const isAllZeroExceptLast = groups.slice(0, 7).every((g) => g === 0);
  if (isAllZeroExceptLast && groups[7] === 0) {
    return {
      valid: true,
      family: 'IPv6',
      scope: 'unspecified',
      label: 'Unspecified (::)',
      isPrivateOrLocal: false,
    };
  }
  if (isAllZeroExceptLast && groups[7] === 1) {
    return {
      valid: true,
      family: 'IPv6',
      scope: 'loopback',
      label: 'Loopback (::1)',
      isPrivateOrLocal: true,
    };
  }

  // IPv4-mapped IPv6 ::ffff:0:0/96
  if (
    groups[0] === 0 &&
    groups[1] === 0 &&
    groups[2] === 0 &&
    groups[3] === 0 &&
    groups[4] === 0 &&
    groups[5] === 0xffff
  ) {
    const ipv4Str = [
      (groups[6] >>> 8) & 0xff,
      groups[6] & 0xff,
      (groups[7] >>> 8) & 0xff,
      groups[7] & 0xff,
    ].join('.');
    const v4Info = classifyIPv4(ipv4Str);
    return {
      valid: true,
      family: 'IPv6',
      scope: v4Info.scope,
      label: `IPv4-Mapped IPv6 (${v4Info.label})`,
      isPrivateOrLocal: v4Info.isPrivateOrLocal,
    };
  }

  const first = groups[0];
  // fc00::/7 -> Unique Local Address (ULA)
  if ((first & 0xfe00) === 0xfc00) {
    return {
      valid: true,
      family: 'IPv6',
      scope: 'ula',
      label: 'Unique Local Address (ULA fc00::/7)',
      isPrivateOrLocal: true,
    };
  }
  // fe80::/10 -> Link-local
  if ((first & 0xffc0) === 0xfe80) {
    return {
      valid: true,
      family: 'IPv6',
      scope: 'link-local',
      label: 'Link-Local IPv6 (fe80::/10)',
      isPrivateOrLocal: true,
    };
  }
  // ff00::/8 -> Multicast
  if ((first & 0xff00) === 0xff00) {
    return {
      valid: true,
      family: 'IPv6',
      scope: 'multicast',
      label: 'Multicast IPv6 (ff00::/8)',
      isPrivateOrLocal: false,
    };
  }
  // 2001:db8::/32 -> Documentation
  if (first === 0x2001 && groups[1] === 0x0db8) {
    return {
      valid: true,
      family: 'IPv6',
      scope: 'documentation',
      label: 'Documentation Prefix (2001:db8::/32)',
      isPrivateOrLocal: false,
    };
  }

  return {
    valid: true,
    family: 'IPv6',
    scope: 'public',
    label: 'Public IPv6',
    isPrivateOrLocal: false,
  };
}

/**
 * Classify any WebRTC candidate connection-address (mDNS hostname, IPv4, or IPv6).
 * @param {string} raw
 */
export function classifyAddress(raw) {
  if (typeof raw !== 'string' || !raw.trim()) {
    return {
      kind: 'unknown',
      address: '',
      family: 'Unknown',
      scope: 'unknown',
      label: 'Empty Address',
      isPrivateOrLocal: false,
      isPublicIp: false,
    };
  }

  const trimmed = raw.trim();

  // Check mDNS before IP parsing so `.local` hostnames are never treated as IP literals
  if (isMdnsHostname(trimmed)) {
    return {
      kind: 'mdns',
      address: trimmed,
      family: 'mDNS',
      scope: 'mdns-masked',
      label: 'mDNS Hostname (Masked Local Address)',
      isPrivateOrLocal: false,
      isPublicIp: false,
    };
  }

  if (isValidIPv4(trimmed)) {
    const info = classifyIPv4(trimmed);
    return {
      kind: 'ip',
      address: trimmed,
      family: info.family,
      scope: info.scope,
      label: info.label,
      isPrivateOrLocal: info.isPrivateOrLocal,
      isPublicIp: info.scope === 'public',
    };
  }

  const normalizedV6 = stripIpv6Zone(trimmed);
  if (isValidIPv6(normalizedV6)) {
    const info = classifyIPv6(normalizedV6);
    return {
      kind: 'ip',
      address: normalizedV6,
      rawAddress: trimmed,
      family: info.family,
      scope: info.scope,
      label: info.label,
      isPrivateOrLocal: info.isPrivateOrLocal,
      isPublicIp: info.scope === 'public',
    };
  }

  return {
    kind: 'unknown',
    address: trimmed,
    family: 'Unknown',
    scope: 'unknown',
    label: 'Unrecognized Address Format',
    isPrivateOrLocal: false,
    isPublicIp: false,
  };
}

/**
 * Parse an RFC 8445 / RFC 5245 ICE candidate SDP line (with optional RTCIceCandidate metadata fallback).
 * Format: `candidate:<foundation> <component> <protocol> <priority> <address> <port> typ <type> [raddr <addr>] [rport <port>] ...`
 * @param {string} candidateLine
 * @param {object} [candidateMeta]
 */
export function parseIceCandidate(candidateLine, candidateMeta = null) {
  if (typeof candidateLine !== 'string' || !candidateLine.trim()) {
    return null;
  }

  const cleanLine = candidateLine.trim().replace(/^a=/, '');
  const parts = cleanLine.split(/\s+/);
  if (parts.length < 8 || !parts[0].startsWith('candidate:')) {
    return null;
  }

  const foundation = parts[0].slice('candidate:'.length);
  const component = Number.parseInt(parts[1], 10);
  const protocol = (parts[2] || '').toLowerCase();
  const priority = Number.parseInt(parts[3], 10);
  const rawAddress = parts[4] || (candidateMeta?.address ?? '');
  const port = Number.parseInt(parts[5], 10);

  let type = candidateMeta?.type ?? 'unknown';
  let relatedAddressRaw = candidateMeta?.relatedAddress ?? null;
  let relatedPort = candidateMeta?.relatedPort ?? null;
  let tcpType = candidateMeta?.tcpType ?? null;

  for (let i = 6; i < parts.length; i += 1) {
    const key = parts[i];
    const next = parts[i + 1];
    if (key === 'typ' && next) {
      type = next.toLowerCase();
      i += 1;
    } else if (key === 'raddr' && next) {
      relatedAddressRaw = next;
      i += 1;
    } else if (key === 'rport' && next) {
      const parsedPort = Number.parseInt(next, 10);
      relatedPort = Number.isNaN(parsedPort) ? null : parsedPort;
      i += 1;
    } else if (key === 'tcptype' && next) {
      tcpType = next.toLowerCase();
      i += 1;
    }
  }

  const addressInfo = classifyAddress(rawAddress);
  const relatedAddressInfo = relatedAddressRaw ? classifyAddress(relatedAddressRaw) : null;

  return {
    foundation,
    component: Number.isNaN(component) ? null : component,
    protocol: protocol || 'unknown',
    priority: Number.isNaN(priority) ? null : priority,
    address: addressInfo.address,
    addressInfo,
    port: Number.isNaN(port) ? null : port,
    type,
    relatedAddress: relatedAddressInfo ? relatedAddressInfo.address : null,
    relatedAddressInfo,
    relatedPort,
    tcpType,
    raw: cleanLine,
  };
}

/**
 * Assess collected WebRTC ICE candidates alongside an optional HTTP-observed public IP.
 * Educational evaluation only — not a definitive VPN security verdict.
 */
export function assessWebRtcPrivacy({
  supported = true,
  candidates = [],
  httpPublicIp = null,
  gatheringTimedOut = false,
  error = null,
}) {
  const hostCandidates = [];
  const srflxCandidates = [];
  const relayCandidates = [];
  const otherCandidates = [];

  const exposedLocalIpMap = new Map();
  const mdnsSet = new Set();
  const publicWebRtcIpMap = new Map();

  for (const cand of candidates) {
    if (cand.type === 'host') hostCandidates.push(cand);
    else if (cand.type === 'srflx') srflxCandidates.push(cand);
    else if (cand.type === 'relay') relayCandidates.push(cand);
    else otherCandidates.push(cand);

    const checkAddress = (info, sourceLabel) => {
      if (!info || !info.address) return;
      if (info.kind === 'mdns') {
        mdnsSet.add(info.address);
      } else if (info.kind === 'ip') {
        if (info.isPrivateOrLocal && info.scope !== 'loopback') {
          if (!exposedLocalIpMap.has(info.address)) {
            exposedLocalIpMap.set(info.address, { ...info, source: sourceLabel });
          }
        }
        if (info.isPublicIp && (cand.type === 'srflx' || cand.type === 'host')) {
          if (!publicWebRtcIpMap.has(info.address)) {
            publicWebRtcIpMap.set(info.address, { ...info, candidateType: cand.type });
          }
        }
      }
    };

    checkAddress(cand.addressInfo, `${cand.type} candidate`);
    if (cand.relatedAddressInfo && cand.relatedAddressInfo.scope !== 'unspecified') {
      checkAddress(cand.relatedAddressInfo, `${cand.type} raddr`);
    }
  }

  const exposedLocalIps = Array.from(exposedLocalIpMap.values());
  const mdnsHostnames = Array.from(mdnsSet.values());
  const publicWebRtcIps = Array.from(publicWebRtcIpMap.values());

  // Normalize HTTP public IP for exact comparison
  const normalizedHttpIp = typeof httpPublicIp === 'string' && httpPublicIp.trim()
    ? classifyAddress(httpPublicIp.trim())
    : null;

  let publicComparison;
  if (publicWebRtcIps.length === 0) {
    publicComparison = {
      status: 'no-webrtc-public',
      httpIp: normalizedHttpIp?.kind === 'ip' ? normalizedHttpIp.address : null,
      webrtcIps: [],
      summary: 'No public (srflx) WebRTC IP address was observed during ICE gathering.',
    };
  } else if (!normalizedHttpIp || normalizedHttpIp.kind !== 'ip') {
    publicComparison = {
      status: 'no-http-ip',
      httpIp: null,
      webrtcIps: publicWebRtcIps.map((x) => x.address),
      summary: 'WebRTC observed a public IP, but the HTTP IP lookup has not completed or failed, so cross-comparison is unavailable.',
    };
  } else {
    const exactMatch = publicWebRtcIps.some((x) => x.address.toLowerCase() === normalizedHttpIp.address.toLowerCase());
    if (exactMatch && publicWebRtcIps.length === 1) {
      publicComparison = {
        status: 'match',
        httpIp: normalizedHttpIp.address,
        webrtcIps: publicWebRtcIps.map((x) => x.address),
        summary: 'The public address observed by WebRTC STUN matches the public IP from the HTTP lookup.',
      };
    } else if (exactMatch && publicWebRtcIps.length > 1) {
      publicComparison = {
        status: 'dual-stack-mismatch',
        httpIp: normalizedHttpIp.address,
        webrtcIps: publicWebRtcIps.map((x) => x.address),
        summary: 'Multiple public addresses were observed by WebRTC (such as both IPv4 and IPv6), including one that matches the HTTP lookup.',
      };
    } else {
      const hasFamilyDiff = publicWebRtcIps.some((x) => x.family !== normalizedHttpIp.family);
      publicComparison = {
        status: hasFamilyDiff ? 'dual-stack-mismatch' : 'mismatch',
        httpIp: normalizedHttpIp.address,
        webrtcIps: publicWebRtcIps.map((x) => x.address),
        summary: hasFamilyDiff
          ? 'The HTTP lookup and WebRTC STUN returned different address families (IPv4 vs IPv6). This often indicates dual-stack routing or IPv6/IPv4 VPN split behavior rather than conclusive proof of a leak.'
          : 'The public IP observed by WebRTC STUN differs from the HTTP lookup IP. This can indicate split-tunnel routing, multiple exit paths, or a proxy/VPN routing discrepancy, though it is not conclusive proof of a VPN leak on its own.',
      };
    }
  }

  // Educational status indicator: RED / YELLOW / GREEN
  let verdict;
  if (!supported || error) {
    verdict = {
      level: 'yellow',
      badge: 'Unavailable / Restricted',
      title: 'WebRTC Testing Restricted or Unsupported',
      summary: error || 'RTCPeerConnection is disabled or unavailable in this browser environment.',
      notes: [
        'Some browsers, privacy extensions, or enterprise policies disable WebRTC ICE gathering.',
        'Unavailable WebRTC results do not guarantee complete protection from other network tracking vectors.',
      ],
    };
  } else if (exposedLocalIps.length > 0 || publicComparison.status === 'mismatch' || publicComparison.status === 'dual-stack-mismatch') {
    const reasons = [];
    if (exposedLocalIps.length > 0) {
      reasons.push(
        `Observed ${exposedLocalIps.length} raw local/private IP address(es) (${exposedLocalIps.map((x) => x.address).join(', ')}).`
      );
    }
    if (publicComparison.status === 'mismatch' || publicComparison.status === 'dual-stack-mismatch') {
      reasons.push(publicComparison.summary);
    }

    verdict = {
      level: 'red',
      badge: 'Sensitive Network Info Observed',
      title: 'Raw Local IP or Public Address Discrepancy Observed',
      summary: reasons.join(' '),
      notes: [
        'Exposing a local RFC 1918 or IPv6 ULA address reveals internal LAN topology to scripts, which is separate from a public VPN exit leak.',
        'Seeing a private LAN IP alone does not mean your VPN failed to tunnel public traffic; compare the public WebRTC srflx address against your expected exit IP.',
      ],
    };
  } else if (
    candidates.length === 0 ||
    mdnsHostnames.length > 0 ||
    publicComparison.status === 'no-webrtc-public' ||
    publicComparison.status === 'no-http-ip' ||
    gatheringTimedOut
  ) {
    const notes = [];
    if (mdnsHostnames.length > 0) {
      notes.push(
        `Browser masked local interface IP(s) using ${mdnsHostnames.length} ephemeral mDNS .local hostname(s).`
      );
    }
    if (publicComparison.status === 'no-webrtc-public') {
      notes.push('No public server-reflexive (srflx) candidate was returned by the STUN probe (UDP/STUN may be blocked or restricted).');
    } else if (publicComparison.status === 'no-http-ip') {
      notes.push('Run the IP lookup in Module 1 to compare the WebRTC srflx IP against your HTTP public IP.');
    }
    if (candidates.length === 0) {
      notes.push('Zero ICE candidates were exposed (WebRTC ICE may be restricted by browser policy or network firewall).');
    }
    if (gatheringTimedOut) {
      notes.push('ICE gathering reached the timeout limit before signaling completion.');
    }

    verdict = {
      level: 'yellow',
      badge: mdnsHostnames.length > 0 ? 'Masked / Partial Info' : 'Partial / Unavailable Info',
      title: mdnsHostnames.length > 0
        ? 'Local IP Addresses Masked via mDNS (Partial Information)'
        : 'Partial WebRTC Information Observed',
      summary: notes[0] || 'Some WebRTC candidate or comparison information was unavailable or obfuscated.',
      notes,
    };
  } else {
    verdict = {
      level: 'green',
      badge: 'No Raw Local IP Observed',
      title: 'No Raw Local IP Exposed & Public Addresses Match',
      summary: 'No unmasked private LAN or ULA IP addresses were exposed, and the observed WebRTC public address matched the HTTP lookup.',
      notes: [
        'This is an educational indicator, not a definitive guarantee of anonymity or VPN security.',
        'Remember that websites still observe your active exit IP address via normal HTTP requests and STUN responses.',
      ],
    };
  }

  return {
    groups: {
      host: hostCandidates,
      srflx: srflxCandidates,
      relay: relayCandidates,
      other: otherCandidates,
    },
    counts: {
      total: candidates.length,
      host: hostCandidates.length,
      srflx: srflxCandidates.length,
      relay: relayCandidates.length,
      other: otherCandidates.length,
      mdns: mdnsHostnames.length,
      localIp: exposedLocalIps.length,
      publicIp: publicWebRtcIps.length,
    },
    exposedLocalIps,
    mdnsHostnames,
    publicWebRtcIps,
    publicComparison,
    verdict,
  };
}

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  assessWebRtcPrivacy,
  classifyAddress,
  classifyIPv4,
  classifyIPv6,
  isMdnsHostname,
  parseIceCandidate,
} from '../js/lib/ipUtils.js';

test('isMdnsHostname distinguishes RFC 6762 .local hostnames from IPs', () => {
  assert.equal(isMdnsHostname('e3b0c442-98fc-1c14-9afb-4c8996fb9242.local'), true);
  assert.equal(isMdnsHostname('host-12.local'), true);
  assert.equal(isMdnsHostname('192.168.1.5'), false);
  assert.equal(isMdnsHostname('192.168.1.5.example.com'), false);
  assert.equal(isMdnsHostname('fe80::1.local'), false);
  assert.equal(isMdnsHostname('.local'), false);

  const classified = classifyAddress('a1b2c3d4-0000-4000-8000-000000000001.local');
  assert.equal(classified.kind, 'mdns');
  assert.equal(classified.family, 'mDNS');
  assert.equal(classified.isPrivateOrLocal, false);
  assert.equal(classified.isPublicIp, false);
});

test('classifyIPv4 accurately detects RFC 1918, CGNAT, link-local, loopback, and public IPs', () => {
  assert.equal(classifyIPv4('10.0.0.1').scope, 'private-rfc1918');
  assert.equal(classifyIPv4('10.255.255.254').isPrivateOrLocal, true);

  assert.equal(classifyIPv4('172.16.0.1').scope, 'private-rfc1918');
  assert.equal(classifyIPv4('172.31.255.254').scope, 'private-rfc1918');
  assert.equal(classifyIPv4('172.15.255.254').scope, 'public');
  assert.equal(classifyIPv4('172.32.0.1').scope, 'public');

  assert.equal(classifyIPv4('192.168.1.42').scope, 'private-rfc1918');
  assert.equal(classifyIPv4('169.254.10.20').scope, 'link-local');
  assert.equal(classifyIPv4('127.0.0.1').scope, 'loopback');
  assert.equal(classifyIPv4('100.64.10.1').scope, 'cgnat');
  assert.equal(classifyIPv4('8.8.8.8').scope, 'public');
  assert.equal(classifyIPv4('0.0.0.0').scope, 'unspecified');
  assert.equal(classifyIPv4('999.1.2.3').valid, false);
});

test('classifyIPv6 detects ULA (fc00::/7), link-local (fe80::/10), loopback, and public IPv6', () => {
  assert.equal(classifyIPv6('fd12:3456:789a::1').scope, 'ula');
  assert.equal(classifyIPv6('fd12:3456:789a::1').isPrivateOrLocal, true);
  assert.equal(classifyIPv6('fc00::1').scope, 'ula');
  assert.equal(classifyIPv6('fe80::1ff:fe23:4567:890a%eth0').scope, 'link-local');
  assert.equal(classifyIPv6('::1').scope, 'loopback');
  assert.equal(classifyIPv6('2606:4700:4700::1111').scope, 'public');
  assert.equal(classifyIPv6('2606:4700:4700::1111').isPublicIp, undefined);
  assert.equal(classifyAddress('2606:4700:4700::1111').isPublicIp, true);
  assert.equal(classifyIPv6('::ffff:192.168.1.50').scope, 'private-rfc1918');
});

test('parseIceCandidate parses host, srflx, relay, tcp, IPv6, and mDNS candidates cleanly', () => {
  const mdnsHost = parseIceCandidate(
    'candidate:842163049 1 udp 2122260223 e3b0c442-98fc-1c14-9afb-4c8996fb9242.local 51234 typ host generation 0'
  );
  assert.equal(mdnsHost.type, 'host');
  assert.equal(mdnsHost.protocol, 'udp');
  assert.equal(mdnsHost.port, 51234);
  assert.equal(mdnsHost.addressInfo.kind, 'mdns');

  const srflx = parseIceCandidate(
    'a=candidate:842163049 1 udp 1686052607 203.0.113.55 54321 typ srflx raddr 0.0.0.0 rport 0 generation 0'
  );
  assert.equal(srflx.type, 'srflx');
  assert.equal(srflx.address, '203.0.113.55');
  assert.equal(srflx.addressInfo.isPublicIp, true);
  assert.equal(srflx.relatedAddressInfo.scope, 'unspecified');

  const tcpRelay = parseIceCandidate(
    'candidate:12345 1 tcp 1518280447 198.51.100.12 9 typ relay raddr 192.168.1.9 rport 55555 tcptype active'
  );
  assert.equal(tcpRelay.type, 'relay');
  assert.equal(tcpRelay.protocol, 'tcp');
  assert.equal(tcpRelay.tcpType, 'active');
  assert.equal(tcpRelay.relatedAddressInfo.scope, 'private-rfc1918');
});

test('assessWebRtcPrivacy assigns GREEN, YELLOW, and RED educational verdicts accurately', () => {
  const srflxOnly = [
    parseIceCandidate('candidate:1 1 udp 1686052607 203.0.113.55 54321 typ srflx raddr 0.0.0.0 rport 0'),
  ];
  const greenRes = assessWebRtcPrivacy({
    supported: true,
    candidates: srflxOnly,
    httpPublicIp: '203.0.113.55',
  });
  assert.equal(greenRes.verdict.level, 'green');
  assert.equal(greenRes.publicComparison.status, 'match');

  // mDNS masked host + matching srflx -> YELLOW (local addresses masked)
  const mdnsPlusSrflx = [
    parseIceCandidate('candidate:2 1 udp 2122260223 abcdef01-2345-6789-abcd-ef0123456789.local 51000 typ host'),
    ...srflxOnly,
  ];
  const yellowMdns = assessWebRtcPrivacy({
    supported: true,
    candidates: mdnsPlusSrflx,
    httpPublicIp: '203.0.113.55',
  });
  assert.equal(yellowMdns.verdict.level, 'yellow');
  assert.equal(yellowMdns.mdnsHostnames.length, 1);

  // Raw RFC 1918 local IP exposed -> RED
  const localExposed = [
    parseIceCandidate('candidate:3 1 udp 2122260223 192.168.1.44 51000 typ host'),
    ...srflxOnly,
  ];
  const redLocal = assessWebRtcPrivacy({
    supported: true,
    candidates: localExposed,
    httpPublicIp: '203.0.113.55',
  });
  assert.equal(redLocal.verdict.level, 'red');
  assert.equal(redLocal.exposedLocalIps.length, 1);

  // Public IP mismatch -> RED
  const redMismatch = assessWebRtcPrivacy({
    supported: true,
    candidates: srflxOnly,
    httpPublicIp: '198.51.100.77',
  });
  assert.equal(redMismatch.verdict.level, 'red');
  assert.equal(redMismatch.publicComparison.status, 'mismatch');

  // Dual-stack mismatch -> RED with dual-stack status
  const ipv6Srflx = [
    parseIceCandidate('candidate:4 1 udp 1686052607 2606:4700:4700::1111 54321 typ srflx raddr :: rport 0'),
  ];
  const redDualStack = assessWebRtcPrivacy({
    supported: true,
    candidates: ipv6Srflx,
    httpPublicIp: '203.0.113.55',
  });
  assert.equal(redDualStack.verdict.level, 'red');
  assert.equal(redDualStack.publicComparison.status, 'dual-stack-mismatch');

  // WebRTC unavailable -> YELLOW
  const yellowUnsupported = assessWebRtcPrivacy({
    supported: false,
    candidates: [],
    error: 'RTCPeerConnection disabled',
  });
  assert.equal(yellowUnsupported.verdict.level, 'yellow');
});

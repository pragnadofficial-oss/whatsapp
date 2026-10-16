'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { createApp, inspectUrl, parseSubmittedUrl } = require('../server');

async function withServer(t, options = {}) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cybershield-test-'));
  const app = createApp({ dataDir, env: options.env || {}, fetch: options.fetch });
  const server = app.listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  const address = server.address();
  t.after(async () => {
    await new Promise((resolve, reject) => {
      server.close((error) => error ? reject(error) : resolve());
      server.closeAllConnections();
    });
    fs.rmSync(dataDir, { recursive: true, force: true });
  });
  return {
    dataDir,
    request: (route, init) => fetch(`http://127.0.0.1:${address.port}${route}`, init)
  };
}

function postJson(request, route, value, headers = {}) {
  return request(route, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(value)
  });
}

function jsonResponse(value, init = {}) {
  return new Response(JSON.stringify(value), {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init.headers || {})
    }
  });
}

test('HTTPS without reputation data remains unknown, not proven safe', () => {
  const parsed = parseSubmittedUrl('https://store.example.com/product');
  const result = inspectUrl(parsed);
  assert.equal(result.classification, 'unknown');
  assert.equal(result.severity, 'unverified');
  assert.equal(result.riskScore, 0);
  assert.ok(result.evidence.some((item) => item.includes('does not prove')));
  assert.match(result.certificateDetails, /never connects/);
});

test('URL normalization preserves fragments and case-sensitive paths', () => {
  const first = inspectUrl(parseSubmittedUrl('https://example.org/Private/Path?Key=Value#section'));
  const second = inspectUrl(parseSubmittedUrl('https://example.org/private/path?Key=Value#other'));
  assert.equal(first.normalizedUrl, 'https://example.org/Private/Path?Key=Value#section');
  assert.notEqual(first.normalizedUrl, second.normalizedUrl);
});

test('lookalike and insecure URL indicators are explained', () => {
  const result = inspectUrl(parseSubmittedUrl('http://amaz0n-login.example/path'));
  assert.equal(result.classification, 'suspicious');
  assert.equal(result.riskScore, 45);
  assert.ok(result.evidence.some((item) => item.includes('resembles amazon')));
  assert.ok(result.evidence.some((item) => item.includes('does not use HTTPS')));
});

test('public IP, punycode, unusual ports, and suspicious encoding are surfaced as local findings', () => {
  const publicIp = inspectUrl(parseSubmittedUrl('https://8.8.8.8/'));
  assert.ok(publicIp.evidence.some((item) => item.includes('IP number')));

  const publicIpv6 = inspectUrl(parseSubmittedUrl('https://[2606:4700:4700::1111]/'));
  assert.ok(publicIpv6.evidence.some((item) => item.includes('IP number')));

  const punycode = inspectUrl(parseSubmittedUrl('https://xn--pple-43d.example/'));
  assert.ok(punycode.evidence.some((item) => item.includes('internationalized characters')));

  const unusualPort = inspectUrl(parseSubmittedUrl('https://example.org:8443/'));
  assert.ok(unusualPort.evidence.some((item) => item.includes('non-default port')));

  const encodedControl = inspectUrl(parseSubmittedUrl('https://example.org/path%00'));
  assert.ok(encodedControl.evidence.some((item) => item.includes('encoded control characters')));
  assert.ok(encodedControl.riskScore > 0);
});

test('shorteners are reported as a caution without being treated as proof', () => {
  const result = inspectUrl(parseSubmittedUrl('https://bit.ly/a1b2'));
  assert.equal(result.classification, 'suspicious');
  assert.ok(result.evidence.some((item) => item.includes('not proof')));
  assert.ok(result.evidence.some((item) => item.includes('not opened or expanded')));
});

test('private, local, and credential-bearing targets are rejected before inspection', () => {
  assert.throws(() => parseSubmittedUrl('http://127.0.0.1/admin'), /Local, private/);
  assert.throws(() => parseSubmittedUrl('http://intranet/login'), /Local, private/);
  const credentialUrl = new URL('https://example.com');
  credentialUrl.username = 'test-user';
  credentialUrl.password = 'test-value';
  assert.throws(() => parseSubmittedUrl(credentialUrl.href), /without embedded credentials/);
});

test('reserved, private, link-local, and mapped IP ranges are rejected', () => {
  for (const address of [
    '10.1.2.3', '172.16.0.1', '192.168.1.1', '169.254.169.254',
    '100.64.0.1', '192.0.2.1', '198.51.100.2', '203.0.113.8',
    '224.0.0.1', '240.0.0.1', '[::1]', '[fe80::1]', '[fc00::1]',
    '[2001:db8::1]', '[::ffff:127.0.0.1]'
  ]) {
    assert.throws(() => parseSubmittedUrl(`https://${address}/`), undefined, address);
  }
  assert.equal(parseSubmittedUrl('https://8.8.8.8/').hostname, '8.8.8.8');
});

test('valid HTTP, HTTPS, and host-only input are accepted while malformed input is rejected', () => {
  assert.equal(parseSubmittedUrl('http://example.org').protocol, 'http:');
  assert.equal(parseSubmittedUrl('https://example.org/path').protocol, 'https:');
  const hostOnly = parseSubmittedUrl('news.shop.example.co.uk:8443/path#section');
  const inspected = inspectUrl(hostOnly);
  assert.equal(hostOnly.protocol, 'https:');
  assert.equal(hostOnly.port, '8443');
  assert.equal(hostOnly.schemeWasAdded, true);
  assert.equal(inspected.registeredDomain, 'example.co.uk');
  assert.equal(inspected.subdomain, 'news.shop');
  assert.match(inspected.evidence[0], /HTTPS was assumed/);
  assert.equal(inspected.normalizedUrl, 'https://news.shop.example.co.uk:8443/path#section');
  assert.throws(() => parseSubmittedUrl(''), /non-empty string/);
  assert.throws(() => parseSubmittedUrl('https://[invalid'), /valid hostname or a complete URL/);
  assert.throws(() => parseSubmittedUrl('https://bad..example/'), /hostname is not syntactically valid/);
  assert.throws(() => parseSubmittedUrl('https://bad_host.example/'), /hostname is not syntactically valid/);
  assert.throws(() => parseSubmittedUrl('javascript:alert(1)'), /Only HTTP and HTTPS/);
});

test('known controlled threat indicators match from the local cache', async (t) => {
  const { dataDir, request } = await withServer(t);
  fs.writeFileSync(path.join(dataDir, 'threats.json'), JSON.stringify({
    entries: [{
      type: 'domain',
      indicator: 'phishing.example.test',
      category: 'phishing',
      source: 'controlled test fixture',
      confirmedAt: new Date().toISOString()
    }]
  }));
  const response = await postJson(request, '/api/scan/url', { url: 'https://phishing.example.test/login' });
  const payload = await response.json();
  assert.equal(response.status, 200);
  assert.equal(payload.result.threatMatch, true);
  assert.equal(payload.result.classification, 'phishing');
  assert.equal(payload.result.severity, 'high-risk');
  assert.match(payload.result.analysisSource, /local-confirmed-cache/);
  assert.equal(payload.result.blocked, true);
  const blocklist = await request('/api/blocked-links');
  const blockedEntry = (await blocklist.json()).entries[0];
  assert.equal(blockedEntry.hostname, 'phishing.example.test');
  assert.equal(blockedEntry.id.length, 64);
  assert.equal(JSON.stringify(blockedEntry).includes('/login'), false);
});

test('a confirmed malicious scan persists a local block, skips future providers, and can be removed', async (t) => {
  let providerCalls = 0;
  const { dataDir, request } = await withServer(t, {
    env: { PHISHTANK_ENABLED: 'true' },
    fetch: async () => {
      providerCalls += 1;
      return jsonResponse({ results: { in_database: true, verified: 'y', valid: 'y' } });
    }
  });
  const url = 'https://confirmed.example.org/login?token=private';
  const scan = () => postJson(request, '/api/scan/url', {
    url,
    consentToExternalScan: true
  });
  const first = await scan();
  const result = (await first.json()).result;
  assert.equal(result.verdict, 'malicious');
  assert.equal(result.blocked, true);
  assert.equal(providerCalls, 1);
  const saved = JSON.parse(fs.readFileSync(path.join(dataDir, 'blocked-links.json'), 'utf8'));
  assert.equal(saved.entries.length, 1);
  assert.equal(JSON.stringify(saved).includes('private'), false);
  assert.equal(saved.entries[0].hostname, 'confirmed.example.org');

  const repeat = (await (await scan()).json()).result;
  assert.equal(repeat.verdict, 'malicious');
  assert.equal(repeat.blocked, true);
  assert.equal(providerCalls, 1);

  const remove = await request(`/api/blocked-links/${saved.entries[0].id}`, { method: 'DELETE' });
  const removePayload = await remove.json();
  assert.equal(remove.status, 200);
  assert.equal(removePayload.removed, true);
  assert.match(removePayload.message, /later malicious scan may add it again/);
  const afterRemoval = await request('/api/blocked-links');
  assert.deepEqual((await afterRemoval.json()).entries, []);

  const recheck = (await (await scan()).json()).result;
  assert.equal(recheck.verdict, 'malicious');
  assert.equal(recheck.blocked, true);
  assert.equal((await (await request('/api/blocked-links')).json()).entries.length, 1);
});

test('suspicious and unknown scans stay distinct and do not enter the blocklist', async (t) => {
  const { request } = await withServer(t);
  const suspicious = await postJson(request, '/api/scan/url', {
    url: 'http://amaz0n-login.example.org/'
  });
  assert.equal((await suspicious.json()).result.verdict, 'suspicious');
  const unknown = await postJson(request, '/api/scan/url', {
    url: 'https://ordinary.example.org/'
  });
  assert.equal((await unknown.json()).result.verdict, 'unknown');
  const blocklist = await request('/api/blocked-links');
  assert.deepEqual((await blocklist.json()).entries, []);
});

test('blocked-link deletion validates identifiers and missing entries safely', async (t) => {
  const { request } = await withServer(t);
  const malformed = await request('/api/blocked-links/not-a-hash', { method: 'DELETE' });
  assert.equal(malformed.status, 400);
  const missing = await request(`/api/blocked-links/${'a'.repeat(64)}`, { method: 'DELETE' });
  assert.equal(missing.status, 200);
  assert.equal((await missing.json()).removed, false);
});

test('stale or undated cached threat entries are ignored', async (t) => {
  const { dataDir, request } = await withServer(t);
  fs.writeFileSync(path.join(dataDir, 'threats.json'), JSON.stringify({
    entries: [
      {
        type: 'domain',
        indicator: 'stale.example.test',
        category: 'phishing',
        source: 'expired test fixture',
        confirmedAt: new Date(Date.now() - (25 * 60 * 60 * 1000)).toISOString()
      },
      {
        type: 'domain',
        indicator: 'undated.example.test',
        category: 'phishing',
        source: 'legacy fixture'
      }
    ]
  }));
  for (const url of [
    'https://stale.example.test/login',
    'https://undated.example.test/login'
  ]) {
    const response = await postJson(request, '/api/scan/url', { url });
    const payload = await response.json();
    assert.equal(payload.result.threatMatch, false);
    assert.equal(payload.result.verdict, 'unknown');
  }
});

test('local-only checks report unknown when no provider is configured', async (t) => {
  const { request } = await withServer(t);
  const response = await postJson(request, '/api/scan/url', {
    url: 'https://ordinary.example.org/page',
    consentToExternalScan: false
  });
  const payload = await response.json();
  assert.equal(response.status, 200);
  assert.equal(payload.result.verdict, 'unknown');
  assert.equal(payload.result.classification, 'unknown');
  assert.equal(payload.result.severity, 'unverified');
  assert.ok(payload.result.checks.some((check) =>
    check.provider === 'PhishTank' && check.status === 'not_configured'));
  assert.equal(payload.result.riskScore, 0);
  assert.equal(payload.result.confidence, 'low');
  assert.equal(payload.result.model.available, false);
});

test('PhishTank permits a low-volume lookup without an app key after consent', async (t) => {
  let requestOptions;
  const { request } = await withServer(t, {
    env: { PHISHTANK_ENABLED: 'true' },
    fetch: async (url, options) => {
      requestOptions = { url: String(url), options };
      return jsonResponse({ results: { in_database: false } });
    }
  });
  const response = await postJson(request, '/api/scan/url', {
    url: 'https://ordinary.example.org/',
    consentToExternalScan: true
  });
  const payload = await response.json();
  assert.equal(response.status, 200);
  assert.equal(requestOptions.url, 'https://checkurl.phishtank.com/checkurl/');
  assert.equal(requestOptions.options.method, 'POST');
  assert.equal(requestOptions.options.body.has('app_key'), false);
  assert.equal(payload.result.verdict, 'safe');
  assert.equal(payload.result.checks.find((check) => check.provider === 'PhishTank').status, 'clean');
});

test('external reputation failures fall back to local analysis without leaking details', async (t) => {
  const { request } = await withServer(t, {
    env: { PHISHTANK_ENABLED: 'true', URLHAUS_AUTH_KEY: 'test-only-key' },
    fetch: async (url) => String(url).includes('urlhaus')
      ? new Response('provider failure detail', { status: 503 })
      : jsonResponse({ results: { in_database: false } })
  });
  const response = await postJson(request, '/api/scan/url', {
    url: 'https://ordinary.example.org/page',
    consentToExternalScan: true
  });
  const payload = await response.json();
  assert.equal(response.status, 200);
  assert.equal(payload.result.classification, 'unknown');
  assert.equal(payload.result.severity, 'unverified');
  assert.ok(payload.result.reasons.some((item) => item.includes('inconclusive')));
  assert.equal(payload.result.checks.find((check) => check.provider === 'PhishTank').status, 'clean');
  assert.equal(payload.result.checks.find((check) => check.provider === 'URLhaus').status, 'unavailable');
  const urlhausError = payload.result.externalCheck.errors.find((item) => item.provider === 'URLhaus');
  assert.ok(urlhausError);
  assert.match(urlhausError.error, /no reputation verdict/);
  assert.equal(JSON.stringify(payload).includes('provider failure detail'), false);
});

test('free providers are called only after consent and confirmed matches are cached', async (t) => {
  const providerCalls = [];
  const { dataDir, request } = await withServer(t, {
    env: {
      PHISHTANK_APP_KEY: 'test-phish-key',
      URLHAUS_AUTH_KEY: 'test-urlhaus-key'
    },
    fetch: async (url, options) => {
      providerCalls.push({ url: String(url), options });
      if (String(url).includes('phishtank')) {
        return jsonResponse({ results: { in_database: true, verified: 'y', valid: 'y' } });
      }
      return jsonResponse({
        query_status: 'ok',
        urls: [{ url_status: 'offline', threat: 'malware_download' }]
      });
    }
  });

  const noConsent = await postJson(request, '/api/scan/url', {
    url: 'https://ordinary.example.org/page',
    consentToExternalScan: false
  });
  assert.equal((await noConsent.json()).result.externalCheck.checked.length, 0);
  assert.equal(providerCalls.length, 0);

  const response = await postJson(request, '/api/scan/url', {
    url: 'https://ordinary.example.org/page',
    consentToExternalScan: true
  });
  const payload = await response.json();
  assert.equal(response.status, 200);
  assert.equal(providerCalls.length, 2);
  assert.equal(payload.result.verdict, 'malicious');
  assert.equal(payload.result.classification, 'potential-malware');
  assert.equal(payload.result.severity, 'high-risk');
  assert.deepEqual(payload.result.externalCheck.checked.sort(), ['PhishTank', 'URLhaus']);
  assert.equal(JSON.stringify(payload).includes('test-phish-key'), false);
  assert.equal(JSON.stringify(payload).includes('test-urlhaus-key'), false);
  assert.ok(providerCalls.some((call) =>
    call.url.includes('phishtank')
    && call.options.body.toString().includes('test-phish-key')));
  assert.ok(providerCalls.some((call) =>
    call.url.includes('urlhaus')
    && call.options.headers['Auth-Key'] === 'test-urlhaus-key'));

  const cache = JSON.parse(fs.readFileSync(path.join(dataDir, 'threats.json'), 'utf8'));
  assert.equal(cache.entries[0].indicator.length, 64);
  assert.equal(JSON.stringify(cache).includes('/page'), false);
});

test('PhishTank API-level key errors are explicit and not presented as safe', async (t) => {
  const { request } = await withServer(t, {
    env: { PHISHTANK_APP_KEY: 'invalid-test-key' },
    fetch: async () => jsonResponse({ errortext: 'private provider response details' })
  });
  const response = await postJson(request, '/api/scan/url', {
    url: 'https://ordinary.example.org/',
    consentToExternalScan: true
  });
  const payload = await response.json();
  assert.equal(response.status, 200);
  assert.equal(payload.result.verdict, 'unknown');
  assert.equal(payload.result.severity, 'unverified');
  assert.ok(payload.result.checks.some((item) =>
    item.provider === 'PhishTank' && item.status === 'unavailable' && item.details.includes('key')));
  assert.equal(JSON.stringify(payload).includes('private provider response details'), false);
});

test('message analysis uses no external service and stores no message or history', async (t) => {
  const { dataDir, request } = await withServer(t);
  const response = await postJson(request, '/api/scan/message', {
    message: 'Your parcel is ready: https://ordinary.example.org/track'
  });
  const payload = await response.json();
  assert.equal(response.status, 200);
  assert.equal(payload.messageStored, false);
  assert.equal(payload.externalServiceUsed, false);
  assert.equal(payload.urlsFound, 1);
  assert.equal(JSON.stringify(payload).includes('Your parcel is ready'), false);
  const historyResponse = await request('/api/scan/history');
  assert.deepEqual((await historyResponse.json()).history, []);
  assert.deepEqual(fs.readdirSync(dataDir), []);
});

test('a malicious link found in an in-memory message is added to the app blocklist without storing the message', async (t) => {
  const { dataDir, request } = await withServer(t);
  fs.writeFileSync(path.join(dataDir, 'threats.json'), JSON.stringify({
    entries: [{
      type: 'domain',
      indicator: 'phishing.example.test',
      category: 'phishing',
      source: 'controlled test feed',
      confirmedAt: new Date().toISOString()
    }]
  }));
  const message = 'Please review https://phishing.example.test/login?session=private';
  const response = await postJson(request, '/api/scan/message', { message });
  const payload = await response.json();
  assert.equal(payload.results[0].verdict, 'malicious');
  assert.equal(payload.results[0].blocked, true);
  assert.equal(payload.results[0].checks.some((check) =>
    check.provider === 'Local confirmed cache' && check.status === 'malicious'), true);
  const blocklist = JSON.parse(fs.readFileSync(path.join(dataDir, 'blocked-links.json'), 'utf8'));
  assert.equal(blocklist.entries[0].hostname, 'phishing.example.test');
  assert.equal(JSON.stringify(blocklist).includes('session=private'), false);
  assert.equal(JSON.stringify(payload).includes('Please review'), false);
});

test('invalid request input returns a clear client error', async (t) => {
  const { request } = await withServer(t);
  const response = await postJson(request, '/api/scan/url', { url: 'file:///etc/passwd' });
  const payload = await response.json();
  assert.equal(response.status, 400);
  assert.equal(payload.ok, false);
  assert.equal(payload.verdict, 'invalid');
  assert.equal(payload.riskScore, null);
  assert.match(payload.error, /Only HTTP and HTTPS/);
});

test('API key protects scan endpoints when configured', async (t) => {
  const { request } = await withServer(t, { env: { API_TOKEN: 'test-only-secret' } });
  const status = await request('/api/auth/status');
  assert.deepEqual(await status.json(), { ok: true, required: true });

  const unauthenticated = await postJson(request, '/api/scan/url', { url: 'https://example.org' });
  assert.equal(unauthenticated.status, 401);
  const invalidSession = await postJson(request, '/api/auth/session', { apiKey: 'wrong-secret' });
  assert.equal(invalidSession.status, 401);
  assert.deepEqual(await invalidSession.json(), { ok: false, error: 'The API key is invalid.' });

  const validSession = await postJson(request, '/api/auth/session', { apiKey: 'test-only-secret' });
  assert.equal(validSession.status, 200);
  assert.deepEqual(await validSession.json(), { ok: true, authenticated: true });

  const invalidHeader = await postJson(request, '/api/scan/url', { url: 'https://example.org' }, { 'X-API-Key': 'wrong-secret' });
  assert.equal(invalidHeader.status, 401);
  const authenticated = await postJson(request, '/api/scan/url', { url: 'https://example.org' }, { 'X-API-Key': 'test-only-secret' });
  assert.equal(authenticated.status, 200);
});

test('provider credential rejection is surfaced and cannot produce a safe-looking verdict', async (t) => {
  const { request } = await withServer(t, {
    env: { URLHAUS_AUTH_KEY: 'invalid-test-key' },
    fetch: async (url) => {
      if (String(url).includes('urlhaus')) return new Response('denied', { status: 403 });
      return jsonResponse({ results: { in_database: false } });
    }
  });
  const response = await postJson(request, '/api/scan/url', {
    url: 'https://ordinary.example.org/',
    consentToExternalScan: true
  });
  const payload = await response.json();
  assert.equal(response.status, 200);
  assert.equal(payload.result.verdict, 'unknown');
  assert.equal(payload.result.severity, 'unverified');
  assert.ok(payload.result.checks.some((item) =>
    item.provider === 'URLhaus' && item.status === 'unavailable' && item.details.includes('credentials')));
});

test('all configured providers unavailable produces an inconclusive unknown result', async (t) => {
  const { request } = await withServer(t, {
    env: {
      GOOGLE_SAFE_BROWSING_ENABLED: 'true',
      GOOGLE_SAFE_BROWSING_API_KEY: 'test-google-key',
      VIRUSTOTAL_API_KEY: 'test-vt-key',
      URLHAUS_AUTH_KEY: 'test-urlhaus-key',
      PHISHTANK_ENABLED: 'true'
    },
    fetch: async () => new Response('{}', { status: 503 })
  });
  const response = await postJson(request, '/api/scan/url', {
    url: 'https://ordinary.example.org/',
    consentToExternalScan: true
  });
  const payload = await response.json();
  assert.equal(response.status, 200);
  assert.equal(payload.result.verdict, 'unknown');
  assert.ok(payload.result.providers
    .every((check) => check.status === 'unavailable'));
  assert.ok(payload.result.reasons.some((reason) => reason.includes('inconclusive')));
});

test('conflicting clean and malicious providers retain the malicious verdict and explain the conflict', async (t) => {
  let googleRequests = 0;
  const { request } = await withServer(t, {
    env: {
      GOOGLE_SAFE_BROWSING_ENABLED: 'true',
      GOOGLE_SAFE_BROWSING_API_KEY: 'test-google-key',
      VIRUSTOTAL_API_KEY: 'test-vt-key'
    },
    fetch: async (url) => {
      if (String(url).includes('safebrowsing')) {
        googleRequests += 1;
        return jsonResponse(googleRequests === 1 ? { matches: [{ threatType: 'MALWARE' }] } : {});
      }
      return jsonResponse({
        data: { attributes: { last_analysis_stats: { malicious: 0, suspicious: 0 } } }
      });
    }
  });
  const response = await postJson(request, '/api/scan/url', {
    url: 'https://ordinary.example.org/',
    consentToExternalScan: true
  });
  const result = (await response.json()).result;
  assert.equal(result.verdict, 'malicious');
  assert.equal(result.riskScore, 100);
  assert.ok(result.checks.some((check) => check.provider === 'VirusTotal' && check.status === 'clean'));
  assert.ok(result.reasons.some((reason) => reason.includes('conflicting results')));
});

test('request rate limiting returns HTTP 429 after the configured limit', async (t) => {
  const { request } = await withServer(t);
  let lastResponse;
  for (let index = 0; index < 61; index += 1) {
    lastResponse = await request('/api/health');
    if (lastResponse.status === 429) break;
  }
  assert.equal(lastResponse.status, 429);
});

test('scan history can be deleted', async (t) => {
  const { dataDir, request } = await withServer(t);
  await postJson(request, '/api/scan/url', { url: 'https://ordinary.example.org/page' });
  const savedHistory = fs.readFileSync(path.join(dataDir, 'history.json'), 'utf8');
  assert.equal(savedHistory.includes('/page'), false);
  const deletion = await request('/api/scan/history', { method: 'DELETE' });
  assert.equal(deletion.status, 200);
  const history = await request('/api/scan/history');
  assert.deepEqual((await history.json()).history, []);
});

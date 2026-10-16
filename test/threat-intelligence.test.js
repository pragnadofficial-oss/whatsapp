'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { checkThreatIntelligence } = require('../threat-intelligence');

function jsonResponse(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

function findCheck(checks, provider) {
  return checks.find((check) => check.provider === provider);
}

test('unconfigured providers are explicitly distinguished from clean checks', async () => {
  const checks = await checkThreatIntelligence('https://example.org/', {});
  assert.equal(checks.length, 4);
  assert.ok(checks.every((check) => check.status === 'not_configured'));
});

test('Google Safe Browsing uses valid list groups and reports clean lookup results', async () => {
  const requests = [];
  const checks = await checkThreatIntelligence(
    'https://example.org/',
    { GOOGLE_SAFE_BROWSING_ENABLED: 'true', GOOGLE_SAFE_BROWSING_API_KEY: 'server-key' },
    async (url, options) => {
      requests.push({ url: String(url), options });
      return jsonResponse({});
    }
  );
  const check = findCheck(checks, 'Google Safe Browsing');
  assert.equal(check.status, 'clean');
  assert.equal(requests.length, 2);
  assert.ok(requests.every((request) => request.url.includes('key=server-key')));
  const groups = requests.map((request) => JSON.parse(request.options.body).threatInfo);
  assert.deepEqual(groups[0].platformTypes, ['WINDOWS']);
  assert.deepEqual(groups[0].threatTypes, ['MALWARE', 'UNWANTED_SOFTWARE']);
  assert.deepEqual(groups[1].platformTypes, ['ANY_PLATFORM']);
  assert.deepEqual(groups[1].threatTypes, ['SOCIAL_ENGINEERING']);
});

test('a confirmed Google Safe Browsing match produces a malicious finding', async () => {
  let requestIndex = 0;
  const checks = await checkThreatIntelligence(
    'https://malware.example.test/',
    { GOOGLE_SAFE_BROWSING_ENABLED: 'true', GOOGLE_SAFE_BROWSING_API_KEY: 'server-key' },
    async () => {
      requestIndex += 1;
      return jsonResponse(requestIndex === 1
        ? { matches: [{ threatType: 'MALWARE' }] }
        : {});
    }
  );
  assert.equal(findCheck(checks, 'Google Safe Browsing').status, 'malicious');
});

test('Google API credential errors remain unavailable, not clean', async () => {
  const checks = await checkThreatIntelligence(
    'https://example.org/',
    { GOOGLE_SAFE_BROWSING_ENABLED: 'true', GOOGLE_SAFE_BROWSING_API_KEY: 'invalid-key' },
    async () => jsonResponse({ error: { message: 'private provider response' } }, 403)
  );
  const check = findCheck(checks, 'Google Safe Browsing');
  assert.equal(check.status, 'unavailable');
  assert.match(check.details, /credentials or access/);
  assert.equal(check.details.includes('private provider response'), false);
});

test('VirusTotal submits missing URLs and returns pending until analysis is complete', async () => {
  const requests = [];
  const checks = await checkThreatIntelligence(
    'https://example.org/path',
    { VIRUSTOTAL_API_KEY: 'server-key' },
    async (url, options) => {
      requests.push({ url: String(url), options });
      if (requests.length === 1) return jsonResponse({ error: 'not found' }, 404);
      if (requests.length === 2) return jsonResponse({ data: { id: 'analysis-123' } });
      return jsonResponse({ data: { attributes: { status: 'queued' } } });
    }
  );
  const check = findCheck(checks, 'VirusTotal');
  assert.equal(check.status, 'pending');
  assert.equal(requests.length, 3);
  assert.match(requests[0].url, /\/api\/v3\/urls\//);
  assert.equal(requests[1].url, 'https://www.virustotal.com/api/v3/urls');
  assert.equal(requests[1].options.body.get('url'), 'https://example.org/path');
  assert.equal(requests[2].url, 'https://www.virustotal.com/api/v3/analyses/analysis-123');
  assert.ok(requests.every((request) => request.options.headers['x-apikey'] === 'server-key'));
});

test('VirusTotal completed reports distinguish malicious from clean', async () => {
  const malicious = await checkThreatIntelligence(
    'https://bad.example.test/',
    { VIRUSTOTAL_API_KEY: 'test-key' },
    async () => jsonResponse({
      data: { attributes: { last_analysis_stats: { malicious: 2, suspicious: 0 } } }
    })
  );
  assert.equal(findCheck(malicious, 'VirusTotal').status, 'malicious');

  const clean = await checkThreatIntelligence(
    'https://clean.example.test/',
    { VIRUSTOTAL_API_KEY: 'test-key' },
    async () => jsonResponse({
      data: { attributes: { last_analysis_stats: { malicious: 0, suspicious: 0 } } }
    })
  );
  assert.equal(findCheck(clean, 'VirusTotal').status, 'clean');
});

test('URLhaus interprets an indexed malware URL as malicious and no_results as limited clean', async () => {
  const malicious = await checkThreatIntelligence(
    'https://bad.example.test/',
    { URLHAUS_AUTH_KEY: 'test-key' },
    async () => jsonResponse({
      query_status: 'ok',
      urls: [{ url_status: 'offline', threat: 'malware_download' }]
    })
  );
  assert.equal(findCheck(malicious, 'URLhaus').status, 'malicious');

  const clean = await checkThreatIntelligence(
    'https://unknown.example.test/',
    { URLHAUS_AUTH_KEY: 'test-key' },
    async () => jsonResponse({ query_status: 'no_results' })
  );
  assert.equal(findCheck(clean, 'URLhaus').status, 'clean');
  assert.match(findCheck(clean, 'URLhaus').details, /not proof of safety/);
});

test('provider timeouts and rate limits are explicitly unavailable', async () => {
  const timedOut = await checkThreatIntelligence(
    'https://example.org/',
    { URLHAUS_AUTH_KEY: 'test-key' },
    () => new Promise(() => {}),
    { timeoutMs: 5 }
  );
  assert.equal(findCheck(timedOut, 'URLhaus').status, 'unavailable');
  assert.match(findCheck(timedOut, 'URLhaus').details, /timed out/);

  const rateLimited = await checkThreatIntelligence(
    'https://example.org/',
    { URLHAUS_AUTH_KEY: 'test-key' },
    async () => jsonResponse({}, 429)
  );
  assert.match(findCheck(rateLimited, 'URLhaus').details, /rate limit or quota/);
});

test('VirusTotal requests are throttled to four API calls per minute', async () => {
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    return jsonResponse({
      data: { attributes: { last_analysis_stats: { malicious: 0, suspicious: 0 } } }
    });
  };
  let lastChecks;
  for (let index = 0; index < 5; index += 1) {
    lastChecks = await checkThreatIntelligence(
      `https://example${index}.org/`,
      { VIRUSTOTAL_API_KEY: 'test-key' },
      fetchImpl
    );
  }
  assert.equal(calls, 4);
  assert.equal(findCheck(lastChecks, 'VirusTotal').status, 'unavailable');
  assert.match(findCheck(lastChecks, 'VirusTotal').details, /local VirusTotal request limit/);
});

'use strict';

const PROVIDERS = [
  'Google Safe Browsing',
  'VirusTotal',
  'URLhaus',
  'PhishTank'
];
const REQUEST_TIMEOUT_MS = 3500;
const VIRUSTOTAL_REQUEST_LIMIT = 4;
const VIRUSTOTAL_WINDOW_MS = 60 * 1000;
const virusTotalRequestTimes = new WeakMap();

function getProviderConfiguration(env) {
  return {
    'Google Safe Browsing': env.GOOGLE_SAFE_BROWSING_ENABLED === 'true'
      && Boolean(env.GOOGLE_SAFE_BROWSING_API_KEY),
    VirusTotal: Boolean(env.VIRUSTOTAL_API_KEY),
    URLhaus: Boolean(env.URLHAUS_AUTH_KEY),
    PhishTank: env.PHISHTANK_ENABLED === 'true' || Boolean(env.PHISHTANK_APP_KEY)
  };
}

function providerError(name, status) {
  if (status === 401 || status === 403) {
    return {
      provider: name,
      status: 'unavailable',
      details: 'The provider rejected its credentials or access. Check the API key, account access, and quota.'
    };
  }
  if (status === 429 || status === 509) {
    return {
      provider: name,
      status: 'unavailable',
      details: 'The provider rate limit or quota was reached. Try again later.'
    };
  }
  return {
    provider: name,
    status: 'unavailable',
    details: 'The provider request failed; no reputation verdict was obtained.'
  };
}

async function requestJson(fetchImpl, name, endpoint, options = {}, timeoutMs = REQUEST_TIMEOUT_MS) {
  const controller = new AbortController();
  let timeout;
  try {
    const request = (async () => {
      const response = await fetchImpl(endpoint, {
        ...options,
        redirect: 'error',
        signal: controller.signal,
        headers: { Accept: 'application/json', ...options.headers }
      });
      if (!response.ok) return { response };
      try {
        return { response, payload: await response.json() };
      } catch {
        return { malformed: true };
      }
    })();
    const timedOut = new Promise((resolve) => {
      timeout = setTimeout(() => {
        controller.abort();
        resolve({ timedOut: true });
      }, timeoutMs);
    });
    const result = await Promise.race([request, timedOut]);
    if (result.timedOut) {
      return {
        error: {
          provider: name,
          status: 'unavailable',
          details: 'The provider request timed out; no reputation verdict was obtained.'
        }
      };
    }
    if (result.malformed) {
      return {
        error: {
          provider: name,
          status: 'unavailable',
          details: 'The provider returned an unreadable response.'
        }
      };
    }
    if (result.response && !result.response.ok) {
      return {
        error: providerError(name, result.response.status),
        httpStatus: result.response.status
      };
    }
    return { payload: result.payload };
  } catch (error) {
    if (error.code === 'LOCAL_PROVIDER_RATE_LIMIT') {
      return {
        error: {
          provider: name,
          status: 'unavailable',
          details: 'CyberShield reached its local VirusTotal request limit. Try again after a minute.'
        }
      };
    }
    return {
      error: {
        provider: name,
        status: 'unavailable',
        details: 'The provider could not be reached; no reputation verdict was obtained.'
      }
    };
  } finally {
    clearTimeout(timeout);
  }
}

function makeCheck(provider, status, details, category) {
  return {
    provider,
    status,
    details,
    ...(category ? { category } : {})
  };
}

function interpretVirusTotalStats(name, stats) {
  if (!stats || !Number.isInteger(stats.malicious) || !Number.isInteger(stats.suspicious)) {
    return makeCheck(name, 'unavailable', 'VirusTotal returned no usable analysis statistics.');
  }
  if (stats.malicious > 0) {
    return makeCheck(
      name,
      'malicious',
      `${stats.malicious} security vendors marked the URL malicious.`,
      'malware'
    );
  }
  if (stats.suspicious > 0) {
    return makeCheck(
      name,
      'suspicious',
      `${stats.suspicious} security vendors marked the URL suspicious.`,
      'suspicious'
    );
  }
  return makeCheck(
    name,
    'clean',
    'The completed VirusTotal report contains no malicious or suspicious vendor detections; this is not proof of safety.'
  );
}

async function checkGoogleSafeBrowsing(url, env, fetchImpl, timeoutMs) {
  const name = 'Google Safe Browsing';
  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(env.GOOGLE_SAFE_BROWSING_API_KEY)}`;
  const listGroups = [
    { threatTypes: ['MALWARE', 'UNWANTED_SOFTWARE'], platformTypes: ['WINDOWS'] },
    { threatTypes: ['SOCIAL_ENGINEERING'], platformTypes: ['ANY_PLATFORM'] }
  ];
  const outcomes = await Promise.all(listGroups.map((group) => requestJson(fetchImpl, name, endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client: { clientId: 'cybershield-ai', clientVersion: '1.0.0' },
      threatInfo: {
        ...group,
        threatEntryTypes: ['URL'],
        threatEntries: [{ url }]
      }
    })
  }, timeoutMs)));
  const failed = outcomes.find((outcome) => outcome.error);
  const invalid = outcomes.some((outcome) =>
    !outcome.payload || (outcome.payload.matches !== undefined && !Array.isArray(outcome.payload.matches)));
  const matches = outcomes.flatMap((outcome) => outcome.payload && outcome.payload.matches || []);
  if (matches.length) {
    const types = [...new Set(matches.map((match) => match.threatType).filter(Boolean))];
    return makeCheck(
      name,
      'malicious',
      `Google Safe Browsing reported a match${types.length ? ` (${types.join(', ')})` : ''}.${failed ? ' Another selected list could not be checked.' : ''}`,
      types.length && types.every((type) => type === 'SOCIAL_ENGINEERING') ? 'phishing' : 'malware'
    );
  }
  if (failed) return failed.error;
  if (invalid) return makeCheck(name, 'unavailable', 'Google Safe Browsing returned an unexpected response.');
  return makeCheck(
    name,
    'clean',
    'No matching entry was returned from the selected Google Safe Browsing lists; this is not proof of safety.'
  );
}

async function checkVirusTotal(url, env, fetchImpl, timeoutMs) {
  const name = 'VirusTotal';
  const headers = { 'x-apikey': env.VIRUSTOTAL_API_KEY };
  const rateLimitedFetch = async (...args) => {
    const now = Date.now();
    const recentRequests = (virusTotalRequestTimes.get(fetchImpl) || [])
      .filter((startedAt) => now - startedAt < VIRUSTOTAL_WINDOW_MS);
    if (recentRequests.length >= VIRUSTOTAL_REQUEST_LIMIT) {
      virusTotalRequestTimes.set(fetchImpl, recentRequests);
      const error = new Error('Local provider request limit reached.');
      error.code = 'LOCAL_PROVIDER_RATE_LIMIT';
      throw error;
    }
    recentRequests.push(now);
    virusTotalRequestTimes.set(fetchImpl, recentRequests);
    return fetchImpl(...args);
  };
  const urlId = Buffer.from(url).toString('base64url');
  let report = await requestJson(
    rateLimitedFetch,
    name,
    `https://www.virustotal.com/api/v3/urls/${urlId}`,
    { headers },
    timeoutMs
  );

  if (report.error && report.httpStatus !== 404) return report.error;
  if (report.payload) {
    const attributes = report.payload.data && report.payload.data.attributes;
    if (attributes && attributes.last_analysis_stats) {
      return interpretVirusTotalStats(name, attributes.last_analysis_stats);
    }
  }

  const submission = await requestJson(rateLimitedFetch, name, 'https://www.virustotal.com/api/v3/urls', {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ url })
  }, timeoutMs);
  if (submission.error) return submission.error;
  const analysisId = submission.payload
    && submission.payload.data
    && submission.payload.data.id;
  if (typeof analysisId !== 'string' || !analysisId) {
    return makeCheck(name, 'unavailable', 'VirusTotal did not return an analysis identifier.');
  }

  const analysis = await requestJson(
    rateLimitedFetch,
    name,
    `https://www.virustotal.com/api/v3/analyses/${encodeURIComponent(analysisId)}`,
    { headers },
    timeoutMs
  );
  if (analysis.error) {
    if (analysis.httpStatus === 404) {
      return makeCheck(name, 'pending', 'The URL was submitted, but its analysis report is not available yet. Try again later.');
    }
    return analysis.error;
  }
  const attributes = analysis.payload && analysis.payload.data && analysis.payload.data.attributes;
  if (!attributes || attributes.status !== 'completed') {
    return makeCheck(name, 'pending', 'The URL was submitted to VirusTotal; analysis is still processing.');
  }
  return interpretVirusTotalStats(name, attributes.stats);
}

async function checkUrlhaus(url, env, fetchImpl, timeoutMs) {
  const name = 'URLhaus';
  const response = await requestJson(fetchImpl, name, 'https://urlhaus-api.abuse.ch/v1/url/', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Auth-Key': env.URLHAUS_AUTH_KEY
    },
    body: new URLSearchParams({ url })
  }, timeoutMs);
  if (response.error) return response.error;
  const payload = response.payload;
  if (!payload || typeof payload.query_status !== 'string') {
    return makeCheck(name, 'unavailable', 'URLhaus returned an unexpected response.');
  }
  if (payload.query_status === 'ok' && Array.isArray(payload.urls) && payload.urls.length > 0) {
    const entry = payload.urls[0];
    const currentStatus = entry.url_status ? ` The listed URL status is ${entry.url_status}.` : '';
    return makeCheck(
      name,
      'malicious',
      `URLhaus lists this URL in its malware-distribution URL database.${currentStatus}`,
      'malware-distribution'
    );
  }
  if (payload.query_status === 'no_results') {
    return makeCheck(
      name,
      'clean',
      'URLhaus returned no matching malware-distribution URL record; this limited lookup is not proof of safety.'
    );
  }
  if (/auth|key/i.test(payload.query_status)) {
    return makeCheck(name, 'unavailable', 'URLhaus rejected its Auth-Key. Check URLHAUS_AUTH_KEY and account access.');
  }
  return makeCheck(name, 'unavailable', 'URLhaus returned no usable URL reputation result.');
}

async function checkPhishTank(url, env, fetchImpl, timeoutMs) {
  const name = 'PhishTank';
  const body = new URLSearchParams({ url, format: 'json' });
  if (env.PHISHTANK_APP_KEY) body.set('app_key', env.PHISHTANK_APP_KEY);
  const response = await requestJson(fetchImpl, name, 'https://checkurl.phishtank.com/checkurl/', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': 'CyberShieldAI/1.0 (URL safety lookup)'
    },
    body
  }, timeoutMs);
  if (response.error) return response.error;
  if (response.payload && response.payload.errortext) {
    return makeCheck(name, 'unavailable', 'PhishTank rejected the lookup; check its API key and request limits.');
  }
  const record = response.payload && response.payload.results;
  if (!record || typeof record !== 'object') {
    return makeCheck(name, 'unavailable', 'PhishTank returned no usable URL reputation result.');
  }
  const inDatabase = record.in_database === true || record.in_database === 'true'
    || record.in_database === false || record.in_database === 'false';
  if (!inDatabase) {
    return makeCheck(name, 'unavailable', 'PhishTank returned an unexpected URL reputation result.');
  }
  if (record.in_database === false || record.in_database === 'false') {
    return makeCheck(
      name,
      'clean',
      'PhishTank returned no phishing record for this URL; this is not proof of safety.'
    );
  }
  if (record.verified === true || record.verified === 'y' || record.verified === 'true') {
    if (record.valid === true || record.valid === 'y' || record.valid === 'true') {
      return makeCheck(name, 'malicious', 'PhishTank reports this URL as a verified, valid phishing URL.', 'phishing');
    }
    return makeCheck(name, 'suspicious', 'PhishTank has a record for this URL, but it is not currently verified as valid.');
  }
  return makeCheck(name, 'suspicious', 'PhishTank has an unverified phishing report for this URL.');
}

async function checkThreatIntelligence(url, env, fetchImpl = globalThis.fetch, options = {}) {
  const configured = getProviderConfiguration(env);
  const timeoutMs = options.timeoutMs || REQUEST_TIMEOUT_MS;
  const checks = PROVIDERS.map((provider) => (
    configured[provider]
      ? null
      : makeCheck(provider, 'not_configured', 'This provider is not configured on the server.')
  ));
  const tasks = [
    ['Google Safe Browsing', () => checkGoogleSafeBrowsing(url, env, fetchImpl, timeoutMs)],
    ['VirusTotal', () => checkVirusTotal(url, env, fetchImpl, timeoutMs)],
    ['URLhaus', () => checkUrlhaus(url, env, fetchImpl, timeoutMs)],
    ['PhishTank', () => checkPhishTank(url, env, fetchImpl, timeoutMs)]
  ];
  const active = tasks.filter(([provider]) => configured[provider]);
  const results = await Promise.all(active.map(async ([provider, check]) => {
    try {
      return await check();
    } catch {
      return makeCheck(provider, 'unavailable', 'The provider check failed; no reputation verdict was obtained.');
    }
  }));
  for (const result of results) {
    checks[PROVIDERS.indexOf(result.provider)] = result;
  }
  return checks;
}

module.exports = {
  PROVIDERS,
  checkThreatIntelligence,
  getProviderConfiguration
};

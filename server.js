'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const express = require('express');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const ipaddr = require('ipaddr.js');
const { parse: parseDomain } = require('tldts');
const { PROVIDERS, checkThreatIntelligence, getProviderConfiguration } = require('./threat-intelligence');

const APP_ROOT = __dirname;
const PORT = Number(process.env.PORT || '3000');
const HOST = process.env.HOST || '127.0.0.1';
const MAX_URL_LENGTH = 2048;
const MAX_MESSAGE_LENGTH = 12000;
const THREAT_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const DEFAULT_DATA_DIR = path.join(APP_ROOT, 'data');
const SHORTENERS = new Set([
  'bit.ly', 't.co', 'tinyurl.com', 'is.gd', 'ow.ly', 'buff.ly', 'rb.gy',
  'cutt.ly', 'lnkd.in', 'shorturl.at', 'rebrand.ly'
]);
const BRAND_DOMAINS = [
  'amazon.com', 'amazon.in', 'paypal.com', 'google.com', 'microsoft.com',
  'apple.com', 'meesho.com', 'flipkart.com'
];
const TRUSTED_HOSTS = new Set([
  'meesho.com', 'www.meesho.com', 'amazon.in', 'www.amazon.in',
  'flipkart.com', 'www.flipkart.com'
]);
const URL_RE = /\bhttps?:\/\/[^\s<>"'`()\[\]{}]+/gi;

function isLocalOrPrivateHost(hostname) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (net.isIP(host)) {
    const address = ipaddr.parse(host);
    if (address.kind() === 'ipv6' && address.isIPv4MappedAddress()) {
      return address.toIPv4Address().range() !== 'unicast';
    }
    return address.range() !== 'unicast';
  }
  return host === 'localhost'
    || host.endsWith('.localhost')
    || host.endsWith('.local')
    || host.endsWith('.lan')
    || host.endsWith('.internal')
    || host.endsWith('.home.arpa')
    || !host.includes('.');
}

function isValidDomainHostname(hostname) {
  const normalized = hostname.toLowerCase().replace(/\.$/, '');
  if (normalized.length > 253) return false;
  const labels = normalized.split('.');
  return labels.length >= 2 && labels.every((label) =>
    label.length >= 1
    && label.length <= 63
    && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label));
}

function makeInvalidUrlError(message, submittedUrl) {
  const error = new Error(message);
  error.status = 400;
  error.code = 'INVALID_URL';
  error.submittedUrl = typeof submittedUrl === 'string' ? submittedUrl.slice(0, MAX_URL_LENGTH) : null;
  return error;
}

function parseSubmittedUrl(value) {
  if (typeof value !== 'string' || value.trim().length === 0 || value.length > MAX_URL_LENGTH) {
    throw makeInvalidUrlError(`URL must be a non-empty string of at most ${MAX_URL_LENGTH} characters.`, value);
  }
  const submittedUrl = value.trim();
  if (/[\u0000-\u0020\u007f]/.test(submittedUrl)) {
    throw makeInvalidUrlError('URL must not contain whitespace or control characters.', submittedUrl);
  }
  const explicitWebScheme = /^https?:\/\//i.test(submittedUrl);
  const hasOtherScheme = /^[a-z][a-z\d+.-]*:/i.test(submittedUrl)
    && !explicitWebScheme
    && !/^[^/:]+:\d+(?:\/|$)/.test(submittedUrl);
  if (hasOtherScheme) {
    throw makeInvalidUrlError('Only HTTP and HTTPS URLs are supported. Remove the unsupported scheme.', submittedUrl);
  }
  const candidate = explicitWebScheme ? submittedUrl : `https://${submittedUrl}`;
  let parsed;
  try {
    parsed = new URL(candidate);
  } catch {
    throw makeInvalidUrlError('Enter a valid hostname or a complete URL beginning with http:// or https://.', submittedUrl);
  }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) {
    throw makeInvalidUrlError('Only HTTP(S) URLs without embedded credentials can be analyzed.', submittedUrl);
  }
  if (!parsed.hostname || isLocalOrPrivateHost(parsed.hostname)) {
    throw makeInvalidUrlError('Local, private, link-local, reserved, and single-label hosts are not supported.', submittedUrl);
  }
  const host = parsed.hostname.replace(/^\[|\]$/g, '');
  if (!net.isIP(host) && !isValidDomainHostname(host)) {
    throw makeInvalidUrlError('The URL hostname is not syntactically valid. Check its labels and punctuation.', submittedUrl);
  }
  parsed.submittedUrl = submittedUrl;
  parsed.schemeWasAdded = !explicitWebScheme;
  return parsed;
}

function normalizeUrl(parsed) {
  return new URL(parsed.href).href;
}

function getDomainDetails(hostname) {
  const unwrappedHost = hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (net.isIP(unwrappedHost)) {
    return { registeredDomain: null, subdomain: null };
  }
  const parsed = parseDomain(unwrappedHost);
  const registeredDomain = parsed.domain && (parsed.isIcann || parsed.isPrivate)
    ? parsed.domain
    : null;
  return {
    registeredDomain,
    subdomain: registeredDomain ? parsed.subdomain || null : null
  };
}

function hashUrl(url) {
  return crypto.createHash('sha256').update(url).digest('hex');
}

function isThreatCacheEntryActive(entry, now = Date.now()) {
  const expiresAt = entry.expiresAt
    ? Date.parse(entry.expiresAt)
    : entry.confirmedAt
      ? Date.parse(entry.confirmedAt) + THREAT_CACHE_TTL_MS
      : Number.NaN;
  return Number.isFinite(expiresAt) && expiresAt > now;
}

function editDistance(left, right) {
  const row = Array.from({ length: right.length + 1 }, (_, index) => index);
  for (let i = 1; i <= left.length; i += 1) {
    let diagonal = row[0];
    row[0] = i;
    for (let j = 1; j <= right.length; j += 1) {
      const above = row[j];
      row[j] = Math.min(row[j] + 1, row[j - 1] + 1, diagonal + (left[i - 1] === right[j - 1] ? 0 : 1));
      diagonal = above;
    }
  }
  return row[right.length];
}

function inspectUrl(parsed) {
  const hostname = parsed.hostname.toLowerCase();
  const hostWithoutWww = hostname.replace(/^www\./, '');
  const findings = [];
  const labels = hostname.split('.');
  const addFinding = (message, points) => findings.push({ message, points });

  if (net.isIP(hostname.replace(/^\[|\]$/g, ''))) {
    addFinding('The address uses an IP number instead of a domain name.', 30);
  }
  if (hostname.startsWith('xn--') || hostname.includes('.xn--')) {
    addFinding('The domain uses internationalized characters that can resemble other letters.', 25);
  }
  if (labels.length > 4) addFinding('The domain has an unusually deep subdomain structure.', 15);
  if (parsed.href.length > 180) addFinding('The URL is unusually long.', 10);
  if (/%[0-9a-f]{2}/i.test(parsed.href)) addFinding('The URL contains percent-encoded characters.', 10);
  if (/%(?:00|0[1-9a-f]|1[0-9a-f]|7f)/i.test(parsed.href)) {
    addFinding('The URL contains percent-encoded control characters.', 20);
  }
  if (/%(?![0-9a-f]{2})/i.test(parsed.href)) addFinding('The URL contains malformed percent encoding.', 20);
  if (parsed.href.includes('@')) addFinding('The URL contains an @ character that can obscure its destination.', 20);
  if (parsed.port) addFinding('The URL uses a non-default port.', 15);

  const isShortener = SHORTENERS.has(hostWithoutWww);
  if (isShortener) {
    addFinding('This is a link-shortening service; its destination was not opened or expanded. This is not proof of malicious activity.', 10);
  }

  const hostContainsBrand = BRAND_DOMAINS.some((brand) => {
    const brandName = brand.split('.')[0];
    return labels.some((label) => label.includes(brandName))
      && !hostWithoutWww.endsWith(`.${brand}`)
      && hostWithoutWww !== brand;
  });
  if (hostContainsBrand) addFinding('A well-known brand name appears outside its known domain.', 30);

  const domainLabel = labels.length > 1 ? labels[labels.length - 2] : labels[0];
  const lookalike = BRAND_DOMAINS.find((brand) => {
    const brandName = brand.split('.')[0];
    return domainLabel.split(/[-_]/).some((label) =>
      label !== brandName
      && label.length >= 5
      && Math.abs(label.length - brandName.length) <= 2
      && editDistance(label, brandName) <= 2)
      && !hostWithoutWww.endsWith(`.${brand}`)
      && hostWithoutWww !== brand;
  });
  if (lookalike && !hostContainsBrand) {
    addFinding(`The domain name resembles ${lookalike.split('.')[0]} but is not its known domain.`, 30);
  }

  const redirectParameter = [...parsed.searchParams.keys()].some((key) =>
    /^(url|redirect|redirect_url|next|target|dest|destination|continue)$/i.test(key));
  if (redirectParameter) addFinding('A parameter may redirect to another destination; no redirect was followed.', 10);

  const trusted = [...TRUSTED_HOSTS].some((host) => hostWithoutWww === host || hostWithoutWww.endsWith(`.${host}`));
  if (trusted) addFinding('The host matches a configured familiar-domain hint; this is not a safety guarantee.', 0);
  if (parsed.protocol === 'http:') addFinding('The connection does not use HTTPS.', 15);
  else findings.push({ message: 'HTTPS encrypts the connection but does not prove that a site is trustworthy.', points: 0 });

  const evidence = findings.map((finding) => finding.message);
  const riskScore = Math.min(100, findings.reduce((score, finding) => score + finding.points, 0));
  const suspicious = riskScore > 0;
  const domainDetails = getDomainDetails(hostname);
  if (parsed.schemeWasAdded) {
    evidence.unshift('No scheme was supplied; HTTPS was assumed for scanning. Confirm the normalized URL before opening it.');
  }
  return {
    classification: suspicious ? 'suspicious' : 'unknown',
    severity: suspicious ? 'suspicious' : 'unverified',
    riskScore,
    evidence,
    reasons: findings.filter((finding) => finding.points > 0).map((finding) => finding.message),
    hostname,
    ...domainDetails,
    normalizedUrl: normalizeUrl(parsed),
    trustedDomainHint: trusted,
    certificateDetails: 'Not checked: the service never connects to the submitted host.'
  };
}

function readJson(filePath, fallback) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return fallback;
    throw error;
  }
}

function writeJson(filePath, value) {
  const temporaryPath = `${filePath}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  fs.writeFileSync(temporaryPath, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(temporaryPath, filePath);
}

function makeApiError(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

function safeTokenMatch(expected, actual) {
  if (typeof actual !== 'string') return false;
  const expectedBuffer = Buffer.from(expected);
  const actualBuffer = Buffer.from(actual);
  return expectedBuffer.length === actualBuffer.length
    && crypto.timingSafeEqual(expectedBuffer, actualBuffer);
}

function buildAssessment(parsed, heuristic, providerChecks, cachedThreat, blockedEntry = null) {
  const configuredChecks = providerChecks.filter((check) =>
    PROVIDERS.includes(check.provider) && check.status !== 'not_configured');
  const maliciousChecks = providerChecks.filter((check) => check.status === 'malicious');
  const suspiciousChecks = providerChecks.filter((check) => check.status === 'suspicious');
  const cleanChecks = providerChecks.filter((check) => check.status === 'clean');
  const hasHeuristicWarnings = heuristic.riskScore > 0;
  const providerVerdicts = new Set(providerChecks
    .filter((check) => ['clean', 'suspicious', 'malicious'].includes(check.status))
    .map((check) => check.status));
  const conflict = providerVerdicts.size > 1;
  const cacheCheck = cachedThreat
    ? [{
      provider: 'Local confirmed cache',
      status: 'malicious',
      details: `Matches a locally cached, previously confirmed ${cachedThreat.source || 'threat'} indicator.`,
      category: cachedThreat.category
    }]
    : [];
  const blocklistCheck = blockedEntry
    ? [{
      provider: 'Application blocklist',
      status: 'malicious',
      details: `This URL is blocked in CyberShield AI based on a prior confirmed malicious result (${blockedEntry.source}).`,
      category: 'confirmed-threat'
    }]
    : [];
  const checks = [
    {
      provider: 'URL validation',
      status: 'clean',
      details: 'A supported HTTP(S) URL with a syntactically valid public hostname was accepted.'
    },
    {
      provider: 'Local heuristics',
      status: hasHeuristicWarnings ? 'suspicious' : 'clean',
      details: hasHeuristicWarnings
        ? `${heuristic.reasons.length} URL pattern warning(s) detected. The score is a rule-based indicator, not a probability.`
        : 'No warning patterns were detected by the limited local checks; this is not proof of safety.'
    },
    {
      provider: 'DNS resolution',
      status: 'not_checked',
      details: 'Not checked. The scanner does not resolve or connect to user-supplied hostnames.'
    },
    {
      provider: 'Website reachability',
      status: 'not_checked',
      details: 'Not checked. The scanner never sends requests to the submitted website.'
    },
    {
      provider: 'HTTPS/TLS certificate',
      status: 'not_checked',
      details: 'Not checked. HTTPS encryption and certificate validity do not establish trust.'
    },
    {
      provider: 'Redirect chain',
      status: 'not_checked',
      details: 'Not checked. The submitted website was not opened and no redirects were followed.'
    },
    ...providerChecks,
    ...cacheCheck,
    ...blocklistCheck
  ];
  let verdict = 'unknown';
  if (maliciousChecks.length || cachedThreat || blockedEntry) verdict = 'malicious';
  else if (suspiciousChecks.length || hasHeuristicWarnings) verdict = 'suspicious';
  else if (configuredChecks.length > 0 && configuredChecks.every((check) => check.status === 'clean')) verdict = 'safe';

  const riskScore = cachedThreat || maliciousChecks.length || blockedEntry
    ? 100
    : Math.max(heuristic.riskScore, suspiciousChecks.length ? 65 : 0);
  const reasons = [...heuristic.reasons];
  for (const check of [...maliciousChecks, ...suspiciousChecks, ...cacheCheck, ...blocklistCheck]) {
    reasons.push(`${check.provider}: ${check.details}`);
  }
  if (conflict) {
    reasons.push('Threat-intelligence providers returned conflicting results; a clean response does not override a reported threat.');
  }
  if (verdict === 'unknown' && configuredChecks.some((check) => ['unavailable', 'pending'].includes(check.status))) {
    reasons.push('One or more configured reputation checks did not complete; the result is inconclusive.');
  }
  if (verdict === 'unknown' && configuredChecks.some((check) => check.status === 'not_checked')) {
    reasons.push('Configured reputation providers were not contacted because external-sharing consent was not given.');
  }
  if (verdict === 'unknown' && configuredChecks.length === 0 && !hasHeuristicWarnings) {
    reasons.push('Only limited local heuristics ran; no configured reputation provider returned a result.');
  }

  const recommendation = verdict === 'malicious'
    ? 'Do not open this URL. CyberShield AI blocks it because a threat-intelligence source or confirmed local record reported a threat.'
    : verdict === 'suspicious'
      ? 'Do not enter credentials or payment details. Verify the destination through a trusted, independently obtained link.'
      : verdict === 'safe'
        ? 'No configured provider reported a threat and no local warning pattern was found. This is not a guarantee that the URL is safe.'
        : 'Treat this URL as unverified. Avoid opening it or entering sensitive information until you can verify it independently.';
  const analyzedAt = new Date().toISOString();
  const confidence = verdict === 'malicious'
    ? 'high'
    : verdict === 'safe'
      ? 'medium'
      : verdict === 'suspicious' && suspiciousChecks.length
        ? 'medium'
        : 'low';
  const legacyClassification = verdict === 'malicious'
    ? (cachedThreat
      ? (cachedThreat.category === 'phishing' ? 'phishing' : 'potential-malware')
      : maliciousChecks.some((check) => check.category && check.category !== 'phishing')
        ? 'potential-malware'
        : 'phishing')
    : verdict === 'safe'
      ? 'safe-looking'
      : verdict;
  const severity = verdict === 'malicious'
    ? 'high-risk'
    : verdict === 'suspicious'
      ? 'suspicious'
      : verdict === 'safe'
        ? 'safe'
        : 'unverified';
  const externalChecks = providerChecks.filter((check) => check.status !== 'not_configured');
  const externalCheck = {
    configured: externalChecks.map((check) => check.provider),
    checked: externalChecks
      .filter((check) => ['clean', 'malicious', 'suspicious'].includes(check.status))
      .map((check) => check.provider),
    threats: externalChecks
      .filter((check) => ['malicious', 'suspicious'].includes(check.status))
      .map((check) => ({ provider: check.provider, category: check.category || check.status })),
    errors: externalChecks
      .filter((check) => check.status === 'unavailable')
      .map((check) => ({ provider: check.provider, error: check.details }))
  };

  return {
    submittedUrl: parsed.submittedUrl || parsed.href,
    url: parsed.href,
    verdict,
    riskScore,
    confidence,
    checks,
    providers: providerChecks,
    reasons,
    recommendation,
    recommendations: [recommendation],
    analyzedAt,
    scannedAt: analyzedAt,
    classification: legacyClassification,
    severity,
    evidence: heuristic.evidence,
    hostname: heuristic.hostname,
    registeredDomain: heuristic.registeredDomain,
    subdomain: heuristic.subdomain,
    normalizedUrl: heuristic.normalizedUrl,
    trustedDomainHint: heuristic.trustedDomainHint,
    certificateDetails: heuristic.certificateDetails,
    threatMatch: Boolean(cachedThreat || maliciousChecks.length || blockedEntry),
    blocked: verdict === 'malicious',
    blockEntryId: blockedEntry ? blockedEntry.id : null,
    externalCheck,
    analysisSource: blockedEntry
      ? 'application blocklist'
      : cachedThreat
      ? 'local-confirmed-cache'
      : maliciousChecks.length
        ? maliciousChecks.map((check) => check.provider).join(', ')
        : hasHeuristicWarnings
          ? 'local heuristics'
          : configuredChecks.length > 0 && configuredChecks.every((check) => check.status === 'clean')
            ? 'configured threat-intelligence providers and local heuristics'
            : 'limited local heuristics',
    model: { used: false, available: false, reason: 'No trained model is configured.' }
  };
}

function createApp(options = {}) {
  const env = options.env || process.env;
  const dataDir = options.dataDir || env.DATA_DIR || DEFAULT_DATA_DIR;
  const apiToken = env.API_TOKEN || '';
  const fetchImpl = options.fetch || globalThis.fetch;
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const historyPath = path.join(dataDir, 'history.json');
  const threatsPath = path.join(dataDir, 'threats.json');
  const blockedLinksPath = path.join(dataDir, 'blocked-links.json');
  const providerConfiguration = getProviderConfiguration(env);
  const app = express();

  function readBlockedLinks() {
    const blockedLinks = readJson(blockedLinksPath, { entries: [] });
    if (!Array.isArray(blockedLinks.entries)) {
      throw new Error('Application blocklist has an invalid format.');
    }
    return blockedLinks;
  }

  function findBlockedLink(id) {
    return readBlockedLinks().entries.find((entry) => entry.id === id) || null;
  }

  function addBlockedLink(id, hostname, source, blockedAt) {
    const blockedLinks = readBlockedLinks();
    const existing = blockedLinks.entries.find((entry) => entry.id === id);
    if (existing) return existing;
    const entry = { id, hostname, source, blockedAt };
    blockedLinks.entries = [...blockedLinks.entries, entry].slice(-10000);
    writeJson(blockedLinksPath, blockedLinks);
    return entry;
  }

  app.disable('x-powered-by');
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        baseUri: ["'none'"],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        imgSrc: ["'self'", 'data:'],
        objectSrc: ["'none'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"]
      }
    }
  }));
  app.use(express.json({ limit: '16kb', strict: true }));

  const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 60,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { ok: false, error: 'Too many requests. Please wait before trying again.' }
  });
  app.use('/api', apiLimiter);
  app.use('/api', (req, res, next) => {
    if (req.path === '/health' || req.path === '/auth/status' || req.path === '/auth/session') return next();
    if (!apiToken || safeTokenMatch(apiToken, req.get('x-api-key'))) return next();
    return res.status(401).json({ ok: false, error: 'An API key is required or invalid.' });
  });

  app.get('/api/health', (req, res) => {
    res.json({
      ok: true,
      service: 'cybershield-ai',
      status: 'healthy',
      analysis: 'local heuristics and cached threat data',
      configuredThreatIntelligence: PROVIDERS.filter((name) => providerConfiguration[name]),
      machineLearning: { available: false, reason: 'No trained model or labeled dataset is configured.' }
    });
  });

  app.get('/api/auth/status', (req, res) => {
    res.json({ ok: true, required: Boolean(apiToken) });
  });

  app.post('/api/auth/session', (req, res) => {
    if (!apiToken) return res.json({ ok: true, authenticated: true });
    if (safeTokenMatch(apiToken, req.body && req.body.apiKey)) {
      return res.json({ ok: true, authenticated: true });
    }
    return res.status(401).json({ ok: false, error: 'The API key is invalid.' });
  });

  app.get('/api/allowlist', (req, res) => {
    res.json({ ok: true, allowlist: [...TRUSTED_HOSTS] });
  });

  app.get('/api/protection/status', (req, res) => {
    const threats = readJson(threatsPath, { entries: [], synchronizedAt: null });
    const blockedLinks = readBlockedLinks();
    const providers = PROVIDERS.map((name) => ({
      name,
      configured: providerConfiguration[name]
    }));
    res.json({
      ok: true,
      mode: 'local',
      onlineIntelConfigured: providers.some((provider) => provider.configured),
      threatIntelProviders: providers,
      threatIntelNotice: 'Provider checks require per-scan consent. A submitted URL is shared with every configured provider; provider terms, rate limits, and retention policies apply.',
      cachedConfirmedThreats: Array.isArray(threats.entries) ? threats.entries.length : 0,
      applicationBlockedLinks: blockedLinks.entries.length,
      synchronizedAt: threats.synchronizedAt || null,
      offlineCapability: 'Checks only locally cached confirmed threats; new threats may not be detected.',
      machineLearning: { available: false, reason: 'No trained model or labeled dataset is configured.' }
    });
  });

  app.post('/api/protection/sync', (req, res, next) => {
    try {
      const threats = readJson(threatsPath, { entries: [], synchronizedAt: null });
      return res.status(503).json({
        ok: false,
        error: 'No remote threat-feed synchronization source is configured. Provider-confirmed scan matches are cached locally as they are found.',
        cachedConfirmedThreats: Array.isArray(threats.entries) ? threats.entries.length : 0
      });
    } catch (error) {
      next(error);
    }
  });

  async function scanUrl(req, res, next) {
    try {
      const parsed = parseSubmittedUrl(req.body && req.body.url);
      const heuristic = inspectUrl(parsed);
      const threats = readJson(threatsPath, { entries: [], synchronizedAt: null });
      if (!Array.isArray(threats.entries)) throw new Error('Threat cache has an invalid format.');
      const normalized = heuristic.normalizedUrl;
      const urlHash = hashUrl(normalized);
      const blockedEntry = findBlockedLink(urlHash);
      const cached = threats.entries.find((entry) =>
        isThreatCacheEntryActive(entry)
        && ((entry.type === 'url-sha256' && entry.indicator === urlHash)
          || (entry.type === 'domain' && entry.indicator === heuristic.hostname)));
      const providerChecks = blockedEntry
        ? PROVIDERS.map((provider) => ({
          provider,
          status: 'not_checked',
          details: 'Skipped because this URL is already blocked in the CyberShield AI application.'
        }))
        : cached
        ? PROVIDERS.map((provider) => ({
          provider,
          status: 'not_configured',
          details: 'Skipped because this URL matches a confirmed local threat cache entry.'
        }))
        : req.body && req.body.consentToExternalScan === true
          ? await checkThreatIntelligence(normalized, env, fetchImpl)
          : PROVIDERS.map((provider) => ({
            provider,
            status: providerConfiguration[provider] ? 'not_checked' : 'not_configured',
            details: providerConfiguration[provider]
              ? 'Not checked because per-scan external sharing consent was not given.'
              : 'This provider is not configured on the server.'
          }));

      const result = buildAssessment(parsed, heuristic, providerChecks, cached, blockedEntry);
      const maliciousChecks = providerChecks.filter((check) => check.status === 'malicious');
      if (!cached && maliciousChecks.length) {
        const category = maliciousChecks.some((check) => check.category && check.category !== 'phishing')
          ? 'potential-malware'
          : 'phishing';
        const entry = {
          type: 'url-sha256',
          indicator: urlHash,
          category,
          source: maliciousChecks.map((check) => check.provider).join(', '),
          confirmedAt: result.analyzedAt,
          expiresAt: new Date(Date.parse(result.analyzedAt) + THREAT_CACHE_TTL_MS).toISOString()
        };
        const latestThreats = readJson(threatsPath, { entries: [], synchronizedAt: null });
        if (!Array.isArray(latestThreats.entries)) throw new Error('Threat cache has an invalid format.');
        latestThreats.entries = [...latestThreats.entries.filter((item) =>
          !(item.type === entry.type && item.indicator === entry.indicator)), entry].slice(-10000);
        writeJson(threatsPath, latestThreats);
      }
      if (result.verdict === 'malicious') {
        const maliciousSources = providerChecks
          .filter((check) => check.status === 'malicious')
          .map((check) => check.provider);
        const source = blockedEntry
          ? blockedEntry.source
          : cached
            ? cached.source || 'local confirmed threat cache'
            : maliciousSources.join(', ') || 'confirmed local threat record';
        const persistedBlock = addBlockedLink(urlHash, heuristic.hostname, source, result.analyzedAt);
        result.blocked = true;
        result.blockEntryId = persistedBlock.id;
        result.recommendation = 'Do not open this URL. CyberShield AI blocks it because a threat-intelligence source or confirmed local record reported a threat.';
        result.recommendations = [result.recommendation];
      }

      const history = readJson(historyPath, []);
      if (!Array.isArray(history)) throw new Error('Scan history has an invalid format.');
      history.unshift({
        id: crypto.randomUUID(),
        scannedAt: result.analyzedAt,
        hostname: result.hostname,
        classification: result.verdict,
        severity: result.severity,
        threatMatch: result.threatMatch,
        evidence: result.reasons.slice(0, 6)
      });
      writeJson(historyPath, history.slice(0, 100));
      return res.json({ ok: true, result });
    } catch (error) {
      return next(error);
    }
  }

  app.post('/api/scan/url', scanUrl);
  app.post('/api/check-link', scanUrl);

  app.get('/api/blocked-links', (req, res, next) => {
    try {
      res.json({ ok: true, entries: readBlockedLinks().entries });
    } catch (error) {
      next(error);
    }
  });

  app.delete('/api/blocked-links/:id', (req, res, next) => {
    try {
      if (!/^[a-f\d]{64}$/i.test(req.params.id)) {
        return res.status(400).json({ ok: false, error: 'A valid blocked-link identifier is required.' });
      }
      const blockedLinks = readBlockedLinks();
      const previousCount = blockedLinks.entries.length;
      blockedLinks.entries = blockedLinks.entries.filter((entry) => entry.id !== req.params.id);
      const removed = blockedLinks.entries.length !== previousCount;
      if (removed) writeJson(blockedLinksPath, blockedLinks);
      return res.json({
        ok: true,
        removed,
        message: removed
          ? 'The entry was removed from this application’s blocklist. A later malicious scan may add it again.'
          : 'No matching blocklist entry was found.'
      });
    } catch (error) {
      return next(error);
    }
  });

  app.post('/api/scan/message', (req, res, next) => {
    try {
      const message = req.body && req.body.message;
      if (typeof message !== 'string' || message.length === 0 || message.length > MAX_MESSAGE_LENGTH) {
        throw makeApiError(400, `Message must be a non-empty string of at most ${MAX_MESSAGE_LENGTH} characters.`);
      }
      const candidates = message.match(URL_RE) || [];
      const urls = [...new Set(candidates.map((candidate) =>
        candidate.replace(/[.,!?;:]+$/g, '')))].slice(0, 20);
      const results = [];
      for (const url of urls) {
        try {
          const parsed = parseSubmittedUrl(url);
          const heuristic = inspectUrl(parsed);
          const threats = readJson(threatsPath, { entries: [], synchronizedAt: null });
          if (!Array.isArray(threats.entries)) throw new Error('Threat cache has an invalid format.');
          const urlHash = hashUrl(heuristic.normalizedUrl);
          const blockedEntry = findBlockedLink(urlHash);
          const cached = threats.entries.find((entry) =>
            isThreatCacheEntryActive(entry)
            && ((entry.type === 'url-sha256' && entry.indicator === urlHash)
              || (entry.type === 'domain' && entry.indicator === heuristic.hostname)));
          const providerChecks = PROVIDERS.map((provider) => ({
            provider,
            status: 'not_configured',
            details: 'Message analysis does not contact external providers.'
          }));
          const result = buildAssessment(parsed, heuristic, providerChecks, cached, blockedEntry);
          let persistedBlock = blockedEntry;
          if (result.verdict === 'malicious') {
            persistedBlock = addBlockedLink(
              urlHash,
              heuristic.hostname,
              blockedEntry ? blockedEntry.source : cached
                ? cached.source || 'local confirmed threat cache'
                : 'confirmed local threat record',
              result.analyzedAt
            );
          }
          results.push({
            hostname: result.hostname,
            verdict: result.verdict,
            riskScore: result.riskScore,
            confidence: result.confidence,
            checks: result.checks,
            reasons: result.reasons,
            recommendation: result.recommendation,
            analyzedAt: result.analyzedAt,
            classification: result.classification,
            severity: result.severity,
            threatMatch: result.threatMatch,
            evidence: result.evidence,
            blocked: Boolean(persistedBlock),
            blockEntryId: persistedBlock ? persistedBlock.id : null
          });
        } catch (error) {
          results.push({
            verdict: 'unknown',
            riskScore: 0,
            confidence: 'low',
            checks: [],
            reasons: [error.message],
            recommendation: 'The extracted link could not be analyzed. Do not open it until you verify it independently.',
            analyzedAt: new Date().toISOString(),
            classification: 'unknown',
            severity: 'unverified',
            evidence: [error.message]
          });
        }
      }
      res.json({
        ok: true,
        messageStored: false,
        externalServiceUsed: false,
        notice: 'Message text was analyzed in memory and was not saved or sent to a third party.',
        urlsFound: results.length,
        results
      });
    } catch (error) {
      next(error);
    }
  });

  app.get('/api/scan/history', (req, res, next) => {
    try {
      const history = readJson(historyPath, []);
      if (!Array.isArray(history)) throw new Error('Scan history has an invalid format.');
      res.json({ ok: true, history });
    } catch (error) {
      next(error);
    }
  });

  app.delete('/api/scan/history', (req, res, next) => {
    try {
      writeJson(historyPath, []);
      res.json({ ok: true, deleted: true });
    } catch (error) {
      next(error);
    }
  });

  app.post('/api/clear-blocks', (req, res, next) => {
    try {
      writeJson(threatsPath, { entries: [], synchronizedAt: null });
      writeJson(blockedLinksPath, { entries: [] });
      res.json({ ok: true, message: 'Local cached threat data and the CyberShield AI application blocklist were cleared.' });
    } catch (error) {
      next(error);
    }
  });

  app.use(express.static(path.join(APP_ROOT, 'public'), { index: 'index.html', dotfiles: 'ignore' }));
  app.get('/', (req, res) => res.sendFile(path.join(APP_ROOT, 'public', 'index.html')));
  app.use('/api', (req, res) => res.status(404).json({ ok: false, error: 'API endpoint not found.' }));
  app.use((req, res) => res.status(404).send('Not found.'));

  app.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    if (error.type === 'entity.too.large') {
      return res.status(413).json({ ok: false, error: 'Request body is too large.' });
    }
    if (error instanceof SyntaxError && error.status === 400) {
      return res.status(400).json({ ok: false, error: 'Request body must be valid JSON.' });
    }
    const status = Number.isInteger(error.status) ? error.status : 500;
    if (status >= 500) console.error(`Request failed (${req.method} ${req.path}): internal service error.`);
    if (error.code === 'INVALID_URL') {
      return res.status(400).json({
        ok: false,
        verdict: 'invalid',
        submittedUrl: error.submittedUrl,
        normalizedUrl: null,
        hostname: null,
        registeredDomain: null,
        riskScore: null,
        confidence: 'low',
        checks: [],
        providers: [],
        reasons: [error.message],
        recommendation: 'Correct the URL format and submit a complete HTTP or HTTPS address.',
        recommendations: ['Correct the URL format and submit a complete HTTP or HTTPS address.'],
        analyzedAt: new Date().toISOString(),
        error: error.message
      });
    }
    return res.status(status).json({
      ok: false,
      error: status >= 500 ? 'The request could not be completed. Check the server logs.' : error.message
    });
  });

  return app;
}

function isLoopbackAddress(address) {
  return address === '127.0.0.1' || address === '::1' || address === 'localhost';
}

if (require.main === module) {
  if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
    console.error('PORT must be an integer between 1 and 65535.');
    process.exitCode = 1;
  } else if (!net.isIP(HOST) && HOST !== 'localhost') {
    console.error('HOST must be a loopback address, or an IP address protected with API_TOKEN.');
    process.exitCode = 1;
  } else if (!isLoopbackAddress(HOST)
    && (!process.env.API_TOKEN || Buffer.byteLength(process.env.API_TOKEN) < 32)) {
    console.error('Refusing non-loopback binding without an API_TOKEN of at least 32 bytes.');
    process.exitCode = 1;
  } else {
    if (!process.env.API_TOKEN) {
      console.warn('API_TOKEN is not set; protected API routes are unauthenticated on this loopback server.');
    }
    const app = createApp();
    const server = app.listen(PORT, HOST);
    server.requestTimeout = 10000;
    server.headersTimeout = 12000;
    server.keepAliveTimeout = 5000;
    server.on('listening', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        console.error('CyberShield AI did not start because the listening address could not be confirmed.');
        process.exitCode = 1;
        return;
      }
      console.log(`CyberShield AI listening on http://${HOST}:${address.port}`);
    });
    server.on('error', (error) => {
      if (error.code === 'EADDRINUSE') {
        console.error(`Port ${PORT} is already in use on ${HOST}; CyberShield AI did not start.`);
        console.error('No process was stopped. Identify the listener and stop it only if you confirm it is an old CyberShield AI instance, or choose another port: $env:PORT = "3001"; npm.cmd run dev');
      } else {
        console.error(`Server could not bind to ${HOST}:${PORT} (${error.code || 'unknown error'}).`);
      }
      process.exitCode = 1;
    });
  }
}

module.exports = {
  createApp,
  inspectUrl,
  isLocalOrPrivateHost,
  normalizeUrl,
  parseSubmittedUrl
};

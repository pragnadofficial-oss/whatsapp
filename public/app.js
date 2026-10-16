'use strict';

const apiKeyDialog = document.querySelector('#api-key-dialog');
const apiKeyForm = document.querySelector('#api-key-form');
const apiKeyInput = document.querySelector('#api-key-input');
const apiKeyButton = document.querySelector('#api-key-button');
const apiKeyError = document.querySelector('#api-key-error');
const keyStoreName = 'cybershield-api-key';
let apiKeyRequired = false;
let apiKey = sessionStorage.getItem(keyStoreName) || '';

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (options.body) headers.set('Content-Type', 'application/json');
  if (apiKey) headers.set('X-API-Key', apiKey);
  let response;
  try {
    response = await fetch(path, { ...options, headers });
  } catch {
    throw new Error('Could not reach the CyberShield AI server. Check that it is running and try again.');
  }
  const payload = await response.json().catch(() => ({ ok: false, error: 'The server returned an invalid response.' }));
  if (!response.ok) {
    if (response.status === 401 && apiKeyRequired) {
      apiKey = '';
      sessionStorage.removeItem(keyStoreName);
      showApiKeyDialog();
    }
    const error = new Error(payload.error || `Request failed (${response.status}).`);
    error.status = response.status;
    error.verdict = payload.verdict;
    error.payload = payload;
    throw error;
  }
  return payload;
}

function showApiKeyDialog() {
  apiKeyError.classList.add('hidden');
  if (!apiKeyDialog.open) apiKeyDialog.showModal();
}

function showMessage(target, text, type = '') {
  CyberShieldResults.renderMessage(target, text, type);
}

function showAnalysis(target, result) {
  CyberShieldResults.renderAnalysis(target, result);
}

function makeHistoryRow(item) {
  const row = document.createElement('div');
  row.className = 'history-row';
  const host = document.createElement('span');
  host.className = 'history-host';
  host.textContent = item.hostname;
  host.title = item.hostname;
  const date = document.createElement('time');
  date.className = 'history-date';
  const timestamp = new Date(item.scannedAt);
  date.dateTime = timestamp.toISOString();
  date.textContent = timestamp.toLocaleString();
  const tag = document.createElement('span');
  tag.className = `status-tag ${item.severity || 'unverified'}`;
  tag.textContent = item.classification.replaceAll('-', ' ');
  row.append(host, date, tag);
  return row;
}

async function loadStatus() {
  const health = await api('/api/health');
  const status = await api('/api/protection/status');
  document.querySelector('#threat-count').textContent = String(status.cachedConfirmedThreats);
  document.querySelector('#model-value').textContent = status.machineLearning.available ? 'AVAILABLE' : 'NOT CONFIGURED';
  document.querySelector('#protection-copy').textContent = status.offlineCapability;
  document.querySelector('#mode-copy').textContent = status.onlineIntelConfigured
    ? 'Local checks plus optional configured threat-intelligence providers'
    : 'Threat checks stay on this device';
  document.querySelector('#mode-value').textContent = status.onlineIntelConfigured ? 'LOCAL + OPT-IN' : 'LOCAL';
  const consentCopy = document.querySelector('#external-consent-copy');
  const configuredProviders = status.threatIntelProviders
    .filter((provider) => provider.configured)
    .map((provider) => provider.name);
  consentCopy.textContent = configuredProviders.length
    ? `Allow this URL to be sent to ${configuredProviders.join(', ')}. VirusTotal may add submitted or queried URLs to its community dataset. Do not send confidential URLs.`
    : 'No external provider is configured. This scan will use limited local checks only.';
  document.querySelector('#external-consent').disabled = !status.onlineIntelConfigured;
  if (health.machineLearning && health.machineLearning.available) {
    document.querySelector('#model-value').textContent = 'AVAILABLE';
  }
}

async function loadHistory() {
  const data = await api('/api/scan/history');
  const list = document.querySelector('#history-list');
  list.replaceChildren();
  document.querySelector('#scan-count').textContent = String(data.history.length);
  if (!data.history.length) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    empty.textContent = 'No URL scans yet. Scan results will appear here.';
    list.append(empty);
    return;
  }
  for (const item of data.history.slice(0, 10)) list.append(makeHistoryRow(item));
}

async function loadBlockedLinks() {
  const data = await api('/api/blocked-links');
  const list = document.querySelector('#blocked-list');
  list.replaceChildren();
  document.querySelector('#blocked-count').textContent = String(data.entries.length);
  if (!data.entries.length) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    empty.textContent = 'No links are currently blocked in this app.';
    list.append(empty);
    return;
  }
  for (const entry of data.entries) {
    const row = document.createElement('div');
    row.className = 'blocked-entry';
    const details = document.createElement('div');
    details.className = 'blocked-entry-details';
    const hostname = document.createElement('strong');
    hostname.className = 'history-host';
    hostname.textContent = entry.hostname;
    const source = document.createElement('span');
    source.className = 'blocked-source';
    source.textContent = `Reported by ${entry.source}`;
    const time = document.createElement('time');
    time.className = 'history-date';
    const timestamp = new Date(entry.blockedAt);
    if (!Number.isNaN(timestamp.valueOf())) {
      time.dateTime = timestamp.toISOString();
      time.textContent = timestamp.toLocaleString();
    }
    details.append(hostname, source, time);
    const remove = document.createElement('button');
    remove.className = 'quiet-button';
    remove.type = 'button';
    remove.textContent = 'Remove';
    remove.setAttribute('aria-label', `Remove ${entry.hostname} from the application blocklist`);
    remove.addEventListener('click', async () => {
      remove.disabled = true;
      try {
        await api(`/api/blocked-links/${encodeURIComponent(entry.id)}`, { method: 'DELETE' });
        await loadBlockedLinks();
        await loadStatus();
      } catch (error) {
        remove.disabled = false;
        window.alert(error.message);
      }
    });
    row.append(details, remove);
    list.append(row);
  }
}

document.querySelector('#url-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const target = document.querySelector('#url-result');
  const button = event.currentTarget.querySelector('button[type="submit"]');
  const buttonLabel = button.querySelector('span');
  const originalLabel = buttonLabel.textContent;
  const url = document.querySelector('#url-input').value.trim();
  const consentCheckbox = document.querySelector('#external-consent');
  const consentToExternalScan = consentCheckbox.checked;
  consentCheckbox.checked = false;
  button.disabled = true;
  button.setAttribute('aria-busy', 'true');
  buttonLabel.textContent = 'Analyzing…';
  target.className = 'result-box';
  target.textContent = 'Checking URL patterns and any consented reputation providers without opening the address…';
  try {
    const response = await api('/api/scan/url', {
      method: 'POST',
      body: JSON.stringify({
        url,
        consentToExternalScan
      })
    });
    if (!CyberShieldResults.renderUrlResponse(target, response)) {
      throw new Error('The server returned an invalid analysis result.');
    }
    await Promise.all([loadHistory(), loadStatus(), loadBlockedLinks()]);
  } catch (error) {
    if (error.verdict === 'invalid') {
      CyberShieldResults.renderAnalysis(target, error.payload);
    } else {
      showMessage(target, error.message, 'unknown');
    }
  } finally {
    button.disabled = false;
    button.setAttribute('aria-busy', 'false');
    buttonLabel.textContent = originalLabel;
  }
});

document.querySelector('#message-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const target = document.querySelector('#message-result');
  const button = event.currentTarget.querySelector('button[type="submit"]');
  button.disabled = true;
  target.className = 'result-box';
  target.textContent = 'Checking message links in memory…';
  try {
    const response = await api('/api/scan/message', {
      method: 'POST',
      body: JSON.stringify({ message: document.querySelector('#message-input').value })
    });
    target.className = 'result-box';
    target.replaceChildren();
    const notice = document.createElement('p');
    notice.className = 'result-copy';
    notice.textContent = response.notice;
    target.append(notice);
    if (!response.results.length) {
      const noLinks = document.createElement('p');
      noLinks.className = 'result-copy';
      noLinks.textContent = 'No complete HTTP(S) links were found in this message.';
      target.append(noLinks);
    } else {
      for (const result of response.results) {
        const item = document.createElement('div');
        item.className = 'message-item';
        showAnalysis(item, result);
        target.append(item);
      }
    }
    await loadBlockedLinks();
    await loadStatus();
  } catch (error) {
    showMessage(target, error.message, 'unverified');
  } finally {
    button.disabled = false;
  }
});

document.querySelector('#delete-history').addEventListener('click', async () => {
  if (!window.confirm('Delete all saved URL scan history?')) return;
  try {
    await api('/api/scan/history', { method: 'DELETE' });
    await loadHistory();
  } catch (error) {
    window.alert(error.message);
  }
});

document.querySelector('#cancel-api-key').addEventListener('click', () => apiKeyDialog.close());
apiKeyButton.addEventListener('click', showApiKeyDialog);
apiKeyForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const candidate = apiKeyInput.value;
  try {
    const response = await fetch('/api/auth/session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ apiKey: candidate })
    });
    const payload = await response.json();
    if (!response.ok || !payload.authenticated) throw new Error(payload.error || 'Could not authenticate.');
    apiKey = candidate;
    sessionStorage.setItem(keyStoreName, apiKey);
    apiKeyInput.value = '';
    apiKeyDialog.close();
    await initializeDashboard();
  } catch (error) {
    apiKeyError.textContent = error.message;
    apiKeyError.classList.remove('hidden');
  }
});

function updateConnection() {
  const pill = document.querySelector('#connection-pill');
  const label = pill.querySelector('span');
  const online = navigator.onLine;
  pill.classList.toggle('offline', !online);
  label.textContent = online ? 'Browser online' : 'Offline · cached checks only';
}

window.addEventListener('online', updateConnection);
window.addEventListener('offline', updateConnection);

async function initializeDashboard() {
  updateConnection();
  try {
    const auth = await fetch('/api/auth/status').then((response) => response.json());
    apiKeyRequired = auth.required;
    apiKeyButton.classList.toggle('hidden', !apiKeyRequired);
    if (apiKeyRequired && !apiKey) {
      showApiKeyDialog();
      return;
    }
    await Promise.all([loadStatus(), loadHistory(), loadBlockedLinks()]);
  } catch (error) {
    document.querySelector('#protection-copy').textContent = 'Backend unavailable. Start the local server to scan.';
    showMessage(document.querySelector('#url-result'), error.message, 'unverified');
  }
}

initializeDashboard();

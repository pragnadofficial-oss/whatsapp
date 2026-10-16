'use strict';

(function exposeResultRendering(root) {
  function addText(target, tagName, className, text) {
    const element = document.createElement(tagName);
    if (className) element.className = className;
    element.textContent = String(text);
    target.append(element);
    return element;
  }

  function renderMessage(target, text, type = '') {
    target.className = `result-box ${type}`.trim();
    target.replaceChildren();
    addText(target, 'p', 'result-copy', text);
  }

  function renderAnalysis(target, result) {
    const verdict = result.verdict
      || (result.classification === 'safe-looking' ? 'safe' : result.classification)
      || 'unknown';
    const severity = result.severity
      || (verdict === 'malicious' ? 'high-risk' : verdict === 'safe' || verdict === 'clean' ? 'safe' : verdict);
    target.className = `result-box ${severity}`;
    target.replaceChildren();

    if (verdict === 'malicious') {
      const warning = document.createElement('div');
      warning.className = 'blocked-warning';
      warning.setAttribute('role', 'alert');
      addText(warning, 'strong', '', result.blocked
        ? 'BLOCKED IN CYBERSHIELD AI'
        : 'MALICIOUS — DO NOT OPEN');
      addText(warning, 'p', '', 'This application will not open, preview, or follow this URL. The block applies only inside this app.');
      target.append(warning);
    }

    const heading = document.createElement('div');
    heading.className = `result-heading ${severity}`;
    addText(heading, 'span', '', verdict.replaceAll('-', ' ').toUpperCase());
    if (Number.isFinite(result.riskScore)) {
      addText(heading, 'span', '', `RISK ${result.riskScore}/100`);
    }
    target.append(heading);

    if (Number.isFinite(result.riskScore)) {
      addText(target, 'p', 'result-copy', `${result.confidence || 'low'} confidence · rule-based risk score ${result.riskScore}/100, not a probability.`);
    } else {
      addText(target, 'p', 'result-copy', `${result.confidence || 'low'} confidence · no risk score for invalid input.`);
    }
    if (result.recommendation) addText(target, 'p', 'result-copy', result.recommendation);
    if (result.submittedUrl) addText(target, 'p', 'result-copy', `Submitted: ${result.submittedUrl}`);
    if (result.normalizedUrl) addText(target, 'p', 'result-copy', `Normalized: ${result.normalizedUrl}`);
    addText(target, 'p', 'result-copy', `Hostname: ${result.hostname || 'Not available'}`);
    addText(target, 'p', 'result-copy', `Registered domain: ${result.registeredDomain || 'Not available from the public suffix data'}`);
    if (result.subdomain) addText(target, 'p', 'result-copy', `Subdomain: ${result.subdomain}`);

    const reasons = Array.isArray(result.reasons) ? result.reasons : result.evidence;
    if (Array.isArray(reasons) && reasons.length) {
      const title = addText(target, 'p', 'result-copy', 'Reasons');
      title.classList.add('result-subheading');
      const list = document.createElement('ul');
      list.className = 'evidence-list';
      for (const reason of reasons) addText(list, 'li', '', reason);
      target.append(list);
    }

    if (Array.isArray(result.checks) && result.checks.length) {
      const title = addText(target, 'p', 'result-copy', 'Reputation checks');
      title.classList.add('result-subheading');
      const list = document.createElement('ul');
      list.className = 'provider-list';
      for (const check of result.checks) {
        addText(list, 'li', `provider-status ${check.status || 'unavailable'}`,
          `${check.provider}: ${check.status || 'unavailable'} — ${check.details || 'No details provided.'}`);
      }
      target.append(list);
    }
    if (result.analyzedAt) {
      const timestamp = new Date(result.analyzedAt);
      if (!Number.isNaN(timestamp.valueOf())) {
        const time = document.createElement('time');
        time.className = 'result-copy';
        time.dateTime = timestamp.toISOString();
        time.textContent = `Analyzed ${timestamp.toLocaleString()}`;
        target.append(time);
      }
    }
  }

  function renderUrlResponse(target, response) {
    if (response && response.verdict === 'invalid') {
      renderAnalysis(target, response);
      return true;
    }
    if (!response || response.ok !== true || !response.result) {
      renderMessage(target, response && response.error
        ? response.error
        : 'The server returned an invalid analysis response.', 'unverified');
      return false;
    }
    renderAnalysis(target, response.result);
    return true;
  }

  root.CyberShieldResults = { renderAnalysis, renderMessage, renderUrlResponse };
})(window);

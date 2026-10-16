'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const test = require('node:test');

class Element {
  constructor(tagName) {
    this.tagName = tagName;
    this.children = [];
    this.className = '';
    this.textContent = '';
    this.classList = { add: () => {} };
  }

  append(...elements) {
    this.children.push(...elements);
  }

  setAttribute() {}

  replaceChildren(...elements) {
    this.children = [...elements];
    this.textContent = '';
  }
}

function loadResultsRenderer() {
  const document = { createElement: (tagName) => new Element(tagName) };
  const window = {};
  const source = fs.readFileSync(path.join(__dirname, '..', 'public', 'results.js'), 'utf8');
  vm.runInNewContext(source, { document, window, Date, Number, String });
  return { renderer: window.CyberShieldResults, document };
}

function allText(element) {
  return [element.textContent, ...element.children.map(allText)].filter(Boolean).join(' ');
}

test('frontend renders a successful analysis, score, reasons, advice, and providers as text', () => {
  const { renderer, document } = loadResultsRenderer();
  const target = document.createElement('div');
  const rendered = renderer.renderUrlResponse(target, {
    ok: true,
    result: {
      verdict: 'malicious',
      riskScore: 100,
      confidence: 'high',
      recommendation: 'Do not open this URL.',
      reasons: ['Google Safe Browsing reported a match.'],
      checks: [{
        provider: 'Google Safe Browsing',
        status: 'malicious',
        details: '<img src=x onerror=alert(1)>'
      }],
      analyzedAt: '2026-10-16T00:00:00.000Z'
    }
  });

  test('frontend prominently warns on malicious URLs but keeps suspicious and unknown distinct', () => {
    const { renderer, document } = loadResultsRenderer();
    const target = document.createElement('div');
    renderer.renderUrlResponse(target, {
      ok: true,
      result: {
        verdict: 'malicious',
        blocked: true,
        riskScore: 100,
        reasons: ['Confirmed phishing report.']
      }
    });
    assert.match(allText(target), /BLOCKED IN CYBERSHIELD AI/);
    assert.match(allText(target), /will not open, preview, or follow/);
    assert.match(allText(target), /Confirmed phishing report/);

    renderer.renderUrlResponse(target, { ok: true, result: { verdict: 'suspicious', riskScore: 35 } });
    assert.match(allText(target), /SUSPICIOUS/);
    assert.doesNotMatch(allText(target), /BLOCKED IN CYBERSHIELD AI/);
    renderer.renderUrlResponse(target, { ok: true, result: { verdict: 'unknown', riskScore: 0 } });
    assert.match(allText(target), /UNKNOWN/);
    assert.doesNotMatch(allText(target), /BLOCKED IN CYBERSHIELD AI/);
  });
  const text = allText(target);
  assert.equal(rendered, true);
  assert.match(text, /MALICIOUS/);
  assert.match(text, /100\/100/);
  assert.match(text, /Do not open this URL/);
  assert.match(text, /Google Safe Browsing/);
  assert.match(text, /<img src=x onerror=alert\(1\)>/);
  assert.equal(target.children.some((child) => child.tagName === 'img'), false);
});

test('frontend displays API errors and malformed success responses without fake verdicts', () => {
  const { renderer, document } = loadResultsRenderer();
  const target = document.createElement('div');
  assert.equal(renderer.renderUrlResponse(target, { ok: false, error: 'Input URL is invalid.' }), false);
  assert.match(allText(target), /Input URL is invalid/);
  assert.equal(allText(target).includes('SAFE'), false);
  assert.equal(renderer.renderUrlResponse(target, { ok: true }), false);
  assert.match(allText(target), /invalid analysis response/);
});

test('frontend explains scheme assumptions, domain details, and checks that were not performed', () => {
  const { renderer, document } = loadResultsRenderer();
  const target = document.createElement('div');
  renderer.renderUrlResponse(target, {
    ok: true,
    result: {
      submittedUrl: 'example.co.uk',
      normalizedUrl: 'https://example.co.uk/',
      hostname: 'example.co.uk',
      registeredDomain: 'example.co.uk',
      verdict: 'unknown',
      riskScore: 0,
      confidence: 'low',
      checks: [
        { provider: 'DNS resolution', status: 'not_checked', details: 'Not checked.' },
        { provider: 'Google Safe Browsing', status: 'not_configured', details: 'Not configured.' }
      ]
    }
  });
  const text = allText(target);
  assert.match(text, /Submitted: example\.co\.uk/);
  assert.match(text, /Normalized: https:\/\/example\.co\.uk\//);
  assert.match(text, /Registered domain: example\.co\.uk/);
  assert.match(text, /DNS resolution: not_checked/);
  assert.match(text, /Google Safe Browsing: not_configured/);
});

test('frontend renders invalid input distinctly and does not invent a risk score', () => {
  const { renderer, document } = loadResultsRenderer();
  const target = document.createElement('div');
  assert.equal(renderer.renderUrlResponse(target, {
    ok: false,
    verdict: 'invalid',
    submittedUrl: 'javascript:alert(1)',
    riskScore: null,
    reasons: ['Only HTTP and HTTPS URLs are supported.'],
    recommendation: 'Correct the URL.'
  }), true);
  const text = allText(target);
  assert.match(text, /INVALID/);
  assert.match(text, /no risk score for invalid input/);
  assert.match(text, /Only HTTP and HTTPS/);
  assert.doesNotMatch(text, /RISK 0\/100/);
});

# CyberShield AI

Local-first URL and message-link analysis with a responsive browser dashboard. The app keeps the existing Express architecture and does not open submitted websites, follow redirects, or monitor other apps.

## Requirements and setup

- Node.js 18.17 or newer
- npm
- `ipaddr.js` classifies public versus special-use IP address ranges, and `tldts` extracts registered-domain details using the public suffix list.

On Windows, if `node` and `npm` are not recognized, install the current Node.js LTS release from an elevated or authorized PowerShell terminal:

```powershell
winget install --id OpenJS.NodeJS.LTS --exact
```

Close and reopen the VS Code terminal, then verify `node --version` and `npm --version`. If `winget` is unavailable, install the LTS release from [nodejs.org](https://nodejs.org/) and reopen VS Code so its PATH updates.

```powershell
npm.cmd install
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
npm.cmd start
```

If port `3000` is already occupied, the server reports the conflict and does not stop the other process. Identify its owner before stopping anything:

```powershell
Get-NetTCPConnection -LocalPort 3000 -State Listen |
  Select-Object LocalAddress, LocalPort, OwningProcess
Get-Process -Id <PID>
```

Stop it only if you confirm it is an old CyberShield AI process (`Stop-Process -Id <PID>`). Otherwise, use another port in the current terminal:

```powershell
$env:PORT = "3001"
npm.cmd run dev
```

### Replit

The `.replit` configuration starts the existing Express server with `npm start`, binds it to `0.0.0.0`, and maps its internal port `3000` to the web port `80`. The frontend and API are served by the same process, so browser requests such as `POST /api/scan/url` use the current app's origin and need no proxy or second backend. Before running or publishing on Replit, add an `API_TOKEN` secret containing at least 32 random bytes (64 hexadecimal characters). The server requires this secret when exposed on a non-loopback interface, and the dashboard will prompt for its value before protected API requests. Add provider keys as Replit Secrets only if you want optional external checks; without them, local heuristic checks continue to work.

Before starting, set `API_TOKEN` in `.env` if you want the dashboard/API key prompt enabled on loopback. For development, `npm.cmd run dev` restarts the local server when files change. Run tests with `npm.cmd test`.

By default the server binds only to loopback (`127.0.0.1`). To allow access from another device, set `HOST` to the server's private network IP and configure a long random `API_TOKEN`; the server refuses non-loopback binding without a token. The dashboard prompts for that token and keeps it in tab-scoped session storage. Because the built-in server uses HTTP, only use this option on a trusted private network behind TLS when traffic may cross an untrusted network. Do not expose the server directly to the public internet.

## Environment variables

Copy `.env.example` to `.env`. It contains placeholders only.

| Variable | Required | Purpose |
| --- | --- | --- |
| `PORT` | No | Local HTTP port; defaults to `3000`. |
| `HOST` | No | Bind address; defaults to `127.0.0.1`. Non-loopback requires `API_TOKEN`. |
| `API_TOKEN` | No | Protects scan/history/protection APIs; keep it secret. |
| `GOOGLE_SAFE_BROWSING_ENABLED` | No | Set to `true` to explicitly enable Google Safe Browsing; requires its API key. |
| `GOOGLE_SAFE_BROWSING_API_KEY` | No | Server-side Google Safe Browsing API key. |
| `VIRUSTOTAL_API_KEY` | No | Server-side VirusTotal API key; the public API has strict rate limits. |
| `URLHAUS_AUTH_KEY` | No | URLhaus Auth-Key; community API use is subject to fair-use terms. |
| `PHISHTANK_ENABLED` | No | Set to `true` to enable the optional PhishTank provider. |
| `PHISHTANK_APP_KEY` | No | Optional PhishTank app key; can increase request limits. |
| `DATA_DIR` | No | Local JSON storage path; defaults to `./data`. |

### Optional threat-intelligence providers

Providers run only when configured **and** the user checks the per-scan external-sharing consent box. Without consent, only local heuristics and confirmed local cache entries are checked.

- **Google Safe Browsing Lookup API** checks malware, unwanted-software, and social-engineering lists using `threatMatches:find`. Set both `GOOGLE_SAFE_BROWSING_ENABLED=true` and `GOOGLE_SAFE_BROWSING_API_KEY`. Follow Google's [key and API activation guide](https://developers.google.com/safe-browsing/v4/get-started), then review its [terms](https://developers.google.com/safe-browsing/v4/terms) and [usage limits](https://developers.google.com/safe-browsing/v4/usage-limits) before enabling. The Safe Browsing API is for non-commercial use; commercial services should use [Google Web Risk](https://cloud.google.com/web-risk/docs/lookup-api) and its applicable terms. See the [Safe Browsing Lookup API](https://developers.google.com/safe-browsing/v4/lookup-api).
- **VirusTotal** first requests an existing URL report. If none exists, it submits the URL and requests the returned analysis report. An analysis still processing is shown as pending, not clean. Its public API is rate-limited. VirusTotal states that IoCs submitted **or queried** via the API may be added to its dataset and made available to the community. Do not share confidential URLs or URLs containing private identifiers. Get an API key from [VirusTotal](https://www.virustotal.com/gui/my-apikey). See [Scan URL](https://docs.virustotal.com/reference/scan-url), [URL reports](https://docs.virustotal.com/reference/url-info), and [URL identifiers](https://docs.virustotal.com/reference/url).
- **URLhaus** checks its documented `POST /v1/url/` malware-URL lookup using `Auth-Key`. A match is reported as a URLhaus malware-distribution record; `no_results` means only that URLhaus returned no matching entry, not that the site is safe. Its community API is free under fair-use principles; companies and commercial/for-profit use may need its paid service. Create an Auth-Key at the [abuse.ch Authentication Portal](https://auth.abuse.ch/); see the [URLhaus API documentation](https://urlhaus.abuse.ch/api/) and [fair-use terms](https://abuse.ch/terms-of-use/).
- **PhishTank** remains available as an optional phishing lookup. Set `PHISHTANK_ENABLED=true` and optionally configure `PHISHTANK_APP_KEY`; its report is treated as malicious only when it says the URL is in the database, verified, and valid. Register at [PhishTank API registration](https://phishtank.org/api_register.php).

Put keys only in the ignored `.env` file or deployment secrets. `.env.example` contains placeholders, never credentials. The browser does not receive provider keys. Consent is one scan at a time and is cleared after submitting. Provider timeouts, rejected credentials, quotas, and unavailable services are reported as unavailable, never as clean. Provider terms, quotas, and retention policies can change; review current terms before enabling a service.

The local `API_TOKEN` is not a threat-intelligence API key. It protects your own backend. Without it, protected API routes are unauthenticated; the server prints a warning and stays bound to loopback by default. Set it in `.env` to enable the dashboard key prompt. In PowerShell, generate one without Node.js using:

```powershell
$b = New-Object byte[] 32
$r = [Security.Cryptography.RandomNumberGenerator]::Create()
$r.GetBytes($b)
[BitConverter]::ToString($b).Replace('-', '').ToLower()
```

Message analysis never calls a provider, and message text is not persisted. Do not paste passwords, one-time codes, or unrelated private information into the analyzer.

## Dashboard and analysis behavior

- URL input accepts a host-only value such as `example.com` and assumes HTTPS; explicit `http://` and `https://` values are also accepted. The result shows the submitted and normalized URL so the assumed scheme is visible. Malformed hostnames and unsupported schemes are rejected.
- URL analysis detects indicators such as public IP-address hosts, brand lookalikes, URL encoding/length, deep subdomains, redirect-style parameters, non-default ports, and known shorteners. These are heuristic signals, not proof of maliciousness.
- Private, loopback, link-local, carrier-grade NAT, multicast, reserved/documentation IP ranges, IPv4-mapped private IPv6 addresses, localhost-style names, and single-label hostnames are rejected before analysis. This is input validation, not target fetching; the scanner never performs DNS lookup or connects to the supplied host.
- Results include the parsed hostname, registered domain, and subdomain when recognized by the current public suffix data. Registered-domain details can be unavailable for IP addresses or unrecognized suffixes. DNS, reachability, TLS, and redirects are explicitly reported as `not_checked`.
- The service does not fetch submitted URLs, follow redirects, resolve user-supplied domains, inspect certificates, or reach local/private network hosts. Certificate details are explicitly reported as unchecked.
- A successful URL result contains `submittedUrl`, normalized `url`/`normalizedUrl`, `hostname`, `registeredDomain`, `subdomain`, `verdict` (`safe`, `suspicious`, `malicious`, or `unknown`), `riskScore` (0–100), `confidence`, provider/local `checks`, `providers`, `reasons`, `recommendation`, and `analyzedAt`/`scannedAt`. Invalid input returns HTTP 400 with `verdict: "invalid"`, a reason, and no numeric risk score. `riskScore` is an understandable rule-based indicator, **not** a probability or validated prediction.
- Local heuristic points are added per detected pattern (for example: public IP host 30, lookalike brand 30, encoded control characters 20, unusual port 15); the score is capped at 100. A threat-list hit yields 100 and `malicious`; provider suspicion yields at least 65. The absence of local warnings alone always yields `unknown`. A `safe` verdict is possible only if every configured external provider was consented to and returned clean, with no local warnings; even then it is not a guarantee of safety.
- `clean` means only that a provider returned no match in its limited database/list. `pending`, `unavailable`, `not_checked`, and `not_configured` are distinct from `clean`. Conflicting results are included in the reasons, and a reported threat is not overridden by another provider's clean response.
- HTTPS and known-domain hints do not establish that a link is safe. An `unknown` local-only result means there is insufficient reputation evidence, not that the URL is safe.
- A consented, provider-confirmed threat match is cached locally as a confirmed threat indicator for 24 hours. Expired or undated legacy entries are ignored. The offline component can match those locally cached indicators; it cannot discover every new or changed threat.
- A malicious URL result is also added to a persistent, application-only blocklist. It is stored as a SHA-256 identifier of the normalized URL plus its hostname, detection source, and timestamp; the submitted URL path and query are not stored in the blocklist. Future exact-URL scans are marked malicious and providers are skipped while the entry remains blocked. Remove entries from the dashboard or with `DELETE /api/blocked-links/{id}`. A later confirmed malicious result can add a removed URL again.
- “Blocked” applies only inside this application. The dashboard does not provide an open, preview, or follow action for submitted links, and it does not block the browser, device, network, or other applications. Suspicious and inconclusive results are not added to the blocklist.
- The local threat cache is stored in `data/threats.json`. Provider-confirmed URLs are stored as SHA-256 indicators rather than plaintext URLs, and can be cleared using the legacy `POST /api/clear-blocks` route.
- The scan history stores the host, timestamp, classification, severity, and brief evidence; it does not retain full URL paths or query strings. Use the dashboard's **Delete history** control or `DELETE /api/scan/history`.
- Message scanning is in-memory only and does not create history.
- This is an on-demand scanner, not real-time interception. No extension or device-level protection is included. A normal website cannot intercept links in WhatsApp, Gmail, or other apps.

## Machine-learning status

There is no existing model or reliable labeled dataset in this project. No model has been trained, and the app does **not** claim ML accuracy, scores, or model predictions. The API exposes `machineLearning.available: false`; URL results identify the heuristic analysis source. This avoids presenting hand-authored rules or invented labels as a trained model. A validated baseline and precision/recall/F1/confusion-matrix evaluation require an appropriately licensed, representative labeled dataset and a separate model service.

## Android companion app

The native Android project is separate from the web app in [`android/`](./android/). It registers as a Sharesheet target for plain-text shares. In WhatsApp or another app, choose **Share → CyberShield AI**; if several HTTP(S) links are present, select one, review it, and tap **Scan link**. No message history, sender identity, contacts, or other app content is collected. The app cannot scan messages automatically or block a sender in WhatsApp.

The companion posts `{ "url": "...", "consentToExternalScan": false }` to the existing `POST /api/scan/url` endpoint. It reads the current `{ "ok": true, "result": { ... } }` response and sends `X-API-Key` only when a token is configured. Provider consent is unchecked by default and consumed for one scan only. Provider API keys remain on the backend.

The server base URL is configured in the app's **Server settings**. Production endpoints must use HTTPS. For local Android Emulator development, the default `http://10.0.2.2:3000` reaches the host computer; cleartext is permitted only for that emulator address and localhost. A physical phone should use a reachable HTTPS backend. If `API_TOKEN` is enabled on the server, enter that token in the app; it is encrypted with AES-GCM using Android Keystore and is not included in app source or backups.

To build and run, open the `android/` folder in Android Studio with JDK 17 and Android SDK Platform 35 installed, allow Gradle sync, then run the `app` configuration on an emulator or device. The project uses Android Gradle Plugin 8.7.3, Gradle 8.9, Kotlin 2.0.21, minimum Android API 26, and target API 35. Run unit tests from Android Studio's Gradle tool window with `:app:testDebugUnitTest`. This workspace currently has no Java/JDK, Gradle, Android Studio, or Android SDK installed, so an APK build and Android JVM test execution could not be verified here.

Scanning never opens, previews, follows redirects from, or fetches the submitted target. After a completed assessment, opening a non-malicious link requires a separate user tap. Malicious and already-blocklisted results have no open action; suspicious and unknown results remain distinct and require the explicit “Open anyway” action. A failed, malformed, or unavailable scan provides no open action. “Safe” means only that configured checks did not report a threat; it is not a safety guarantee.

## API

All API responses are JSON. API routes are same-origin and rate-limited to 60 requests per 15 minutes per client. When `API_TOKEN` is configured, send it as `X-API-Key` (except health and auth bootstrap endpoints). Request bodies are limited to 16 KB. No CORS access is enabled.

### `GET /api/auth/status` and `POST /api/auth/session`

The status endpoint tells the dashboard whether an API key is configured. The session endpoint accepts `{ "apiKey": "..." }` and validates it; it does not issue a cookie. Send the validated key as `X-API-Key` on protected API requests. The dashboard keeps it in tab-scoped session storage.

### `GET /api/health`

Health status and ML availability; does not require an API key.

### `POST /api/scan/url`

```json
{
  "url": "https://example.org/path",
  "consentToExternalScan": false
}
```

Returns the structured result described above. Inputs may be a hostname (implicitly treated as HTTPS) or a full HTTP(S) URL, contain no embedded credentials, and target a public hostname. Submitted hosts are never contacted. For example:

```json
{
  "url": "https://example.org/path",
  "verdict": "unknown",
  "riskScore": 0,
  "confidence": "low",
  "checks": [
    {
      "provider": "Local heuristics",
      "status": "clean",
      "details": "No warning patterns were detected by the limited local checks; this is not proof of safety."
    },
    {
      "provider": "Google Safe Browsing",
      "status": "not_configured",
      "details": "This provider is not configured on the server."
    }
  ],
  "reasons": ["Only limited local heuristics ran; no configured reputation provider returned a result."],
  "recommendation": "Treat this URL as unverified.",
  "analyzedAt": "2026-10-16T00:00:00.000Z"
}
```

### `POST /api/scan/message`

```json
{ "message": "Please check https://example.org" }
```

Extracts and inspects up to 20 HTTP(S) URLs using local heuristics and the local threat cache. It does not retain the text or contact a provider.

### `GET /api/scan/history` and `DELETE /api/scan/history`

Retrieve the latest 100 URL scan summaries or delete all saved history.

### `GET /api/protection/status`

Reports local/offline capability, provider configuration, cached confirmed threat count, and ML status. Offline checks only cover indicators already cached on this server.

### `GET /api/blocked-links` and `DELETE /api/blocked-links/{id}`

List the app's persistent malicious-URL block records or remove one by its 64-character SHA-256 identifier. Records contain the identifier, hostname, detection source, and timestamp, not the full submitted URL. A removed link may be added again if a later scan still confirms it as malicious.

### `POST /api/protection/sync`

Returns HTTP `503` because there is no remote threat-feed synchronization source configured. Provider-confirmed matches from consented URL scans are cached locally immediately; the endpoint does not pretend that an unavailable feed was synchronized.

### Compatibility routes

- `POST /api/check-link` delegates to the URL scanner; an unrecognized domain is no longer automatically blocked.
- `GET /api/allowlist` returns familiar-domain hints, which never override threat findings or certify a site as safe.
- `POST /api/clear-blocks` clears both local confirmed threat indicators and the application-only blocklist.

## Verification

`npm.cmd test` covers URL validation and heuristics, provider verdicts/timeouts/errors/conflicts, provider consent and privacy, message analysis, API-key enforcement, rate limiting, history deletion, and frontend result rendering. Provider APIs are mocked; tests use reserved `.test` domains and do not open target URLs or call live threat feeds.

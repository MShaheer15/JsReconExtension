/**
 * popup.js — UI Orchestration Logic
 * 
 * Controls the popup interface, triggers scans on the active tab,
 * communicates with background.js, and renders results.
 * 
 * For authorized security testing only.
 */

/* ═══════════════════════════════════════════════════════
   DOM REFERENCES
   ═══════════════════════════════════════════════════════ */

const DOM = {
  btnScan: document.getElementById('btnScan'),
  btnCopyAll: document.getElementById('btnCopyAll'),
  btnExport: document.getElementById('btnExport'),
  targetUrl: document.getElementById('targetUrl'),
  statusText: document.getElementById('statusText'),
  progressContainer: document.getElementById('progressContainer'),
  progressBar: document.getElementById('progressBar'),
  tabFiles: document.getElementById('tabFiles'),
  tabSecrets: document.getElementById('tabSecrets'),
  tabEndpoints: document.getElementById('tabEndpoints'),
  panelFiles: document.getElementById('panelFiles'),
  panelSecrets: document.getElementById('panelSecrets'),
  panelEndpoints: document.getElementById('panelEndpoints'),
  listFiles: document.getElementById('listFiles'),
  listSecrets: document.getElementById('listSecrets'),
  listEndpoints: document.getElementById('listEndpoints'),
  emptyFiles: document.getElementById('emptyFiles'),
  emptySecrets: document.getElementById('emptySecrets'),
  emptyEndpoints: document.getElementById('emptyEndpoints'),
  countFiles: document.getElementById('countFiles'),
  countSecrets: document.getElementById('countSecrets'),
  countEndpoints: document.getElementById('countEndpoints'),
  statTotal: document.getElementById('statTotal'),
  statScanned: document.getElementById('statScanned'),
  statSecrets: document.getElementById('statSecrets'),
  statEndpoints: document.getElementById('statEndpoints'),
  footer: document.getElementById('footer'),
  toast: document.getElementById('toast'),
};

/* ═══════════════════════════════════════════════════════
   STATE
   ═══════════════════════════════════════════════════════ */

let scanResults = null;
let isScanning = false;

/* ═══════════════════════════════════════════════════════
   INITIALIZATION
   ═══════════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {
  initTargetUrl();
  initTabs();
  initActions();
});

/**
 * Display the current active tab URL in the header.
 */
function initTargetUrl() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs[0]) {
      const url = new URL(tabs[0].url);
      DOM.targetUrl.textContent = url.hostname + url.pathname;
      DOM.targetUrl.title = tabs[0].url;
    }
  });
}

/* ═══════════════════════════════════════════════════════
   TAB NAVIGATION
   ═══════════════════════════════════════════════════════ */

function initTabs() {
  const tabs = document.querySelectorAll('.tab');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      // Remove active state from all tabs/panels
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.results-panel').forEach(p => p.classList.remove('active'));

      // Activate clicked tab
      tab.classList.add('active');
      const panelId = 'panel' + capitalize(tab.dataset.tab);
      document.getElementById(panelId).classList.add('active');
    });
  });
}

function capitalize(str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

/* ═══════════════════════════════════════════════════════
   ACTION HANDLERS
   ═══════════════════════════════════════════════════════ */

function initActions() {
  DOM.btnScan.addEventListener('click', startScan);
  DOM.btnCopyAll.addEventListener('click', copyAllResults);
  DOM.btnExport.addEventListener('click', exportJSON);
}

/* ═══════════════════════════════════════════════════════
   SCAN FLOW
   ═══════════════════════════════════════════════════════ */

async function startScan() {
  if (isScanning) return;
  isScanning = true;

  // Update UI state
  DOM.btnScan.disabled = true;
  DOM.btnScan.innerHTML = `
    <svg class="spinner" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
      <circle cx="12" cy="12" r="10" stroke-dasharray="60" stroke-dashoffset="20"/>
    </svg>
    Scanning...
  `;
  setStatus('Extracting JavaScript files from DOM...', true);
  clearResults();

  try {
    // Step 1: Get the active tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (!tab || !tab.id) {
      throw new Error('No active tab found.');
    }

    // Verify it's a valid scannable page
    if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://') || tab.url.startsWith('about:')) {
      throw new Error('Cannot scan browser internal pages.');
    }

    // Step 2: Inject script into the active tab to extract JS URLs
    setStatus('Injecting extraction script...', true);
    const injectionResults = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: extractJSFromDOM,
    });

    if (!injectionResults || !injectionResults[0] || !injectionResults[0].result) {
      throw new Error('Failed to extract JavaScript files from the page.');
    }

    const jsFiles = injectionResults[0].result;

    if (jsFiles.length === 0) {
      setStatus('No JavaScript files found on this page.', false);
      resetScanButton();
      return;
    }

    setStatus(`Found ${jsFiles.length} JS files. Fetching and analyzing...`, true);
    setProgress(20);

    // Step 3: Send JS URLs to background script for fetching and analysis
    const response = await sendMessage({
      action: 'SCAN_JS_FILES',
      jsFiles: jsFiles,
    });

    if (!response || !response.success) {
      throw new Error(response?.error || 'Background scan failed.');
    }

    scanResults = response.results;

    // Step 4: Render results
    setProgress(90);
    setStatus('Rendering results...', true);
    renderResults(scanResults);

    // Final status
    const { stats } = scanResults;
    setStatus(
      `Scan complete — ${stats.scannedSuccessfully}/${stats.totalFiles} files scanned, ` +
      `${stats.secretsFound} secrets, ${stats.endpointsFound} endpoints found.`,
      false
    );
    setProgress(100);

    // Enable action buttons
    DOM.btnCopyAll.disabled = false;
    DOM.btnExport.disabled = false;

  } catch (err) {
    setStatus(`Error: ${err.message}`, false);
    console.error('[JSRecon] Scan error:', err);
  } finally {
    resetScanButton();
    isScanning = false;
  }
}

/**
 * This function is injected into the active tab's DOM.
 * It extracts all <script src="..."> URLs from the page.
 * It runs inside the page context, not the extension context.
 */
function extractJSFromDOM() {
  const scripts = document.querySelectorAll('script[src]');
  const pageOrigin = window.location.origin;
  const seen = new Set();
  const results = [];

  scripts.forEach(script => {
    try {
      const src = script.src;
      if (!src || seen.has(src)) return;
      seen.add(src);

      // Determine if first-party or third-party
      let type = 'third-party';
      try {
        const scriptUrl = new URL(src);
        if (scriptUrl.origin === pageOrigin) {
          type = 'first-party';
        }
      } catch (e) {
        // If URL parsing fails, treat as third-party
      }

      results.push({ url: src, type: type });
    } catch (e) {
      // Skip problematic scripts
    }
  });

  return results;
}

/* ═══════════════════════════════════════════════════════
   MESSAGE HELPER
   ═══════════════════════════════════════════════════════ */

function sendMessage(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve(response);
      }
    });
  });
}

/* ═══════════════════════════════════════════════════════
   RENDERING
   ═══════════════════════════════════════════════════════ */

function renderResults(results) {
  renderFiles(results.scannedFiles);
  renderSecrets(results.secrets);
  renderEndpoints(results.endpoints);
  renderStats(results.stats);
}

/**
 * Render JS file list.
 */
function renderFiles(files) {
  DOM.listFiles.innerHTML = '';
  DOM.countFiles.textContent = files.length;

  if (files.length === 0) {
    DOM.emptyFiles.style.display = 'flex';
    return;
  }
  DOM.emptyFiles.style.display = 'none';

  files.forEach(file => {
    const item = document.createElement('div');
    item.className = 'result-item file-item';

    const statusClass = file.scanStatus === 'scanned' ? 'status-success' : 'status-error';
    const statusIcon = file.scanStatus === 'scanned' ? '✓' : '✗';
    const sizeStr = file.size ? formatBytes(file.size) : '—';
    const typeClass = file.type === 'first-party' ? 'tag-first-party' : 'tag-third-party';

    item.innerHTML = `
      <div class="result-header">
        <span class="status-badge ${statusClass}">${statusIcon}</span>
        <span class="file-url" title="${escapeHtml(file.url)}">${escapeHtml(truncateUrl(file.url))}</span>
        <button class="btn-icon btn-copy-url" title="Copy URL" data-url="${escapeHtml(file.url)}">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="12" height="12">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
            <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
          </svg>
        </button>
      </div>
      <div class="result-meta">
        <span class="tag ${typeClass}">${file.type}</span>
        <span class="meta-detail">${sizeStr}</span>
        ${file.scanStatus === 'scanned' ? `<span class="meta-detail">${file.secretsCount || 0} secrets · ${file.endpointsCount || 0} endpoints</span>` : ''}
        ${file.error ? `<span class="meta-error">${escapeHtml(file.error)}</span>` : ''}
      </div>
    `;

    // Copy button handler
    const copyBtn = item.querySelector('.btn-copy-url');
    copyBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      copyToClipboard(file.url);
    });

    DOM.listFiles.appendChild(item);
  });
}

/**
 * Render secrets list.
 */
function renderSecrets(secrets) {
  DOM.listSecrets.innerHTML = '';
  DOM.countSecrets.textContent = secrets.length;

  if (secrets.length === 0) {
    DOM.emptySecrets.style.display = 'flex';
    return;
  }
  DOM.emptySecrets.style.display = 'none';

  secrets.forEach(finding => {
    const item = document.createElement('div');
    item.className = 'result-item finding-item';

    const severityClass = `severity-${finding.severity.toLowerCase()}`;
    const confidenceClass = getConfidenceClass(finding.confidence);

    item.innerHTML = `
      <div class="result-header">
        <span class="severity-badge ${severityClass}">${finding.severity}</span>
        <span class="finding-type">${escapeHtml(finding.label)}</span>
        <span class="confidence-badge ${confidenceClass}">${finding.confidence}%</span>
      </div>
      <div class="finding-match">
        <code>${escapeHtml(finding.match)}</code>
      </div>
      <div class="result-meta">
        <span class="meta-file" title="${escapeHtml(finding.file)}">${escapeHtml(extractFilename(finding.file))}</span>
      </div>
    `;

    DOM.listSecrets.appendChild(item);
  });
}

/**
 * Render endpoints list.
 */
function renderEndpoints(endpoints) {
  DOM.listEndpoints.innerHTML = '';
  DOM.countEndpoints.textContent = endpoints.length;

  if (endpoints.length === 0) {
    DOM.emptyEndpoints.style.display = 'flex';
    return;
  }
  DOM.emptyEndpoints.style.display = 'none';

  endpoints.forEach(finding => {
    const item = document.createElement('div');
    item.className = 'result-item endpoint-item';

    const confidenceClass = getConfidenceClass(finding.confidence);

    item.innerHTML = `
      <div class="result-header">
        <span class="endpoint-type-badge">${escapeHtml(finding.label)}</span>
        <span class="confidence-badge ${confidenceClass}">${finding.confidence}%</span>
        <button class="btn-icon btn-copy-url" title="Copy endpoint" data-url="${escapeHtml(finding.match)}">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="12" height="12">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
            <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
          </svg>
        </button>
      </div>
      <div class="finding-match endpoint-url">
        <code>${escapeHtml(finding.match)}</code>
      </div>
      <div class="result-meta">
        <span class="tag severity-${finding.severity.toLowerCase()}">${finding.severity}</span>
        <span class="meta-file" title="${escapeHtml(finding.file)}">${escapeHtml(extractFilename(finding.file))}</span>
      </div>
    `;

    const copyBtn = item.querySelector('.btn-copy-url');
    copyBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      copyToClipboard(finding.match);
    });

    DOM.listEndpoints.appendChild(item);
  });
}

/**
 * Render scan statistics in the footer.
 */
function renderStats(stats) {
  DOM.statTotal.textContent = stats.totalFiles;
  DOM.statScanned.textContent = stats.scannedSuccessfully;
  DOM.statSecrets.textContent = stats.secretsFound;
  DOM.statEndpoints.textContent = stats.endpointsFound;
  DOM.footer.style.display = 'block';
}

/* ═══════════════════════════════════════════════════════
   COPY & EXPORT
   ═══════════════════════════════════════════════════════ */

function copyAllResults() {
  if (!scanResults) return;

  const text = buildPlainTextReport(scanResults);
  copyToClipboard(text);
}

function exportJSON() {
  if (!scanResults) return;

  // Build export with full (unmasked) values
  const exportData = {
    meta: {
      tool: 'JSRecon',
      version: '1.0.0',
      timestamp: scanResults.stats.scanTimestamp,
      disclaimer: 'For authorized security testing only.',
    },
    stats: scanResults.stats,
    files: scanResults.scannedFiles,
    secrets: scanResults.secrets.map(s => ({
      file: s.file,
      type: s.type,
      match: s.rawMatch,
      severity: s.severity,
      confidence: s.confidence,
    })),
    endpoints: scanResults.endpoints.map(e => ({
      file: e.file,
      type: e.type,
      match: e.rawMatch,
      severity: e.severity,
      confidence: e.confidence,
      endpointType: e.endpointType,
    })),
    errors: scanResults.errors,
  };

  const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `jsrecon_report_${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
  showToast('Report exported as JSON');
}

function buildPlainTextReport(results) {
  let text = '═══ JSRecon Report ═══\n\n';
  text += `Scan Time: ${results.stats.scanTimestamp}\n`;
  text += `Total Files: ${results.stats.totalFiles}\n`;
  text += `Scanned: ${results.stats.scannedSuccessfully}\n\n`;

  text += '── JS Files ──\n';
  results.scannedFiles.forEach(f => {
    text += `[${f.scanStatus}] ${f.url}\n`;
  });

  if (results.secrets.length > 0) {
    text += '\n── Secrets ──\n';
    results.secrets.forEach(s => {
      text += `[${s.severity}] ${s.type}: ${s.match} (${s.confidence}%) — ${s.file}\n`;
    });
  }

  if (results.endpoints.length > 0) {
    text += '\n── Endpoints ──\n';
    results.endpoints.forEach(e => {
      text += `[${e.severity}] ${e.label}: ${e.match} (${e.confidence}%) — ${e.file}\n`;
    });
  }

  return text;
}

/* ═══════════════════════════════════════════════════════
   UI HELPERS
   ═══════════════════════════════════════════════════════ */

function setStatus(text, showProgress) {
  DOM.statusText.textContent = text;
  DOM.progressContainer.style.display = showProgress ? 'block' : 'none';
}

function setProgress(percent) {
  DOM.progressBar.style.width = percent + '%';
}

function clearResults() {
  DOM.listFiles.innerHTML = '';
  DOM.listSecrets.innerHTML = '';
  DOM.listEndpoints.innerHTML = '';
  DOM.emptyFiles.style.display = 'flex';
  DOM.emptySecrets.style.display = 'flex';
  DOM.emptyEndpoints.style.display = 'flex';
  DOM.countFiles.textContent = '0';
  DOM.countSecrets.textContent = '0';
  DOM.countEndpoints.textContent = '0';
  DOM.footer.style.display = 'none';
  DOM.btnCopyAll.disabled = true;
  DOM.btnExport.disabled = true;
}

function resetScanButton() {
  DOM.btnScan.disabled = false;
  DOM.btnScan.innerHTML = `
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
      <circle cx="11" cy="11" r="8"/>
      <line x1="21" y1="21" x2="16.65" y2="16.65"/>
    </svg>
    Start Scan
  `;
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => {
    showToast('Copied to clipboard');
  }).catch(() => {
    showToast('Failed to copy');
  });
}

function showToast(message) {
  DOM.toast.textContent = message;
  DOM.toast.classList.add('show');
  setTimeout(() => DOM.toast.classList.remove('show'), 2200);
}

function escapeHtml(str) {
  if (!str) return '';
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function truncateUrl(url, maxLen = 70) {
  if (url.length <= maxLen) return url;
  return url.substring(0, 35) + '...' + url.substring(url.length - 30);
}

function extractFilename(url) {
  try {
    return new URL(url).pathname.split('/').pop() || url;
  } catch {
    return url;
  }
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function getConfidenceClass(confidence) {
  if (confidence >= 75) return 'confidence-high';
  if (confidence >= 45) return 'confidence-medium';
  return 'confidence-low';
}

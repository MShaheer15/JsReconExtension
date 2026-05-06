/**
 * background.js — Fetch & Processing Engine (Service Worker)
 * 
 * Receives JS URLs from popup, fetches their contents,
 * runs secret and endpoint scanners, and returns structured results.
 * 
 * For authorized security testing only.
 */

import { scanForSecrets } from './secret_scanner.js';
import { scanForEndpoints } from './endpoint_scanner.js';

/**
 * Maximum content size to scan (5MB). Prevents memory issues with huge bundles.
 */
const MAX_CONTENT_SIZE = 5 * 1024 * 1024;

/**
 * Fetch timeout in milliseconds.
 */
const FETCH_TIMEOUT_MS = 15000;

/**
 * Fetch a JavaScript file with timeout and size limits.
 * @param {string} url - URL of the JS file to fetch
 * @returns {Promise<{url: string, content: string|null, status: string, error: string|null}>}
 */
async function fetchJSFile(url) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    const response = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
      headers: {
        'Accept': 'application/javascript, text/javascript, */*',
      },
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      return {
        url,
        content: null,
        status: 'fetch_failed',
        error: `HTTP ${response.status} ${response.statusText}`,
      };
    }

    // Check content length before reading
    const contentLength = response.headers.get('content-length');
    if (contentLength && parseInt(contentLength) > MAX_CONTENT_SIZE) {
      return {
        url,
        content: null,
        status: 'too_large',
        error: `File exceeds ${MAX_CONTENT_SIZE / 1024 / 1024}MB limit`,
      };
    }

    const content = await response.text();

    if (content.length > MAX_CONTENT_SIZE) {
      return {
        url,
        content: null,
        status: 'too_large',
        error: `Content exceeds ${MAX_CONTENT_SIZE / 1024 / 1024}MB limit`,
      };
    }

    return {
      url,
      content,
      status: 'success',
      error: null,
    };
  } catch (err) {
    let status = 'fetch_failed';
    let errorMsg = err.message || 'Unknown error';

    if (err.name === 'AbortError') {
      status = 'timeout';
      errorMsg = `Request timed out after ${FETCH_TIMEOUT_MS / 1000}s`;
    } else if (err.message && err.message.includes('Failed to fetch')) {
      status = 'cors_blocked';
      errorMsg = 'Blocked by CORS policy or network error';
    }

    return {
      url,
      content: null,
      status,
      error: errorMsg,
    };
  }
}

/**
 * Process a list of JS URLs: fetch, scan for secrets and endpoints.
 * @param {Array<{url: string, type: string}>} jsFiles 
 * @returns {Promise<object>} Aggregated scan results
 */
async function processJSFiles(jsFiles) {
  const results = {
    scannedFiles: [],
    secrets: [],
    endpoints: [],
    errors: [],
    stats: {
      totalFiles: jsFiles.length,
      scannedSuccessfully: 0,
      fetchFailed: 0,
      secretsFound: 0,
      endpointsFound: 0,
      scanTimestamp: new Date().toISOString(),
    },
  };

  // Fetch all files concurrently (with a concurrency limit)
  const CONCURRENCY_LIMIT = 6;
  const chunks = [];
  for (let i = 0; i < jsFiles.length; i += CONCURRENCY_LIMIT) {
    chunks.push(jsFiles.slice(i, i + CONCURRENCY_LIMIT));
  }

  for (const chunk of chunks) {
    const fetchPromises = chunk.map(file => fetchJSFile(file.url));
    const fetchResults = await Promise.allSettled(fetchPromises);

    for (let i = 0; i < fetchResults.length; i++) {
      const file = chunk[i];
      const fetchResult = fetchResults[i];

      if (fetchResult.status === 'rejected') {
        results.errors.push({
          url: file.url,
          status: 'fetch_failed',
          error: fetchResult.reason?.message || 'Promise rejected',
        });
        results.stats.fetchFailed++;
        results.scannedFiles.push({
          url: file.url,
          type: file.type,
          scanStatus: 'failed',
          error: fetchResult.reason?.message,
        });
        continue;
      }

      const { url, content, status, error } = fetchResult.value;

      if (status !== 'success' || !content) {
        results.errors.push({ url, status, error });
        results.stats.fetchFailed++;
        results.scannedFiles.push({
          url,
          type: file.type,
          scanStatus: status,
          error,
        });
        continue;
      }

      // Scan for secrets
      const secrets = scanForSecrets(content, url);
      results.secrets.push(...secrets);
      results.stats.secretsFound += secrets.length;

      // Scan for endpoints
      const endpoints = scanForEndpoints(content, url);
      results.endpoints.push(...endpoints);
      results.stats.endpointsFound += endpoints.length;

      results.stats.scannedSuccessfully++;
      results.scannedFiles.push({
        url,
        type: file.type,
        scanStatus: 'scanned',
        size: content.length,
        secretsCount: secrets.length,
        endpointsCount: endpoints.length,
      });
    }
  }

  return results;
}

/**
 * Message handler for communication with popup.js
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'SCAN_JS_FILES') {
    const { jsFiles } = message;

    if (!jsFiles || !Array.isArray(jsFiles) || jsFiles.length === 0) {
      sendResponse({
        success: false,
        error: 'No JavaScript files provided for scanning.',
      });
      return true;
    }

    processJSFiles(jsFiles)
      .then(results => {
        // Store results in chrome.storage.local for persistence
        chrome.storage.local.set({ lastScanResults: results }, () => {
          sendResponse({ success: true, results });
        });
      })
      .catch(err => {
        sendResponse({
          success: false,
          error: `Processing error: ${err.message}`,
        });
      });

    // Return true to indicate async response
    return true;
  }

  if (message.action === 'GET_LAST_RESULTS') {
    chrome.storage.local.get('lastScanResults', (data) => {
      sendResponse({ success: true, results: data.lastScanResults || null });
    });
    return true;
  }
});

console.log('[JSRecon] Background service worker initialized.');

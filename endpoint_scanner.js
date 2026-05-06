/**
 * endpoint_scanner.js — API Endpoint Extraction Engine
 * 
 * Analyzes raw JavaScript content for API endpoint patterns
 * (e.g., /api/, /v1/, /graphql, fetch() calls, axios requests).
 * 
 * For authorized security testing only.
 */

/**
 * Endpoint detection patterns.
 * Each entry: { id, label, regex, severity, baseConfidence }
 */
const ENDPOINT_PATTERNS = [
  {
    id: 'FETCH_URL',
    label: 'fetch() URL',
    patterns: [
      /fetch\s*\(\s*['"`]([^'"`\s]{5,})['"`]/g,
    ],
    severity: 'Medium',
    baseConfidence: 80,
  },
  {
    id: 'AXIOS_URL',
    label: 'Axios Request URL',
    patterns: [
      /axios\s*\.\s*(?:get|post|put|patch|delete|request|head|options)\s*\(\s*['"`]([^'"`\s]{5,})['"`]/g,
    ],
    severity: 'Medium',
    baseConfidence: 80,
  },
  {
    id: 'XHR_URL',
    label: 'XMLHttpRequest URL',
    patterns: [
      /\.open\s*\(\s*['"`](?:GET|POST|PUT|DELETE|PATCH)['"`]\s*,\s*['"`]([^'"`\s]{5,})['"`]/g,
    ],
    severity: 'Medium',
    baseConfidence: 75,
  },
  {
    id: 'API_PATH',
    label: 'API Path',
    patterns: [
      /['"`](\/api\/[a-zA-Z0-9\/_\-.:?&={}[\]]+)['"`]/g,
      /['"`](\/v[1-9][0-9]?\/[a-zA-Z0-9\/_\-.:?&={}[\]]+)['"`]/g,
      /['"`](\/graphql[a-zA-Z0-9\/_\-.:?&=]*)['"`]/g,
    ],
    severity: 'Low',
    baseConfidence: 65,
  },
  {
    id: 'ADMIN_PATH',
    label: 'Admin/Internal Path',
    patterns: [
      /['"`](\/(?:admin|dashboard|internal|debug|config|settings|manage|panel)[a-zA-Z0-9\/_\-.:?&=]*)['"`]/g,
    ],
    severity: 'Medium',
    baseConfidence: 60,
  },
  {
    id: 'AUTH_ENDPOINT',
    label: 'Authentication Endpoint',
    patterns: [
      /['"`](\/(?:auth|login|logout|signin|signup|register|oauth|sso|token|callback|verify)[a-zA-Z0-9\/_\-.:?&=]*)['"`]/g,
    ],
    severity: 'Medium',
    baseConfidence: 70,
  },
  {
    id: 'FULL_URL',
    label: 'Full HTTP URL',
    patterns: [
      /['"`](https?:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]{10,})['"`]/g,
    ],
    severity: 'Low',
    baseConfidence: 40,
  },
];

/**
 * Patterns that indicate a false positive endpoint.
 */
const ENDPOINT_FALSE_POSITIVES = [
  /\.(css|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|map)(\?.*)?$/i,
  /^https?:\/\/(www\.)?(google|facebook|twitter|youtube|jsdelivr|cdnjs|unpkg|cloudflare)\./i,
  /^\/\//,          // Protocol-relative URLs (usually CDN)
  /^\/#/,           // Hash-only routes
  /^\/$/,           // Root path only
  /node_modules/,
  /webpack/i,
  /sourceMappingURL/,
  /localhost/,
  /127\.0\.0\.1/,
  /example\.com/,
];

/**
 * Check if an endpoint match is a false positive.
 * @param {string} match 
 * @returns {boolean}
 */
function isEndpointFalsePositive(match) {
  if (!match || match.length < 3) return true;
  for (const fp of ENDPOINT_FALSE_POSITIVES) {
    if (fp.test(match)) return true;
  }
  return false;
}

/**
 * Calculate confidence for an endpoint finding.
 * @param {object} rule 
 * @param {string} match 
 * @param {string} context 
 * @returns {number}
 */
function calculateEndpointConfidence(rule, match, context) {
  let score = rule.baseConfidence;

  // Boost for explicit API-like paths
  if (/\/api\//i.test(match)) score += 10;
  if (/\/v[1-9]/i.test(match)) score += 5;
  if (/\/graphql/i.test(match)) score += 10;

  // Boost for auth-related context
  const contextLower = (context || '').toLowerCase();
  if (/auth|token|login|bearer/i.test(contextLower)) score += 5;

  // Penalize very generic paths
  if (match.length < 5) score -= 15;

  // Penalize full URLs that are just asset URLs
  if (rule.id === 'FULL_URL' && !/\/api\/|\/v[1-9]\/|\/graphql|\/auth|\/admin/i.test(match)) {
    score -= 20;
  }

  return Math.max(0, Math.min(100, score));
}

/**
 * Extract surrounding context.
 * @param {string} content 
 * @param {number} index 
 * @param {number} radius 
 * @returns {string}
 */
function getEndpointContext(content, index, radius = 80) {
  const start = Math.max(0, index - radius);
  const end = Math.min(content.length, index + radius);
  return content.substring(start, end);
}

/**
 * Scan JavaScript content for API endpoints.
 * @param {string} content - Raw JavaScript file content
 * @param {string} fileUrl - Source file URL for reporting
 * @returns {Array<object>} Array of endpoint findings
 */
function scanForEndpoints(content, fileUrl) {
  if (!content || typeof content !== 'string') return [];

  const findings = [];
  const seenMatches = new Set();

  for (const rule of ENDPOINT_PATTERNS) {
    for (const pattern of rule.patterns) {
      pattern.lastIndex = 0;
      let regexMatch;

      while ((regexMatch = pattern.exec(content)) !== null) {
        const matchedValue = regexMatch[1] || regexMatch[0];

        // Deduplicate
        const dedupKey = `${rule.id}:${matchedValue}`;
        if (seenMatches.has(dedupKey)) continue;
        seenMatches.add(dedupKey);

        // Filter false positives
        if (isEndpointFalsePositive(matchedValue)) continue;

        // Get context and calculate confidence
        const context = getEndpointContext(content, regexMatch.index);
        const confidence = calculateEndpointConfidence(rule, matchedValue, context);

        // Skip very low confidence
        if (confidence < 25) continue;

        findings.push({
          file: fileUrl,
          type: 'ENDPOINT',
          label: rule.label,
          match: matchedValue,
          rawMatch: matchedValue,
          severity: rule.severity,
          confidence: confidence,
          source: fileUrl,
          endpointType: rule.id,
        });
      }
    }
  }

  // Sort by confidence descending
  findings.sort((a, b) => b.confidence - a.confidence);
  return findings;
}

export { scanForEndpoints };

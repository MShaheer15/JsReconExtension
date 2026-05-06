/**
 * secret_scanner.js — Sensitive Information Detection Engine
 * 
 * Analyzes raw JavaScript content for sensitive information exposure
 * using regex patterns and heuristic-based confidence scoring.
 * 
 * Detects: API Keys, JWT Tokens, Emails, Passwords, High-Entropy Secrets.
 * 
 * For authorized security testing only.
 */

/**
 * Detection rule definitions.
 * Each rule has: id, label, regex, severity, baseConfidence, and a context
 * boost function that can raise confidence based on surrounding code.
 */
const DETECTION_RULES = [
  {
    id: 'API_KEY',
    label: 'API Key',
    patterns: [
      // Explicit key assignments: api_key = "...", apiKey: "...", etc.
      /(?:api[_-]?key|api[_-]?secret|access[_-]?key|secret[_-]?key)\s*[:=]\s*['"`]([A-Za-z0-9_\-]{16,64})['"`]/gi,
      // Common cloud provider key patterns
      /(?:AKIA[0-9A-Z]{16})/g, // AWS Access Key
      /(?:AIzaSy[A-Za-z0-9_\-]{33})/g, // Google API Key
      /(?:sk-[A-Za-z0-9]{20,50})/g, // Stripe / OpenAI secret key
      /(?:ghp_[A-Za-z0-9]{36})/g, // GitHub personal access token
      /(?:glpat-[A-Za-z0-9\-_]{20,})/g, // GitLab personal access token
    ],
    severity: 'High',
    baseConfidence: 70,
  },
  {
    id: 'JWT',
    label: 'JWT Token',
    patterns: [
      /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    ],
    severity: 'High',
    baseConfidence: 85,
  },
  {
    id: 'EMAIL',
    label: 'Email Address',
    patterns: [
      /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g,
    ],
    severity: 'Low',
    baseConfidence: 60,
  },
  {
    id: 'PASSWORD',
    label: 'Password Field',
    patterns: [
      /(?:password|passwd|pwd|pass_word|user_pass)\s*[:=]\s*['"`]([^'"`\s]{4,})['"`]/gi,
    ],
    severity: 'High',
    baseConfidence: 75,
  },
  {
    id: 'SECRET',
    label: 'High-Entropy Secret',
    patterns: [
      // Generic secret/token/private key assignments with long values
      /(?:secret|token|private[_-]?key|auth[_-]?token|bearer)\s*[:=]\s*['"`]([A-Za-z0-9+/=_\-]{32,})['"`]/gi,
    ],
    severity: 'Medium',
    baseConfidence: 55,
  },
];

/**
 * Known false-positive patterns to filter out.
 */
const FALSE_POSITIVE_PATTERNS = [
  /^[0]+$/,                    // All zeros
  /^[a]+$/i,                   // All same character
  /^(test|example|sample|demo|placeholder|changeme|xxx)/i,
  /^your[_-]?(api|key|token|secret)/i,
  /^insert[_-]?your/i,
  /^TODO/i,
  /^REPLACE/i,
  /node_modules/,
  /webpack/i,
  /sourceMappingURL/,
  /^data:application/,
];

/**
 * Calculate Shannon entropy of a string.
 * Higher entropy = more random = more likely to be a real secret.
 * @param {string} str 
 * @returns {number} Entropy value (0 to ~4.7 for base64-like strings)
 */
function calculateEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const char in freq) {
    const p = freq[char] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Check if a match is likely a false positive.
 * @param {string} match 
 * @returns {boolean}
 */
function isFalsePositive(match) {
  if (!match || match.length < 4) return true;
  for (const fp of FALSE_POSITIVE_PATTERNS) {
    if (fp.test(match)) return true;
  }
  // Very low entropy strings are likely placeholders
  if (match.length > 10 && calculateEntropy(match) < 2.0) return true;
  return false;
}

/**
 * Calculate confidence score for a finding.
 * @param {object} rule - The detection rule that matched
 * @param {string} match - The matched string
 * @param {string} context - Surrounding code context (±100 chars)
 * @returns {number} Confidence score 0-100
 */
function calculateConfidence(rule, match, context) {
  let score = rule.baseConfidence;

  // --- Entropy bonus (0–15 points) ---
  const entropy = calculateEntropy(match);
  if (entropy > 4.0) score += 15;
  else if (entropy > 3.5) score += 10;
  else if (entropy > 3.0) score += 5;
  else if (entropy < 2.0) score -= 15;

  // --- Context bonus (0–10 points) ---
  const contextLower = (context || '').toLowerCase();
  const sensitiveContextWords = [
    'authorization', 'bearer', 'credentials', 'authenticate',
    'private', 'secret', 'confidential', 'production', 'prod',
  ];
  for (const word of sensitiveContextWords) {
    if (contextLower.includes(word)) {
      score += 5;
      break; // Only add once
    }
  }

  // --- Length bonus (0–5 points) ---
  if (match.length > 40) score += 5;
  else if (match.length > 20) score += 3;

  // --- Penalty for common/short values ---
  if (match.length < 10) score -= 10;

  return Math.max(0, Math.min(100, score));
}

/**
 * Mask a sensitive value for safe UI display.
 * @param {string} value 
 * @param {string} type 
 * @returns {string}
 */
function maskValue(value, type) {
  if (!value) return '';
  if (value.length <= 6) return '*'.repeat(value.length);

  switch (type) {
    case 'EMAIL': {
      const [local, domain] = value.split('@');
      if (!domain) return value;
      const maskedLocal = local[0] + '***';
      return `${maskedLocal}@${domain}`;
    }
    case 'JWT': {
      return value.substring(0, 10) + '...' + value.substring(value.length - 6);
    }
    default: {
      const showStart = Math.min(4, Math.floor(value.length * 0.15));
      const showEnd = Math.min(4, Math.floor(value.length * 0.15));
      const masked = value.substring(0, showStart) + '***' + value.substring(value.length - showEnd);
      return masked;
    }
  }
}

/**
 * Extract surrounding context from content around a match position.
 * @param {string} content 
 * @param {number} matchIndex 
 * @param {number} radius 
 * @returns {string}
 */
function getContext(content, matchIndex, radius = 100) {
  const start = Math.max(0, matchIndex - radius);
  const end = Math.min(content.length, matchIndex + radius);
  return content.substring(start, end);
}

/**
 * Scan JavaScript content for sensitive information.
 * @param {string} content - Raw JavaScript file content
 * @param {string} fileUrl - Source file URL for reporting
 * @returns {Array<object>} Array of findings
 */
function scanForSecrets(content, fileUrl) {
  if (!content || typeof content !== 'string') return [];

  const findings = [];
  const seenMatches = new Set();

  for (const rule of DETECTION_RULES) {
    for (const pattern of rule.patterns) {
      // Reset regex state for global patterns
      pattern.lastIndex = 0;
      let regexMatch;

      while ((regexMatch = pattern.exec(content)) !== null) {
        // Use captured group if available, otherwise full match
        const matchedValue = regexMatch[1] || regexMatch[0];

        // Deduplicate
        const dedupKey = `${rule.id}:${matchedValue}`;
        if (seenMatches.has(dedupKey)) continue;
        seenMatches.add(dedupKey);

        // Filter false positives
        if (isFalsePositive(matchedValue)) continue;

        // Get context and calculate confidence
        const context = getContext(content, regexMatch.index);
        const confidence = calculateConfidence(rule, matchedValue, context);

        // Skip very low confidence findings
        if (confidence < 20) continue;

        findings.push({
          file: fileUrl,
          type: rule.id,
          label: rule.label,
          match: maskValue(matchedValue, rule.id),
          rawMatch: matchedValue, // Full value for JSON export
          severity: rule.severity,
          confidence: confidence,
          source: fileUrl,
        });
      }
    }
  }

  // Sort by confidence descending
  findings.sort((a, b) => b.confidence - a.confidence);
  return findings;
}

// Export for use in background.js (ES module)
export { scanForSecrets, maskValue, calculateEntropy };

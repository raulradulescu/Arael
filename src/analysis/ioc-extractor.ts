/**
 * IOC (Indicator of Compromise) Extractor (v2.6)
 *
 * Extracts IOCs from binary strings:
 * - IP addresses (IPv4/IPv6)
 * - Domain names
 * - URLs
 * - Email addresses
 * - File paths
 * - Registry keys
 * - Mutex names
 * - User agents
 */

export interface IOCCollection {
  ips: string[];
  domains: string[];
  urls: string[];
  emails: string[];
  filePaths: string[];
  registryKeys: string[];
  mutexes: string[];
  userAgents: string[];
}

export interface ExtractedIOC {
  type: keyof IOCCollection;
  value: string;
  source: string; // original string containing the IOC
  confidence: number;
}

// ============================================================================
// REGEX PATTERNS
// ============================================================================

const PATTERNS = {
  // IPv4 address (with validation for valid octets)
  ipv4: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,

  // IPv6 address (simplified - catches most common formats)
  ipv6: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b/g,

  // Domain name (with TLD validation)
  domain: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|edu|gov|mil|co|info|biz|name|mobi|pro|int|museum|aero|coop|jobs|travel|xxx|ru|cn|uk|de|fr|jp|br|in|it|au|es|nl|se|no|fi|dk|pl|cz|hu|ro|bg|gr|pt|tr|ua|kr|tw|hk|sg|my|id|ph|th|vn|za|ng|ke|eg|ma|ly|dz|ir|pk|bd|ae|sa|il|qa|kw|bh|om|ye|jo|lb|sy|iq|ps|af|am|az|by|ge|kz|kg|md|mn|tj|tm|uz|eu|me|tv|ws|fm|cc|gg|je|im|to|nu|tk|ml|ga|cf|gq|su|xyz|top|win|vip|site|online|club|shop|app|dev|tech|blog|live|cloud|host|space|store|link|click|work|fun|website|one|network|solutions|digital|world|today|news|media|design|center|support|email|services|systems|company|agency|group|international|global|consulting|enterprises|ventures|partners|holdings|limited|ltd|inc|corp|llc|gmbh|ag|sa|spa|srl|bv|nv|pty|plc|co\.uk|com\.au|co\.nz|co\.za|com\.br|com\.mx|co\.jp|co\.kr|com\.cn|com\.tw|com\.hk|com\.sg|co\.in|com\.pk|co\.id|com\.my|com\.ph|co\.th|com\.vn|co\.il|com\.tr|com\.eg|com\.ng|co\.ke|com\.ua|com\.ru|com\.pl|co\.hu|com\.ro|com\.gr|com\.pt|com\.ar|com\.co|com\.ve|com\.pe|com\.ec|com\.cl|com\.uy|com\.py|com\.bo|local|localhost|internal|intranet|lan|test|example|invalid)\b/gi,

  // URL (http, https, ftp)
  url: /\b(?:https?|ftp):\/\/[^\s<>"{}|\\^`\[\]]+/gi,

  // Email address
  email: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,

  // Windows file path
  windowsPath: /\b[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*\b/g,

  // Unix file path (must start with / and have at least one more segment)
  unixPath: /\b\/(?:usr|etc|var|tmp|home|root|opt|bin|sbin|lib|lib64|dev|proc|sys|mnt|media|srv|boot|run)\/[^\s<>"'`|;]+/g,

  // Windows registry key
  registryKey: /\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s<>"']+/gi,

  // Mutex name (common patterns)
  mutex: /\b(?:Global\\|Local\\)?[A-Za-z_][A-Za-z0-9_-]{8,}(?:Mutex|Mtx|Lock|Sync|Event|Sem)\b/gi,

  // User agent string
  userAgent: /\bMozilla\/[^\r\n]{10,200}\b/g,
};

// ============================================================================
// FALSE POSITIVE FILTERS
// ============================================================================

// IPs to exclude (localhost, private ranges used commonly, broadcast)
const EXCLUDED_IPS = new Set([
  '0.0.0.0',
  '127.0.0.1',
  '255.255.255.255',
  '::1',
  '::',
]);

// Common false positive domains
const EXCLUDED_DOMAINS = new Set([
  'example.com',
  'example.org',
  'example.net',
  'localhost',
  'localhost.localdomain',
  'test.com',
  'test.local',
  'invalid',
  'schema.org',
  'w3.org',
  'microsoft.com', // Often appears in legitimate binaries
  'windows.com',
  'apple.com',
  'google.com', // May want to keep these - making them configurable
]);

// File extensions that are commonly false positives
const EXCLUDED_PATH_PATTERNS = [
  /\.dll$/i,
  /\.sys$/i,
  /\.drv$/i,
  /^C:\\Windows\\System32\\/i, // System paths
  /^C:\\Windows\\SysWOW64\\/i,
  /^C:\\Program Files/i,
];

// ============================================================================
// EXTRACTION FUNCTIONS
// ============================================================================

/**
 * Extract all IOCs from an array of strings
 */
export function extractIOCs(
  strings: string[],
  options: {
    includeFalsePositives?: boolean;
    minConfidence?: number;
  } = {}
): IOCCollection {
  const { includeFalsePositives = false, minConfidence = 0.5 } = options;
  const allIOCs: ExtractedIOC[] = [];

  for (const str of strings) {
    allIOCs.push(...extractFromString(str));
  }

  // Filter by confidence and false positives
  const filtered = allIOCs.filter((ioc) => {
    if (ioc.confidence < minConfidence) return false;
    if (!includeFalsePositives && isFalsePositive(ioc)) return false;
    return true;
  });

  // Deduplicate and organize
  return organizeIOCs(filtered);
}

/**
 * Extract IOCs from a single string
 */
function extractFromString(str: string): ExtractedIOC[] {
  const iocs: ExtractedIOC[] = [];

  // URLs (check first as they contain domains/IPs)
  const urls = str.match(PATTERNS.url) || [];
  for (const url of urls) {
    iocs.push({
      type: 'urls',
      value: url,
      source: str,
      confidence: calculateConfidence('urls', url),
    });
  }

  // IP addresses
  const ipv4s = str.match(PATTERNS.ipv4) || [];
  for (const ip of ipv4s) {
    iocs.push({
      type: 'ips',
      value: ip,
      source: str,
      confidence: calculateConfidence('ips', ip),
    });
  }

  const ipv6s = str.match(PATTERNS.ipv6) || [];
  for (const ip of ipv6s) {
    iocs.push({
      type: 'ips',
      value: ip,
      source: str,
      confidence: calculateConfidence('ips', ip),
    });
  }

  // Domains (only if not already part of a URL)
  const domains = str.match(PATTERNS.domain) || [];
  for (const domain of domains) {
    // Skip if this domain is part of an already extracted URL
    const isInUrl = urls.some((url) => url.includes(domain));
    if (!isInUrl) {
      iocs.push({
        type: 'domains',
        value: domain.toLowerCase(),
        source: str,
        confidence: calculateConfidence('domains', domain),
      });
    }
  }

  // Emails
  const emails = str.match(PATTERNS.email) || [];
  for (const email of emails) {
    iocs.push({
      type: 'emails',
      value: email.toLowerCase(),
      source: str,
      confidence: calculateConfidence('emails', email),
    });
  }

  // File paths
  const winPaths = str.match(PATTERNS.windowsPath) || [];
  for (const path of winPaths) {
    iocs.push({
      type: 'filePaths',
      value: path,
      source: str,
      confidence: calculateConfidence('filePaths', path),
    });
  }

  const unixPaths = str.match(PATTERNS.unixPath) || [];
  for (const path of unixPaths) {
    iocs.push({
      type: 'filePaths',
      value: path,
      source: str,
      confidence: calculateConfidence('filePaths', path),
    });
  }

  // Registry keys
  const regKeys = str.match(PATTERNS.registryKey) || [];
  for (const key of regKeys) {
    iocs.push({
      type: 'registryKeys',
      value: key,
      source: str,
      confidence: calculateConfidence('registryKeys', key),
    });
  }

  // Mutexes
  const mutexes = str.match(PATTERNS.mutex) || [];
  for (const mutex of mutexes) {
    iocs.push({
      type: 'mutexes',
      value: mutex,
      source: str,
      confidence: calculateConfidence('mutexes', mutex),
    });
  }

  // User agents
  const userAgents = str.match(PATTERNS.userAgent) || [];
  for (const ua of userAgents) {
    iocs.push({
      type: 'userAgents',
      value: ua,
      source: str,
      confidence: calculateConfidence('userAgents', ua),
    });
  }

  return iocs;
}

/**
 * Calculate confidence score for an IOC
 */
function calculateConfidence(type: keyof IOCCollection, value: string): number {
  let confidence = 0.7; // Base confidence

  switch (type) {
    case 'ips':
      // Higher confidence for non-private IPs
      if (isPrivateIP(value)) {
        confidence = 0.5;
      } else {
        confidence = 0.9;
      }
      break;

    case 'domains':
      // Higher confidence for suspicious TLDs
      const suspiciousTLDs = ['.ru', '.cn', '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.win', '.vip'];
      if (suspiciousTLDs.some((tld) => value.endsWith(tld))) {
        confidence = 0.95;
      } else if (value.includes('dyndns') || value.includes('no-ip') || value.includes('ddns')) {
        confidence = 0.95; // Dynamic DNS
      }
      break;

    case 'urls':
      // Higher confidence for URLs with suspicious patterns
      if (value.includes('/beacon') || value.includes('/c2') || value.includes('/gate')) {
        confidence = 0.95;
      }
      if (value.match(/\/[a-z0-9]{32,}/i)) {
        confidence = 0.9; // Long random-looking paths
      }
      break;

    case 'registryKeys':
      // Higher confidence for persistence-related keys
      if (value.includes('CurrentVersion\\Run') || value.includes('CurrentVersion\\RunOnce')) {
        confidence = 0.95;
      }
      if (value.includes('Services\\') || value.includes('Image File Execution')) {
        confidence = 0.9;
      }
      break;

    case 'filePaths':
      // Lower confidence for system paths
      if (value.includes('\\Windows\\') || value.includes('\\System32\\')) {
        confidence = 0.4;
      } else if (value.includes('\\Temp\\') || value.includes('\\AppData\\')) {
        confidence = 0.85;
      }
      break;

    case 'mutexes':
      // Higher confidence for unique-looking mutexes
      if (value.length > 20) {
        confidence = 0.85;
      }
      break;

    case 'userAgents':
      // Check for common malware UA patterns
      if (value.includes('curl') || value.includes('wget') || value.includes('python')) {
        confidence = 0.8;
      }
      break;
  }

  return confidence;
}

/**
 * Check if an IP is private
 */
function isPrivateIP(ip: string): boolean {
  // IPv4 private ranges
  if (ip.startsWith('10.')) return true;
  if (ip.startsWith('172.')) {
    const parts = ip.split('.');
    const second = parts[1] ? parseInt(parts[1], 10) : 0;
    if (second >= 16 && second <= 31) return true;
  }
  if (ip.startsWith('192.168.')) return true;
  if (ip.startsWith('169.254.')) return true; // Link-local

  return false;
}

/**
 * Check if an IOC is likely a false positive
 */
function isFalsePositive(ioc: ExtractedIOC): boolean {
  switch (ioc.type) {
    case 'ips':
      if (EXCLUDED_IPS.has(ioc.value)) return true;
      // Version numbers that look like IPs
      if (ioc.source.includes('version') || ioc.source.includes('Version')) return true;
      break;

    case 'domains':
      if (EXCLUDED_DOMAINS.has(ioc.value.toLowerCase())) return true;
      // Single-word domains are often false positives
      if (!ioc.value.includes('.')) return true;
      break;

    case 'filePaths':
      for (const pattern of EXCLUDED_PATH_PATTERNS) {
        if (pattern.test(ioc.value)) return true;
      }
      break;

    case 'emails':
      // Common placeholder emails
      if (ioc.value.includes('example.com') || ioc.value.includes('test.com')) return true;
      break;
  }

  return false;
}

/**
 * Organize IOCs into collection, deduplicating
 */
function organizeIOCs(iocs: ExtractedIOC[]): IOCCollection {
  const result: IOCCollection = {
    ips: [],
    domains: [],
    urls: [],
    emails: [],
    filePaths: [],
    registryKeys: [],
    mutexes: [],
    userAgents: [],
  };

  const seen = new Set<string>();

  for (const ioc of iocs) {
    const key = `${ioc.type}:${ioc.value}`;
    if (!seen.has(key)) {
      seen.add(key);
      result[ioc.type].push(ioc.value);
    }
  }

  return result;
}

/**
 * Get detailed IOC extraction with confidence scores
 */
export function extractIOCsDetailed(strings: string[]): ExtractedIOC[] {
  const allIOCs: ExtractedIOC[] = [];

  for (const str of strings) {
    allIOCs.push(...extractFromString(str));
  }

  // Sort by confidence descending
  allIOCs.sort((a, b) => b.confidence - a.confidence);

  return allIOCs;
}

/**
 * Check if a collection has any IOCs
 */
export function hasIOCs(collection: IOCCollection): boolean {
  return (
    collection.ips.length > 0 ||
    collection.domains.length > 0 ||
    collection.urls.length > 0 ||
    collection.emails.length > 0 ||
    collection.filePaths.length > 0 ||
    collection.registryKeys.length > 0 ||
    collection.mutexes.length > 0 ||
    collection.userAgents.length > 0
  );
}

/**
 * Count total IOCs
 */
export function countIOCs(collection: IOCCollection): number {
  return (
    collection.ips.length +
    collection.domains.length +
    collection.urls.length +
    collection.emails.length +
    collection.filePaths.length +
    collection.registryKeys.length +
    collection.mutexes.length +
    collection.userAgents.length
  );
}

/**
 * Get IOC summary for display
 */
export function getIOCSummary(collection: IOCCollection): string[] {
  const summary: string[] = [];

  if (collection.ips.length > 0) {
    summary.push(`${collection.ips.length} IP address(es)`);
  }
  if (collection.domains.length > 0) {
    summary.push(`${collection.domains.length} domain(s)`);
  }
  if (collection.urls.length > 0) {
    summary.push(`${collection.urls.length} URL(s)`);
  }
  if (collection.emails.length > 0) {
    summary.push(`${collection.emails.length} email(s)`);
  }
  if (collection.filePaths.length > 0) {
    summary.push(`${collection.filePaths.length} file path(s)`);
  }
  if (collection.registryKeys.length > 0) {
    summary.push(`${collection.registryKeys.length} registry key(s)`);
  }
  if (collection.mutexes.length > 0) {
    summary.push(`${collection.mutexes.length} mutex(es)`);
  }
  if (collection.userAgents.length > 0) {
    summary.push(`${collection.userAgents.length} user agent(s)`);
  }

  return summary;
}

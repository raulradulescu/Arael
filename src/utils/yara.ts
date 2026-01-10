import { spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { logger } from './logger';

export interface YaraMatch {
  rule: string;
  tags: string[];
  meta: Record<string, string>;
  strings: Array<{
    offset: number;
    identifier: string;
    data: string;
  }>;
}

export interface YaraScanResult {
  matches: YaraMatch[];
  rulesUsed: string[];
  errors: string[];
}

// Built-in YARA rules for common patterns
const BUILTIN_RULES = `
rule UPX_Packed {
  meta:
    description = "UPX packed executable"
    category = "packer"
  strings:
    $upx0 = "UPX0" ascii
    $upx1 = "UPX1" ascii
    $upx2 = "UPX!" ascii
    $upx3 = { 55 50 58 21 }
  condition:
    any of them
}

rule PyInstaller_Bundle {
  meta:
    description = "PyInstaller bundled executable"
    category = "packer"
  strings:
    $mei = "MEI" ascii
    $pyi = "pyi-" ascii
    $pyinst = "PyInstaller" ascii
    $python = "python" ascii nocase
  condition:
    2 of them
}

rule Themida_Protected {
  meta:
    description = "Themida/WinLicense protected"
    category = "packer"
  strings:
    $s1 = ".themida" ascii
    $s2 = ".winlic" ascii
    $s3 = "THEMIDA" ascii
  condition:
    any of them
}

rule VMProtect_Protected {
  meta:
    description = "VMProtect protected"
    category = "packer"
  strings:
    $vmp0 = ".vmp0" ascii
    $vmp1 = ".vmp1" ascii
    $vmprotect = "VMProtect" ascii
  condition:
    any of them
}

rule Crypto_AES {
  meta:
    description = "AES encryption constants"
    category = "crypto"
  strings:
    $sbox = { 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 }
    $rcon = { 01 02 04 08 10 20 40 80 1b 36 }
  condition:
    any of them
}

rule Crypto_RSA {
  meta:
    description = "RSA related strings"
    category = "crypto"
  strings:
    $rsa1 = "RSA" ascii wide
    $rsa2 = "BEGIN RSA" ascii
    $rsa3 = "PRIVATE KEY" ascii
    $rsa4 = "PUBLIC KEY" ascii
  condition:
    2 of them
}

rule Crypto_Base64 {
  meta:
    description = "Base64 alphabet"
    category = "crypto"
  strings:
    $b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ascii
  condition:
    $b64
}

rule Network_URLs {
  meta:
    description = "Contains URLs"
    category = "network"
  strings:
    $http = "http://" ascii nocase
    $https = "https://" ascii nocase
    $ftp = "ftp://" ascii nocase
  condition:
    any of them
}

rule Network_IP_Address {
  meta:
    description = "Contains IP address pattern"
    category = "network"
  strings:
    $ip = /\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/
  condition:
    $ip
}

rule Anti_Debug_Ptrace {
  meta:
    description = "Anti-debugging via ptrace"
    category = "anti-debug"
  strings:
    $ptrace = "ptrace" ascii
    $traceme = "PTRACE_TRACEME" ascii
  condition:
    any of them
}

rule Anti_Debug_Windows {
  meta:
    description = "Windows anti-debugging techniques"
    category = "anti-debug"
  strings:
    $s1 = "IsDebuggerPresent" ascii
    $s2 = "CheckRemoteDebuggerPresent" ascii
    $s3 = "NtQueryInformationProcess" ascii
    $s4 = "OutputDebugString" ascii
  condition:
    any of them
}

rule Suspicious_Strings {
  meta:
    description = "Suspicious strings often found in malware"
    category = "suspicious"
  strings:
    $s1 = "cmd.exe" ascii nocase
    $s2 = "powershell" ascii nocase
    $s3 = "/c " ascii
    $s4 = "shell" ascii nocase
    $s5 = "exec" ascii nocase
  condition:
    2 of them
}

rule Embedded_PE {
  meta:
    description = "Embedded PE file"
    category = "suspicious"
  strings:
    $mz = { 4D 5A }
    $pe = "PE" ascii
  condition:
    $mz at 0 and $pe
}

rule Flag_Pattern {
  meta:
    description = "CTF flag pattern"
    category = "ctf"
  strings:
    $flag1 = /[A-Z]{2,10}\\{[^}]+\\}/
    $flag2 = "flag{" ascii nocase
    $flag3 = "FLAG" ascii
  condition:
    any of them
}

rule Hardcoded_Credentials {
  meta:
    description = "Potential hardcoded credentials"
    category = "suspicious"
  strings:
    $pass1 = "password" ascii nocase
    $pass2 = "passwd" ascii nocase
    $pass3 = "secret" ascii nocase
    $pass4 = "api_key" ascii nocase
    $pass5 = "apikey" ascii nocase
    $pass6 = "auth_token" ascii nocase
  condition:
    any of them
}
`;

/**
 * Check if YARA is installed
 */
export async function isYaraInstalled(): Promise<boolean> {
  return new Promise((resolve) => {
    const proc = spawn('yara', ['--version']);
    proc.on('error', () => resolve(false));
    proc.on('close', (code) => resolve(code === 0));
  });
}

/**
 * Scan a binary with built-in YARA rules
 */
export async function scanWithBuiltinRules(binaryPath: string): Promise<YaraScanResult> {
  // Check if yara is installed
  const yaraInstalled = await isYaraInstalled();

  if (yaraInstalled) {
    // Use yara CLI
    return scanWithYaraCli(binaryPath, BUILTIN_RULES);
  }

  // Fallback: basic pattern matching without yara
  logger.warn('YARA not installed, using basic pattern matching');
  return scanWithBasicPatterns(binaryPath);
}

/**
 * Scan using YARA CLI
 */
async function scanWithYaraCli(binaryPath: string, rules: string): Promise<YaraScanResult> {
  const result: YaraScanResult = {
    matches: [],
    rulesUsed: ['yara-cli'],
    errors: []
  };

  // Write rules to temp file
  const tempRulesPath = path.join(os.tmpdir(), `arael_yara_${Date.now()}.yar`);
  fs.writeFileSync(tempRulesPath, rules);

  try {
    const output = await new Promise<string>((resolve, reject) => {
      const proc = spawn('yara', ['-s', '-m', tempRulesPath, binaryPath]);
      let stdout = '';
      let stderr = '';

      proc.stdout.on('data', (data) => { stdout += data; });
      proc.stderr.on('data', (data) => { stderr += data; });

      proc.on('error', reject);
      proc.on('close', (code) => {
        if (code === 0 || code === 1) {
          // code 1 means no matches, which is fine
          resolve(stdout);
        } else {
          reject(new Error(stderr || `YARA exited with code ${code}`));
        }
      });
    });

    // Parse YARA output
    const lines = output.trim().split('\n').filter(l => l.trim());
    let currentMatch: YaraMatch | null = null;

    for (const line of lines) {
      // Rule match line: "rule_name [tags] file_path"
      const ruleMatch = line.match(/^(\w+)\s+(?:\[(.*?)\])?\s*(.+)$/);
      if (ruleMatch && ruleMatch[1] && !line.startsWith('0x')) {
        if (currentMatch) {
          result.matches.push(currentMatch);
        }
        currentMatch = {
          rule: ruleMatch[1],
          tags: ruleMatch[2] ? ruleMatch[2].split(',').map(t => t.trim()) : [],
          meta: {},
          strings: []
        };
      }

      // String match line: "0x123:$identifier: data"
      const stringMatch = line.match(/^(0x[0-9a-f]+):(\$\w+):\s*(.*)$/i);
      if (stringMatch && stringMatch[1] && stringMatch[2] && currentMatch) {
        currentMatch.strings.push({
          offset: parseInt(stringMatch[1], 16),
          identifier: stringMatch[2],
          data: stringMatch[3] ?? ''
        });
      }
    }

    if (currentMatch) {
      result.matches.push(currentMatch);
    }

  } catch (error) {
    result.errors.push(error instanceof Error ? error.message : String(error));
  } finally {
    // Clean up temp file
    try {
      fs.unlinkSync(tempRulesPath);
    } catch {
      // Ignore cleanup errors
    }
  }

  return result;
}

/**
 * Basic pattern matching without YARA
 */
async function scanWithBasicPatterns(binaryPath: string): Promise<YaraScanResult> {
  const result: YaraScanResult = {
    matches: [],
    rulesUsed: ['basic-patterns'],
    errors: []
  };

  try {
    const data = fs.readFileSync(binaryPath);
    const text = data.toString('utf8', 0, Math.min(data.length, 1024 * 1024)); // First 1MB

    // Check for packers
    if (text.includes('UPX0') || text.includes('UPX1') || text.includes('UPX!')) {
      result.matches.push({ rule: 'UPX_Packed', tags: ['packer'], meta: {}, strings: [] });
    }
    if (text.includes('MEI') && (text.includes('pyi-') || text.includes('PyInstaller'))) {
      result.matches.push({ rule: 'PyInstaller_Bundle', tags: ['packer'], meta: {}, strings: [] });
    }
    if (text.includes('.themida') || text.includes('.winlic')) {
      result.matches.push({ rule: 'Themida_Protected', tags: ['packer'], meta: {}, strings: [] });
    }
    if (text.includes('.vmp0') || text.includes('.vmp1')) {
      result.matches.push({ rule: 'VMProtect_Protected', tags: ['packer'], meta: {}, strings: [] });
    }

    // Check for crypto
    if (text.includes('RSA') || text.includes('PRIVATE KEY') || text.includes('PUBLIC KEY')) {
      result.matches.push({ rule: 'Crypto_RSA', tags: ['crypto'], meta: {}, strings: [] });
    }

    // Check for network
    if (text.includes('http://') || text.includes('https://') || text.includes('ftp://')) {
      result.matches.push({ rule: 'Network_URLs', tags: ['network'], meta: {}, strings: [] });
    }

    // Check for anti-debug
    if (text.includes('ptrace') || text.includes('PTRACE_TRACEME')) {
      result.matches.push({ rule: 'Anti_Debug_Ptrace', tags: ['anti-debug'], meta: {}, strings: [] });
    }
    if (text.includes('IsDebuggerPresent') || text.includes('CheckRemoteDebuggerPresent')) {
      result.matches.push({ rule: 'Anti_Debug_Windows', tags: ['anti-debug'], meta: {}, strings: [] });
    }

    // Check for suspicious strings
    const suspiciousCount = ['cmd.exe', 'powershell', 'shell', 'exec']
      .filter(s => text.toLowerCase().includes(s)).length;
    if (suspiciousCount >= 2) {
      result.matches.push({ rule: 'Suspicious_Strings', tags: ['suspicious'], meta: {}, strings: [] });
    }

    // Check for flags
    if (/[A-Z]{2,10}\{[^}]+\}/.test(text) || text.toLowerCase().includes('flag{')) {
      result.matches.push({ rule: 'Flag_Pattern', tags: ['ctf'], meta: {}, strings: [] });
    }

    // Check for credentials
    const credCount = ['password', 'passwd', 'secret', 'api_key', 'apikey', 'auth_token']
      .filter(s => text.toLowerCase().includes(s)).length;
    if (credCount >= 1) {
      result.matches.push({ rule: 'Hardcoded_Credentials', tags: ['suspicious'], meta: {}, strings: [] });
    }

  } catch (error) {
    result.errors.push(error instanceof Error ? error.message : String(error));
  }

  return result;
}

/**
 * Scan with custom rules file
 */
export async function scanWithCustomRules(binaryPath: string, rulesPath: string): Promise<YaraScanResult> {
  const rules = fs.readFileSync(rulesPath, 'utf-8');
  return scanWithYaraCli(binaryPath, rules);
}

/**
 * Get list of available rule categories
 */
export function getAvailableCategories(): string[] {
  return ['packer', 'crypto', 'network', 'anti-debug', 'suspicious', 'ctf'];
}

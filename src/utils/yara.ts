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

export type RuleSet = 'builtin' | 'reversinglabs' | 'all' | string;

export interface ScanOptions {
  ruleSet?: RuleSet;
  customRulesPath?: string;
}

// Path to ReversingLabs rules (relative to project root)
const RL_RULES_DIR = 'reversinglabs-yara-rules-develop/yara';

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

rule MPRESS_Packed {
  meta:
    description = "MPRESS packed executable"
    category = "packer"
  strings:
    $mpress1 = ".MPRESS1" ascii
    $mpress2 = ".MPRESS2" ascii
    $mpress3 = "MPRESS" ascii
  condition:
    any of them
}

rule ASPack_Packed {
  meta:
    description = "ASPack packed executable"
    category = "packer"
  strings:
    $aspack1 = ".aspack" ascii
    $aspack2 = "ASPack" ascii
    $aspack3 = ".adata" ascii
  condition:
    any of them
}

rule Enigma_Protected {
  meta:
    description = "Enigma Protector"
    category = "packer"
  strings:
    $enigma1 = ".enigma1" ascii
    $enigma2 = ".enigma2" ascii
    $enigma3 = "Enigma protector" ascii nocase
  condition:
    any of them
}

rule ConfuserEx_Obfuscated {
  meta:
    description = "ConfuserEx .NET obfuscator"
    category = "packer"
  strings:
    $confuser1 = "ConfuserEx" ascii
    $confuser2 = "Confuser.Core" ascii
    $confuser3 = { 43 6F 6E 66 75 73 65 72 }
  condition:
    any of them
}

rule PyArmor_Protected {
  meta:
    description = "PyArmor Python obfuscator"
    category = "packer"
  strings:
    $pyarmor1 = "pyarmor" ascii nocase
    $pyarmor2 = "_pytransform" ascii
    $pyarmor3 = "pytransform.pyd" ascii
  condition:
    any of them
}

rule Crypto_RC4 {
  meta:
    description = "RC4 key schedule pattern"
    category = "crypto"
  strings:
    $rc4_init = { 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F }
    $rc4_str = "RC4" ascii
  condition:
    any of them
}

rule Crypto_ChaCha20 {
  meta:
    description = "ChaCha20 constants"
    category = "crypto"
  strings:
    $chacha = "expand 32-byte k" ascii
    $chacha2 = { 65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B }
  condition:
    any of them
}

rule Crypto_MD5_Constants {
  meta:
    description = "MD5 initialization constants"
    category = "crypto"
  strings:
    $md5_1 = { 01 23 45 67 }
    $md5_2 = { 89 AB CD EF }
    $md5_3 = { FE DC BA 98 }
    $md5_4 = { 76 54 32 10 }
    $md5_str = "MD5" ascii
  condition:
    $md5_str or (2 of ($md5_*))
}

rule Crypto_SHA256_Constants {
  meta:
    description = "SHA256 round constants"
    category = "crypto"
  strings:
    $sha256_1 = { 42 8A 2F 98 }
    $sha256_2 = { 71 37 44 91 }
    $sha256_str = "SHA256" ascii
    $sha256_str2 = "SHA-256" ascii
  condition:
    any of them
}

rule Crypto_XOR_Loop {
  meta:
    description = "XOR encoding loop pattern"
    category = "crypto"
  strings:
    $xor_x86 = { 30 ?? 4? E? F? }
    $xor_x64 = { 30 ?? 48 FF C? }
  condition:
    any of them
}

rule Shellcode_NOP_Sled {
  meta:
    description = "NOP sled pattern"
    category = "shellcode"
  strings:
    $nop_sled = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
  condition:
    $nop_sled
}

rule Shellcode_Common_x86 {
  meta:
    description = "Common x86 shellcode patterns"
    category = "shellcode"
  strings:
    $getpc = { E8 00 00 00 00 }
    $fstenv = { D9 74 24 F4 }
    $call_eax = { FF D0 }
    $jmp_esp = { FF E4 }
  condition:
    2 of them
}

rule Shellcode_Common_x64 {
  meta:
    description = "Common x64 shellcode patterns"
    category = "shellcode"
  strings:
    $syscall = { 0F 05 }
    $gs_access = { 65 48 8B }
    $peb_access = { 65 48 8B 04 25 60 00 00 00 }
  condition:
    2 of them
}

rule Metasploit_Payload {
  meta:
    description = "Metasploit payload signatures"
    category = "shellcode"
  strings:
    $msf1 = "metsrv" ascii
    $msf2 = "meterpreter" ascii nocase
    $msf3 = "stdapi" ascii
    $msf4 = { FC E8 82 00 00 00 }
  condition:
    any of them
}

rule VM_Detection {
  meta:
    description = "Virtual machine detection strings"
    category = "evasion"
  strings:
    $vmware1 = "VMware" ascii nocase
    $vmware2 = "vmtoolsd" ascii
    $vbox1 = "VirtualBox" ascii nocase
    $vbox2 = "VBOX" ascii
    $qemu = "QEMU" ascii
    $hyperv = "Hyper-V" ascii
    $xen = "Xen" ascii
  condition:
    any of them
}

rule Sandbox_Evasion {
  meta:
    description = "Sandbox evasion techniques"
    category = "evasion"
  strings:
    $sleep1 = "SleepEx" ascii
    $sleep2 = "NtDelayExecution" ascii
    $mouse1 = "GetCursorPos" ascii
    $mouse2 = "GetLastInputInfo" ascii
    $tick = "GetTickCount" ascii
    $uptime = "NtQuerySystemTime" ascii
  condition:
    2 of them
}

rule AMSI_Bypass {
  meta:
    description = "AMSI bypass patterns"
    category = "evasion"
  strings:
    $amsi1 = "AmsiScanBuffer" ascii
    $amsi2 = "amsi.dll" ascii nocase
    $amsi3 = "AmsiInitialize" ascii
    $amsi4 = { 48 8B 05 [4] 48 85 C0 74 }
  condition:
    2 of them
}

rule ETW_Bypass {
  meta:
    description = "ETW disabling patterns"
    category = "evasion"
  strings:
    $etw1 = "EtwEventWrite" ascii
    $etw2 = "EtwEventWriteFull" ascii
    $patch1 = { 48 33 C0 C3 }
    $patch2 = { B8 00 00 00 00 C3 }
  condition:
    ($etw1 or $etw2) and any of ($patch*)
}

rule Keylogger_Indicators {
  meta:
    description = "Keylogger API usage"
    category = "malware"
  strings:
    $key1 = "GetAsyncKeyState" ascii
    $key2 = "GetKeyState" ascii
    $key3 = "SetWindowsHookEx" ascii
    $key4 = "WH_KEYBOARD" ascii
    $key5 = "WH_KEYBOARD_LL" ascii
  condition:
    2 of them
}

rule Screenshot_Capture {
  meta:
    description = "Screenshot capture indicators"
    category = "malware"
  strings:
    $scr1 = "BitBlt" ascii
    $scr2 = "GetDC" ascii
    $scr3 = "CreateCompatibleBitmap" ascii
    $scr4 = "GetWindowDC" ascii
    $scr5 = "PrintWindow" ascii
  condition:
    3 of them
}

rule Clipboard_Monitor {
  meta:
    description = "Clipboard monitoring"
    category = "malware"
  strings:
    $clip1 = "GetClipboardData" ascii
    $clip2 = "SetClipboardData" ascii
    $clip3 = "OpenClipboard" ascii
    $clip4 = "AddClipboardFormatListener" ascii
  condition:
    2 of them
}

rule C2_Beaconing {
  meta:
    description = "Beacon/callback indicators"
    category = "malware"
  strings:
    $beacon = "beacon" ascii nocase
    $checkin = "checkin" ascii nocase
    $callback = "callback" ascii nocase
    $heartbeat = "heartbeat" ascii nocase
    $user_agent = "User-Agent" ascii
    $post = "POST " ascii
    $get = "GET " ascii
    $sleep = "sleep" ascii nocase
    $jitter = "jitter" ascii nocase
  condition:
    (1 of ($beacon,$checkin,$callback,$heartbeat)) and (1 of ($user_agent,$post,$get,$sleep,$jitter))
}

rule Go_Binary {
  meta:
    description = "Go compiled binary"
    category = "compiler"
  strings:
    $go1 = "runtime.gopanic" ascii
    $go2 = "runtime.goexit" ascii
    $go3 = "go.buildid" ascii
    $go4 = "runtime.main" ascii
  condition:
    2 of them
}

rule Rust_Binary {
  meta:
    description = "Rust compiled binary"
    category = "compiler"
  strings:
    $rust1 = "rust_panic" ascii
    $rust2 = "core::panicking" ascii
    $rust3 = "std::rt::lang_start" ascii
    $rust4 = ".rustc" ascii
  condition:
    2 of them
}

rule Nim_Binary {
  meta:
    description = "Nim compiled binary"
    category = "compiler"
  strings:
    $nim1 = "nim_program_result" ascii
    $nim2 = "NimMain" ascii
    $nim3 = "@mNim" ascii
    $nim4 = "stdlib_" ascii
  condition:
    2 of them
}

rule DotNet_Assembly {
  meta:
    description = ".NET assembly"
    category = "compiler"
  strings:
    $net1 = "_CorExeMain" ascii
    $net2 = "mscoree.dll" ascii
    $net3 = "#Strings" ascii
    $net4 = "#GUID" ascii
    $net5 = "#Blob" ascii
  condition:
    2 of them
}

rule Ransomware_Extensions {
  meta:
    description = "Common ransomware file extensions"
    category = "ransomware"
  strings:
    $ext1 = ".encrypted" ascii nocase
    $ext2 = ".locked" ascii nocase
    $ext3 = ".crypted" ascii nocase
    $ext4 = ".enc" ascii nocase
    $ext5 = ".WNCRY" ascii
    $ext6 = ".locky" ascii
  condition:
    any of them
}

rule Ransomware_Note_Patterns {
  meta:
    description = "Ransomware note patterns"
    category = "ransomware"
  strings:
    $note1 = "your files have been encrypted" ascii nocase
    $note2 = "bitcoin" ascii nocase
    $note3 = "decrypt" ascii nocase
    $note4 = "ransom" ascii nocase
    $note5 = "pay" ascii nocase
    $note6 = "restore your files" ascii nocase
  condition:
    3 of them
}
`;

const BUILTIN_RULE_COUNT = (BUILTIN_RULES.match(/\brule\s+\w+/g) ?? []).length;

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
    return scanWithYaraCli(binaryPath, BUILTIN_RULES, 'builtin');
  }

  // Fallback: basic pattern matching without yara
  logger.warn('YARA not installed, using basic pattern matching');
  return scanWithBasicPatterns(binaryPath);
}

/**
 * Scan using YARA CLI
 */
async function scanWithYaraCli(binaryPath: string, rules: string, source?: string): Promise<YaraScanResult> {
  const result: YaraScanResult = {
    matches: [],
    rulesUsed: ['yara-cli'],
    errors: []
  };
  const baseMeta: Record<string, string> = source ? { source } : {};

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
      // String match line: "0x123:$identifier: data"
      const stringMatch = line.match(/^(0x[0-9a-f]+):(\$\w+):\s*(.*)$/i);
      if (stringMatch && stringMatch[1] && stringMatch[2] && currentMatch) {
        currentMatch.strings.push({
          offset: parseInt(stringMatch[1], 16),
          identifier: stringMatch[2],
          data: stringMatch[3] ?? ''
        });
        continue;
      }

      const metaMatch = line.match(/^(?:meta:\s*)?(\w+)\s*=\s*(.+)$/);
      if (metaMatch && metaMatch[1] && metaMatch[2] && currentMatch) {
        let value = metaMatch[2].trim();
        if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
          value = value.slice(1, -1);
        }
        currentMatch.meta[metaMatch[1]] = value;
        continue;
      }

      // Rule match line: "rule_name [tags] file_path"
      const ruleMatch = line.match(/^(\w+)\s+(?:\[(.*?)\])?\s*(.+)$/);
      if (ruleMatch && ruleMatch[1] && !line.startsWith('0x')) {
        if (currentMatch) {
          result.matches.push(currentMatch);
        }
        currentMatch = {
          rule: ruleMatch[1],
          tags: ruleMatch[2] ? ruleMatch[2].split(',').map(t => t.trim()) : [],
          meta: { ...baseMeta },
          strings: []
        };
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
  return scanWithYaraCli(binaryPath, rules, 'custom');
}

/**
 * Get list of available rule categories
 */
export function getAvailableCategories(): string[] {
  return ['packer', 'crypto', 'network', 'anti-debug', 'suspicious', 'ctf', 'shellcode', 'evasion', 'malware', 'compiler', 'ransomware'];
}

/**
 * Find ReversingLabs rules directory
 */
function findRLRulesDir(): string | null {
  // Check multiple possible locations
  const possiblePaths = [
    path.join(process.cwd(), RL_RULES_DIR),
    path.join(__dirname, '..', '..', RL_RULES_DIR),
    path.join(__dirname, '..', '..', '..', RL_RULES_DIR),
  ];

  for (const p of possiblePaths) {
    if (fs.existsSync(p)) {
      return p;
    }
  }
  return null;
}

/**
 * Get all .yara files from ReversingLabs rules directory
 */
function getRLRuleFiles(): string[] {
  const rlDir = findRLRulesDir();
  if (!rlDir) {
    return [];
  }

  const ruleFiles: string[] = [];
  const categories = fs.readdirSync(rlDir);

  for (const category of categories) {
    const categoryPath = path.join(rlDir, category);
    if (fs.statSync(categoryPath).isDirectory()) {
      const files = fs.readdirSync(categoryPath);
      for (const file of files) {
        if (file.endsWith('.yara') || file.endsWith('.yar')) {
          ruleFiles.push(path.join(categoryPath, file));
        }
      }
    }
  }

  return ruleFiles;
}

/**
 * Get ReversingLabs rule categories and counts
 */
export function getRLRuleStats(): { category: string; count: number }[] {
  const rlDir = findRLRulesDir();
  if (!rlDir) {
    return [];
  }

  const stats: { category: string; count: number }[] = [];
  const categories = fs.readdirSync(rlDir);

  for (const category of categories) {
    const categoryPath = path.join(rlDir, category);
    if (fs.statSync(categoryPath).isDirectory()) {
      const files = fs.readdirSync(categoryPath).filter(f => f.endsWith('.yara') || f.endsWith('.yar'));
      if (files.length > 0) {
        stats.push({ category, count: files.length });
      }
    }
  }

  return stats;
}

/**
 * Check if ReversingLabs rules are available
 */
export function isRLRulesAvailable(): boolean {
  return findRLRulesDir() !== null;
}

/**
 * Scan with ReversingLabs rules (requires YARA CLI)
 */
export async function scanWithRLRules(binaryPath: string, categories?: string[]): Promise<YaraScanResult> {
  const yaraInstalled = await isYaraInstalled();
  if (!yaraInstalled) {
    return {
      matches: [],
      rulesUsed: [],
      errors: ['YARA CLI required for ReversingLabs rules']
    };
  }

  const rlDir = findRLRulesDir();
  if (!rlDir) {
    return {
      matches: [],
      rulesUsed: [],
      errors: ['ReversingLabs rules not found. Download from: https://github.com/reversinglabs/reversinglabs-yara-rules']
    };
  }

  const ruleFiles = getRLRuleFiles();
  if (ruleFiles.length === 0) {
    return {
      matches: [],
      rulesUsed: [],
      errors: ['No rule files found in ReversingLabs directory']
    };
  }

  // Filter by category if specified
  let filteredFiles = ruleFiles;
  if (categories && categories.length > 0) {
    filteredFiles = ruleFiles.filter(f => {
      const category = path.basename(path.dirname(f));
      return categories.includes(category);
    });
  }

  const result: YaraScanResult = {
    matches: [],
    rulesUsed: ['reversinglabs'],
    errors: []
  };

  // Scan with each rule file
  for (const ruleFile of filteredFiles) {
    try {
      const output = await new Promise<string>((resolve, reject) => {
        const proc = spawn('yara', ['-s', '-m', ruleFile, binaryPath]);
        let stdout = '';
        let stderr = '';

        proc.stdout.on('data', (data) => { stdout += data; });
        proc.stderr.on('data', (data) => { stderr += data; });

        proc.on('error', reject);
        proc.on('close', (code) => {
          if (code === 0 || code === 1) {
            resolve(stdout);
          } else {
            // Don't fail on individual rule errors, just log
            logger.debug(`Rule file ${ruleFile} error: ${stderr}`);
            resolve('');
          }
        });
      });

      // Parse matches
      const lines = output.trim().split('\n').filter(l => l.trim());
      for (const line of lines) {
        if (line.startsWith('0x')) {
          continue;
        }
        const metaMatch = line.match(/^(?:meta:\s*)?\w+\s*=\s*.+$/);
        if (metaMatch) {
          continue;
        }
        const ruleMatch = line.match(/^(\w+)\s+(?:\[(.*?)\])?\s*(.+)$/);
        if (ruleMatch && ruleMatch[1]) {
          result.matches.push({
            rule: ruleMatch[1],
            tags: ruleMatch[2] ? ruleMatch[2].split(',').map(t => t.trim()) : [],
            meta: { source: 'reversinglabs', category: path.basename(path.dirname(ruleFile)) },
            strings: []
          });
        }
      }
    } catch (error) {
      // Continue with other rules on error
      logger.debug(`Error scanning with ${ruleFile}: ${error}`);
    }
  }

  return result;
}

/**
 * Main scan function with tiered rule support
 */
export async function scan(binaryPath: string, options: ScanOptions = {}): Promise<YaraScanResult> {
  const ruleSet = options.ruleSet || 'builtin';
  const results: YaraScanResult = {
    matches: [],
    rulesUsed: [],
    errors: []
  };

  // Handle custom rules path
  if (options.customRulesPath) {
    if (!fs.existsSync(options.customRulesPath)) {
      results.errors.push(`Custom rules file not found: ${options.customRulesPath}`);
      return results;
    }
    const customResult = await scanWithCustomRules(binaryPath, options.customRulesPath);
    results.matches.push(...customResult.matches);
    results.rulesUsed.push('custom');
    results.errors.push(...customResult.errors);
    return results;
  }

  // Handle different rule sets
  switch (ruleSet) {
    case 'builtin':
      return scanWithBuiltinRules(binaryPath);

    case 'reversinglabs':
      return scanWithRLRules(binaryPath);

    case 'all': {
      // Run builtin rules
      const builtinResult = await scanWithBuiltinRules(binaryPath);
      results.matches.push(...builtinResult.matches);
      results.rulesUsed.push(...builtinResult.rulesUsed);
      results.errors.push(...builtinResult.errors);

      // Run RL rules if available
      if (isRLRulesAvailable()) {
        const rlResult = await scanWithRLRules(binaryPath);
        results.matches.push(...rlResult.matches);
        results.rulesUsed.push(...rlResult.rulesUsed);
        results.errors.push(...rlResult.errors);
      }

      return results;
    }

    default:
      // Treat as custom rules path
      if (fs.existsSync(ruleSet)) {
        return scanWithCustomRules(binaryPath, ruleSet);
      }
      results.errors.push(`Unknown rule set: ${ruleSet}`);
      return results;
  }
}

/**
 * Get available rule sets
 */
export function getAvailableRuleSets(): { name: string; description: string; available: boolean; ruleCount?: number }[] {
  const sets = [
    {
      name: 'builtin',
      description: `Built-in technique detection rules (${BUILTIN_RULE_COUNT} rules)`,
      available: true,
      ruleCount: BUILTIN_RULE_COUNT
    },
    {
      name: 'reversinglabs',
      description: 'ReversingLabs malware family detection rules',
      available: isRLRulesAvailable(),
      ruleCount: getRLRuleFiles().length
    },
    {
      name: 'all',
      description: 'All available rules combined',
      available: true,
      ruleCount: BUILTIN_RULE_COUNT + (isRLRulesAvailable() ? getRLRuleFiles().length : 0)
    }
  ];

  return sets;
}

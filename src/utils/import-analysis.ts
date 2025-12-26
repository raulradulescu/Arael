export type ImportCapability =
  | 'Network'
  | 'Crypto'
  | 'FileIO'
  | 'Process'
  | 'Registry'
  | 'Memory'
  | 'Threading'
  | 'System'
  | 'UI'
  | 'AntiDebug'
  | 'Injection'
  | 'Persistence';

export interface CategorizedImport {
  name: string;
  library: string;
  capabilities: ImportCapability[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  description?: string;
}

export interface ImportAnalysisResult {
  categorizedImports: CategorizedImport[];
  capabilitySummary: Map<ImportCapability, number>;
  dangerousFunctions: CategorizedImport[];
  totalRiskScore: number;
}

/**
 * Categorize imports by their capabilities and risk level.
 */
export function categorizeImports(
  imports: Array<{ name: string; library: string }>
): ImportAnalysisResult {
  const categorized: CategorizedImport[] = [];
  const capabilitySummary = new Map<ImportCapability, number>();
  const dangerousFunctions: CategorizedImport[] = [];
  let totalRiskScore = 0;

  for (const imp of imports) {
    const categorizedImport = categorizeImport(imp.name, imp.library);

    if (categorizedImport) {
      categorized.push(categorizedImport);

      // Update capability summary
      for (const cap of categorizedImport.capabilities) {
        capabilitySummary.set(cap, (capabilitySummary.get(cap) ?? 0) + 1);
      }

      // Track dangerous functions
      if (categorizedImport.riskLevel === 'high' || categorizedImport.riskLevel === 'critical') {
        dangerousFunctions.push(categorizedImport);
      }

      // Add to risk score
      const riskScores = { low: 1, medium: 2, high: 5, critical: 10 };
      totalRiskScore += riskScores[categorizedImport.riskLevel];
    }
  }

  return {
    categorizedImports: categorized,
    capabilitySummary,
    dangerousFunctions,
    totalRiskScore
  };
}

/**
 * Categorize a single import function.
 */
function categorizeImport(name: string, library: string): CategorizedImport | null {
  const lowerName = name.toLowerCase();
  const lowerLib = library.toLowerCase();

  // Network functions
  if (isNetworkFunction(lowerName, lowerLib)) {
    return {
      name,
      library,
      capabilities: ['Network'],
      riskLevel: lowerName.includes('http') || lowerName.includes('url') ? 'high' : 'medium',
      description: 'Network communication'
    };
  }

  // Cryptography functions
  if (isCryptoFunction(lowerName, lowerLib)) {
    return {
      name,
      library,
      capabilities: ['Crypto'],
      riskLevel: 'medium',
      description: 'Cryptographic operations'
    };
  }

  // File I/O functions
  if (isFileIOFunction(lowerName, lowerLib)) {
    const riskLevel = lowerName.includes('delete') || lowerName.includes('write') ? 'medium' : 'low';
    return {
      name,
      library,
      capabilities: ['FileIO'],
      riskLevel,
      description: 'File system operations'
    };
  }

  // Process manipulation
  if (isProcessFunction(lowerName, lowerLib)) {
    const highRiskProcessKeywords = ['create', 'terminate', 'exec', 'system', 'popen'];
    const riskLevel = highRiskProcessKeywords.some((keyword) => lowerName.includes(keyword))
      ? 'high'
      : 'medium';
    return {
      name,
      library,
      capabilities: ['Process'],
      riskLevel,
      description: 'Process manipulation'
    };
  }

  // Registry functions (Windows)
  if (isRegistryFunction(lowerName, lowerLib)) {
    return {
      name,
      library,
      capabilities: ['Registry', 'Persistence'],
      riskLevel: 'high',
      description: 'Windows Registry access'
    };
  }

  // Memory manipulation
  if (isMemoryFunction(lowerName, lowerLib)) {
    const riskLevel =
      lowerName.includes('virtualalloc') ||
      lowerName.includes('virtualprotect') ||
      lowerName.includes('writeprocessmemory')
        ? 'critical'
        : 'medium';
    return {
      name,
      library,
      capabilities: ['Memory'],
      riskLevel,
      description: 'Memory manipulation'
    };
  }

  // Threading functions
  if (isThreadingFunction(lowerName, lowerLib)) {
    const riskLevel = lowerName.includes('remote') ? 'critical' : 'low';
    return {
      name,
      library,
      capabilities: ['Threading'],
      riskLevel,
      description: 'Thread management'
    };
  }

  // Anti-debugging functions
  if (isAntiDebugFunction(lowerName, lowerLib)) {
    return {
      name,
      library,
      capabilities: ['AntiDebug'],
      riskLevel: 'critical',
      description: 'Anti-debugging/analysis technique'
    };
  }

  // Code injection functions
  if (isInjectionFunction(lowerName, lowerLib)) {
    return {
      name,
      library,
      capabilities: ['Injection', 'Process'],
      riskLevel: 'critical',
      description: 'Code injection capability'
    };
  }

  // System information
  if (isSystemInfoFunction(lowerName, lowerLib)) {
    return {
      name,
      library,
      capabilities: ['System'],
      riskLevel: 'low',
      description: 'System information gathering'
    };
  }

  // UI functions
  if (isUIFunction(lowerName, lowerLib)) {
    return {
      name,
      library,
      capabilities: ['UI'],
      riskLevel: 'low',
      description: 'User interface'
    };
  }

  // Default: unknown function
  return {
    name,
    library,
    capabilities: [],
    riskLevel: 'low',
    description: 'Unknown function'
  };
}

function isNetworkFunction(name: string, lib: string): boolean {
  const networkKeywords = [
    'socket',
    'connect',
    'send',
    'recv',
    'http',
    'url',
    'inet',
    'ws2_32',
    'wininet',
    'winhttp',
    'internetopen',
    'internetconnect',
    'httpopen',
    'httpsend',
    'getaddrinfo',
    'gethostbyname',
    'bind',
    'listen',
    'accept'
  ];

  return (
    networkKeywords.some((kw) => name.includes(kw)) ||
    lib.includes('ws2_32') ||
    lib.includes('wininet') ||
    lib.includes('winhttp')
  );
}

function isCryptoFunction(name: string, lib: string): boolean {
  const cryptoKeywords = [
    'crypt',
    'encrypt',
    'decrypt',
    'hash',
    'md5',
    'sha',
    'aes',
    'rsa',
    'rc4',
    'des',
    'cipher',
    'bcrypt',
    'random'
  ];

  return (
    cryptoKeywords.some((kw) => name.includes(kw)) ||
    lib.includes('crypt') ||
    lib.includes('bcrypt')
  );
}

function isFileIOFunction(name: string, _lib: string): boolean {
  if (name.includes('process') || name.startsWith('reg')) {
    return false;
  }

  const fileKeywords = [
    'createfile',
    'openfile',
    'readfile',
    'writefile',
    'deletefile',
    'copyfile',
    'movefile',
    'findfirst',
    'findnext',
    'getfileattributes',
    'setfileattributes',
    'open',
    'read',
    'write',
    'close',
    'fopen',
    'fread',
    'fwrite',
    'fclose'
  ];

  return fileKeywords.some((kw) => name.includes(kw));
}

function isProcessFunction(name: string, _lib: string): boolean {
  const processKeywords = [
    'createprocess',
    'openprocess',
    'terminateprocess',
    'getprocaddress',
    'loadlibrary',
    'freelibrary',
    'getmodulehandle',
    'exitprocess',
    'process32first',
    'process32next',
    'createtoolhelp32snapshot',
    'fork',
    'exec',
    'system',
    'popen'
  ];

  return processKeywords.some((kw) => name.includes(kw));
}

function isRegistryFunction(name: string, _lib: string): boolean {
  const regKeywords = [
    'regopen',
    'regcreate',
    'regset',
    'regquery',
    'regdelete',
    'regclose',
    'regEnum'
  ];

  return regKeywords.some((kw) => name.includes(kw));
}

function isMemoryFunction(name: string, _lib: string): boolean {
  const memKeywords = [
    'virtualalloc',
    'virtualfree',
    'virtualprotect',
    'readprocessmemory',
    'writeprocessmemory',
    'malloc',
    'free',
    'heapalloc',
    'heapfree',
    'mmap',
    'munmap'
  ];

  return memKeywords.some((kw) => name.includes(kw));
}

function isThreadingFunction(name: string, _lib: string): boolean {
  const threadKeywords = [
    'createthread',
    'createremotethread',
    'openthread',
    'suspendthread',
    'resumethread',
    'terminatethread',
    'getthreadcontext',
    'setthreadcontext',
    'pthread_create',
    'pthread_join'
  ];

  return threadKeywords.some((kw) => name.includes(kw));
}

function isAntiDebugFunction(name: string, _lib: string): boolean {
  const antiDebugKeywords = [
    'isdebuggerpresent',
    'checkremotedebuggerpresent',
    'ntqueryinformationprocess',
    'outputdebugstring',
    'debugactiveprocess',
    'ptrace'
  ];

  return antiDebugKeywords.some((kw) => name.includes(kw));
}

function isInjectionFunction(name: string, _lib: string): boolean {
  const injectionKeywords = [
    'writeprocessmemory',
    'createremotethread',
    'ntcreatethread',
    'queueuserapc',
    'setwindowshookex',
    'virtualallocex',
    'setthreadcontext'
  ];

  return injectionKeywords.some((kw) => name.includes(kw));
}

function isSystemInfoFunction(name: string, _lib: string): boolean {
  const sysInfoKeywords = [
    'getsysteminfo',
    'getversion',
    'getversionex',
    'getcomputername',
    'getusername',
    'getsystemetrics',
    'uname',
    'sysctl'
  ];

  return sysInfoKeywords.some((kw) => name.includes(kw));
}

function isUIFunction(name: string, lib: string): boolean {
  const uiKeywords = [
    'createwindow',
    'showwindow',
    'messagebox',
    'dialogbox',
    'getmessage',
    'dispatchmessage',
    'gtk',
    'qt'
  ];

  return (
    uiKeywords.some((kw) => name.includes(kw)) ||
    lib.includes('user32') ||
    lib.includes('gdi32') ||
    lib.includes('gtk') ||
    lib.includes('qt')
  );
}

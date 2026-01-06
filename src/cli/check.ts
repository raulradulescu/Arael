#!/usr/bin/env node

/**
 * arael-check: Verify Arael installation and Ghidra connectivity
 */

import * as fs from 'fs';
import * as path from 'path';
import { GhidraBridge } from '../ghidra/bridge';
import { loadEnvFromFile } from '../utils/env';

loadEnvFromFile();

interface CheckResult {
  name: string;
  status: 'pass' | 'fail' | 'warn';
  message: string;
}

async function runChecks(): Promise<CheckResult[]> {
  const results: CheckResult[] = [];

  // Check Node.js version
  const nodeVersion = process.version;
  const majorVersion = parseInt(nodeVersion.slice(1).split('.')[0] ?? '0', 10);
  results.push({
    name: 'Node.js version',
    status: majorVersion >= 20 ? 'pass' : 'warn',
    message: `${nodeVersion} ${majorVersion >= 20 ? '(OK)' : '(recommended: 20+)'}`
  });

  // Check GHIDRA_PATH
  const ghidraPath = process.env['GHIDRA_PATH'];
  if (ghidraPath && fs.existsSync(ghidraPath)) {
    results.push({
      name: 'GHIDRA_PATH',
      status: 'pass',
      message: ghidraPath
    });

    // Check analyzeHeadless
    const isWindows = process.platform === 'win32';
    const headlessName = isWindows ? 'analyzeHeadless.bat' : 'analyzeHeadless';
    const headlessPath = path.join(ghidraPath, 'support', headlessName);

    if (fs.existsSync(headlessPath)) {
      results.push({
        name: 'analyzeHeadless',
        status: 'pass',
        message: 'Found'
      });
    } else {
      results.push({
        name: 'analyzeHeadless',
        status: 'fail',
        message: `Not found at ${headlessPath}`
      });
    }
  } else {
    results.push({
      name: 'GHIDRA_PATH',
      status: 'fail',
      message: ghidraPath ? 'Path does not exist' : 'Not set'
    });
    results.push({
      name: 'analyzeHeadless',
      status: 'fail',
      message: 'Cannot check (GHIDRA_PATH not set)'
    });
  }

  // Check Python
  const { execSync } = await import('child_process');
  const pythonCmd = process.env['ARAEL_PYTHON'] ?? (process.platform === 'win32' ? 'python' : 'python3');
  try {
    const pythonVersion = execSync(`"${pythonCmd}" --version`, { encoding: 'utf-8' }).trim();
    results.push({
      name: 'Python 3',
      status: 'pass',
      message: `${pythonVersion} (${pythonCmd})`
    });

    // Check pyghidra
    try {
      execSync(`"${pythonCmd}" -c "import pyghidra"`, { encoding: 'utf-8' });
      results.push({
        name: 'pyghidra',
        status: 'pass',
        message: 'Installed'
      });
    } catch {
      results.push({
        name: 'pyghidra',
        status: 'warn',
        message: 'Not installed (run: pip install pyghidra)'
      });
    }

    // Check ghidra-bridge (optional)
    try {
      execSync(`"${pythonCmd}" -c "import ghidra_bridge"`, { encoding: 'utf-8' });
      results.push({
        name: 'ghidra-bridge',
        status: 'pass',
        message: 'Installed (optional)'
      });
    } catch {
      results.push({
        name: 'ghidra-bridge',
        status: 'warn',
        message: 'Not installed (optional, for bridge mode)'
      });
    }
  } catch {
    results.push({
      name: 'Python 3',
      status: 'fail',
      message: `Not found (tried: ${pythonCmd})`
    });
    results.push({
      name: 'pyghidra',
      status: 'fail',
      message: 'Cannot check (Python not available)'
    });
    results.push({
      name: 'ghidra-bridge',
      status: 'fail',
      message: 'Cannot check (Python not available)'
    });
  }

  // Check Java
  try {
    const javaVersion = execSync('java -version 2>&1', { encoding: 'utf-8' });
    const versionMatch = javaVersion.match(/version "([^"]+)"/);
    results.push({
      name: 'Java',
      status: 'pass',
      message: versionMatch?.[1] ?? 'Found'
    });
  } catch {
    results.push({
      name: 'Java',
      status: 'fail',
      message: 'Not found (required by Ghidra)'
    });
  }

  // Try to connect to ghidra-bridge
  const bridge = new GhidraBridge();
  try {
    const available = await bridge.isAvailable();
    results.push({
      name: 'ghidra-bridge server',
      status: available ? 'pass' : 'warn',
      message: available ? 'Connected' : 'Not running (start Ghidra with bridge server)'
    });
  } catch {
    results.push({
      name: 'ghidra-bridge server',
      status: 'warn',
      message: 'Not running'
    });
  }

  return results;
}

async function main(): Promise<void> {
  console.log('Arael Installation Check\n');
  console.log('='.repeat(50));

  const results = await runChecks();

  let hasErrors = false;
  for (const result of results) {
    const icon = result.status === 'pass' ? '✓' : result.status === 'warn' ? '!' : '✗';
    const color = result.status === 'pass' ? '\x1b[32m' : result.status === 'warn' ? '\x1b[33m' : '\x1b[31m';
    const reset = '\x1b[0m';

    console.log(`${color}${icon}${reset} ${result.name}: ${result.message}`);

    if (result.status === 'fail') {
      hasErrors = true;
    }
  }

  console.log('\n' + '='.repeat(50));

  if (hasErrors) {
    console.log('\n⚠️  Some checks failed. See TROUBLESHOOTING.md for help.\n');
    process.exit(1);
  } else {
    console.log('\n✓ All checks passed. Arael is ready to use.\n');
  }
}

main().catch((error) => {
  console.error(`Check failed: ${error}`);
  process.exit(1);
});

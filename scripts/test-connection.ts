#!/usr/bin/env npx ts-node

/**
 * test-connection.ts - Verify Ghidra connectivity for Phase 1 success gate
 *
 * Usage: npx ts-node scripts/test-connection.ts
 *
 * Success criteria:
 * - Can reach Ghidra via bridge OR headless mode
 * - Returns exit code 0 on success, 1 on failure
 */

import { loadEnvFromFile } from '../src/utils/env';
import { GhidraBridge } from '../src/ghidra/bridge';
import { GhidraHeadless } from '../src/ghidra/headless';

loadEnvFromFile();

interface ConnectionTestResult {
  mode: 'bridge' | 'headless' | 'none';
  success: boolean;
  message: string;
  latencyMs?: number;
}

async function testBridgeConnection(): Promise<ConnectionTestResult> {
  const bridge = new GhidraBridge();
  const startTime = Date.now();

  try {
    const available = await bridge.isAvailable();
    const latencyMs = Date.now() - startTime;

    if (available) {
      return {
        mode: 'bridge',
        success: true,
        message: `Connected to ghidra-bridge on localhost:4768`,
        latencyMs
      };
    } else {
      return {
        mode: 'bridge',
        success: false,
        message: 'Bridge server not responding'
      };
    }
  } catch (error) {
    return {
      mode: 'bridge',
      success: false,
      message: `Bridge connection failed: ${error instanceof Error ? error.message : error}`
    };
  }
}

async function testHeadlessConnection(): Promise<ConnectionTestResult> {
  const ghidraPath = process.env['GHIDRA_PATH'];

  if (!ghidraPath) {
    return {
      mode: 'headless',
      success: false,
      message: 'GHIDRA_PATH environment variable not set'
    };
  }

  const headless = new GhidraHeadless({ ghidraPath });

  const availabilityError = headless.getAvailabilityError();
  if (availabilityError) {
    return {
      mode: 'headless',
      success: false,
      message: availabilityError
    };
  }

  return {
    mode: 'headless',
    success: true,
    message: `Ghidra headless available at ${ghidraPath}`
  };
}

async function main(): Promise<void> {
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║           Arael Connection Test (Phase 1 Gate)               ║');
  console.log('╚══════════════════════════════════════════════════════════════╝');
  console.log('');

  // Test bridge connection
  console.log('Testing ghidra-bridge connection...');
  const bridgeResult = await testBridgeConnection();

  const bridgeIcon = bridgeResult.success ? '✓' : '✗';
  const bridgeColor = bridgeResult.success ? '\x1b[32m' : '\x1b[31m';
  const reset = '\x1b[0m';

  console.log(`${bridgeColor}${bridgeIcon}${reset} Bridge: ${bridgeResult.message}`);
  if (bridgeResult.latencyMs !== undefined) {
    console.log(`  Latency: ${bridgeResult.latencyMs}ms`);
  }
  console.log('');

  // Test headless connection
  console.log('Testing Ghidra headless availability...');
  const headlessResult = await testHeadlessConnection();

  const headlessIcon = headlessResult.success ? '✓' : '✗';
  const headlessColor = headlessResult.success ? '\x1b[32m' : '\x1b[31m';

  console.log(`${headlessColor}${headlessIcon}${reset} Headless: ${headlessResult.message}`);
  console.log('');

  // Summary
  console.log('─'.repeat(64));

  if (bridgeResult.success || headlessResult.success) {
    const preferredMode = bridgeResult.success ? 'bridge' : 'headless';
    console.log(`\x1b[32m✓ SUCCESS\x1b[0m: Ghidra connection available via ${preferredMode} mode`);
    console.log('');
    console.log('Phase 1 connection gate: PASSED');

    if (bridgeResult.success) {
      console.log('');
      console.log('Tip: Bridge mode provides ~100ms query latency vs 15-60s for headless.');
    }

    process.exit(0);
  } else {
    console.log('\x1b[31m✗ FAILURE\x1b[0m: No Ghidra connection available');
    console.log('');
    console.log('To fix:');
    console.log('  1. Start Ghidra with bridge server:');
    console.log('     ./scripts/start-ghidra-bridge.sh');
    console.log('');
    console.log('  OR');
    console.log('');
    console.log('  2. Set GHIDRA_PATH environment variable:');
    console.log('     export GHIDRA_PATH=/path/to/ghidra_11.0_PUBLIC');
    console.log('');
    console.log('See docs/TROUBLESHOOTING.md for more help.');

    process.exit(1);
  }
}

main().catch((error) => {
  console.error(`Test failed with error: ${error}`);
  process.exit(1);
});

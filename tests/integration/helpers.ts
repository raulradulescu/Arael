import * as fs from 'fs';
import * as path from 'path';
import { GhidraHeadless } from '../../src/ghidra/headless';
import { loadEnvFromFile } from '../../src/utils/env';

// Load .env file FIRST before reading environment variables
loadEnvFromFile();

const ghidraPath = process.env['GHIDRA_PATH'];
const bridgeConfigured = Boolean(
  process.env['GHIDRA_BRIDGE_HOST'] ||
  process.env['GHIDRA_BRIDGE_PORT'] ||
  process.env['ARAEL_FORCE_BRIDGE']
);
const forceIntegration = process.env['ARAEL_FORCE_INTEGRATION'] === '1';
const headlessAvailable = ghidraPath ? new GhidraHeadless({ ghidraPath }).isAvailable() : false;

export const integrationAvailable = forceIntegration || headlessAvailable || bridgeConfigured;
export const describeOrSkip = integrationAvailable ? describe : describe.skip;

export const fixturesDir = path.join(__dirname, '../fixtures');
export const testBinary = path.join(fixturesDir, 'hello_world');

export function hasTestBinary(): boolean {
  return fs.existsSync(testBinary);
}

export function integrationSkipReason(): string {
  if (forceIntegration) {
    return 'force integration enabled';
  }
  if (bridgeConfigured) {
    return 'bridge configured but not detected as available';
  }
  if (ghidraPath && !headlessAvailable) {
    return 'headless runtime not available at GHIDRA_PATH';
  }
  return 'no Ghidra connection configured';
}

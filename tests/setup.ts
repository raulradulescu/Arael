/**
 * Jest setup file
 */

import { loadEnvFromFile } from '../src/utils/env';

loadEnvFromFile();

// Increase timeout for integration tests
jest.setTimeout(60000);

// Suppress console output during tests unless DEBUG is set
if (!process.env['DEBUG']) {
  global.console = {
    ...console,
    log: jest.fn(),
    debug: jest.fn(),
    info: jest.fn(),
    // Keep warn and error for test visibility
    warn: console.warn,
    error: console.error
  };
}

// Set default environment variables for tests
process.env['GHIDRA_VERSION'] = 'test';
process.env['NODE_ENV'] = 'test';

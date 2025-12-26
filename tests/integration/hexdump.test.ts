/**
 * Integration tests for arael_hexdump tool
 */

import { hexdumpHandler } from '../../src/mcp/handlers/hexdump';
import {
  describeOrSkip,
  hasTestBinary,
  integrationAvailable,
  integrationSkipReason,
  testBinary
} from './helpers';

describeOrSkip('arael_hexdump (integration)', () => {
  it('should return formatted hexdump output', async () => {
    if (!hasTestBinary()) {
      console.warn('Skipping: test binary not found');
      return;
    }

    const result = await hexdumpHandler({
      filepath: testBinary,
      start: '0x0',
      length: 64,
      width: 16
    });

    expect(result.formatted).toContain('|');
    expect(result.length).toBeGreaterThan(0);
  });
});

if (!integrationAvailable) {
  describe('arael_hexdump (integration)', () => {
    it.skip(`SKIPPED: ${integrationSkipReason()}`, () => {});
  });
}

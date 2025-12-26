import { StringInfo } from '../output/schema';
import { runCommand } from './system';

export interface SystemStringsOptions {
  minLength?: number;
  encoding?: 'ascii' | 'utf8' | 'utf16le' | 'all';
  pattern?: string;
}

function encodingToFlag(encoding: 'ascii' | 'utf8' | 'utf16le'): string {
  switch (encoding) {
    case 'utf16le':
      return 'l';
    case 'utf8':
      return 'S';
    case 'ascii':
    default:
      return 's';
  }
}

function parseStringsOutput(output: string, encoding: StringInfo['encoding']): StringInfo[] {
  const lines = output.split(/\r?\n/);
  const results: StringInfo[] = [];

  for (const line of lines) {
    if (!line.trim()) {
      continue;
    }

    const match = line.match(/^([0-9a-fA-F]+)\s+(.*)$/);
    let value = line;
    let address = '0x0';

    if (match) {
      address = `0x${match[1]!.toLowerCase()}`;
      value = match[2] ?? '';
    }

    if (!value) {
      continue;
    }

    results.push({
      address,
      value,
      length: value.length,
      encoding,
      xrefs: []
    });
  }

  return results;
}

export async function extractStringsWithSystemTool(
  filepath: string,
  options: SystemStringsOptions = {}
): Promise<StringInfo[]> {
  const minLength = options.minLength ?? 4;
  const encoding = options.encoding ?? 'all';
  const pattern = options.pattern?.trim();

  const args = ['-n', String(minLength), '-t', 'x'];
  if (encoding !== 'all') {
    args.push('-e', encodingToFlag(encoding));
  }
  args.push(filepath);

  const primary = await runCommand('strings', args);
  let output = primary.stdout;

  if (primary.code !== 0 || !output.trim()) {
    const fallback = await runCommand('strings', [filepath]);
    output = fallback.stdout;
  }

  const normalizedEncoding: StringInfo['encoding'] =
    encoding === 'all' ? 'ascii' : encoding;

  if (pattern) {
    try {
      const grepResult = await runCommand('grep', ['-E', pattern], { input: output });
      if (grepResult.code > 1) {
        throw new Error(grepResult.stderr || 'grep failed');
      }
      output = grepResult.stdout;
    } catch {
      let regex: RegExp;
      try {
        regex = new RegExp(pattern);
      } catch {
        throw new Error(`Invalid grep pattern: ${pattern}`);
      }

      return parseStringsOutput(output, normalizedEncoding)
        .filter((item) => item.length >= minLength)
        .filter((item) => regex.test(item.value));
    }
  }

  return parseStringsOutput(output, normalizedEncoding)
    .filter((item) => item.length >= minLength);
}

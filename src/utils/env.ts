import * as fs from 'fs';
import * as path from 'path';

type EnvSection = 'default' | 'wsl' | 'windows';

interface ParsedEnvSections {
  default: Record<string, string>;
  wsl: Record<string, string>;
  windows: Record<string, string>;
}

function detectWsl(): boolean {
  if (process.platform !== 'linux') {
    return false;
  }

  if (process.env['WSL_DISTRO_NAME'] || process.env['WSL_INTEROP'] || process.env['WSLENV']) {
    return true;
  }

  try {
    const version = fs.readFileSync('/proc/version', 'utf-8').toLowerCase();
    return version.includes('microsoft');
  } catch {
    return false;
  }
}

function parseEnvSections(contents: string): ParsedEnvSections {
  const sections: ParsedEnvSections = {
    default: {},
    wsl: {},
    windows: {}
  };

  let current: EnvSection = 'default';

  for (const rawLine of contents.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) {
      continue;
    }

    if (line.startsWith('#')) {
      const label = line.slice(1).trim().toLowerCase();
      if (label === 'wsl') {
        current = 'wsl';
      } else if (label === 'windows') {
        current = 'windows';
      }
      continue;
    }

    const normalized = line.startsWith('export ') ? line.slice(7).trim() : line;
    const eqIndex = normalized.indexOf('=');
    if (eqIndex <= 0) {
      continue;
    }

    const key = normalized.slice(0, eqIndex).trim();
    let value = normalized.slice(eqIndex + 1).trim();

    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    if (key) {
      sections[current][key] = value;
    }
  }

  return sections;
}

export function loadEnvFromFile(envPath = path.resolve(process.cwd(), '.env')): void {
  if (!fs.existsSync(envPath)) {
    return;
  }

  const contents = fs.readFileSync(envPath, 'utf-8');
  const sections = parseEnvSections(contents);

  const selected: EnvSection = process.platform === 'win32'
    ? 'windows'
    : detectWsl()
      ? 'wsl'
      : 'default';

  const merged = {
    ...sections.default,
    ...sections[selected]
  };

  for (const [key, value] of Object.entries(merged)) {
    if (process.env[key] === undefined) {
      process.env[key] = value;
    }
  }
}

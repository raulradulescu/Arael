import * as fs from 'fs';
import * as path from 'path';
import { spawn } from 'child_process';

function isExecutable(filePath: string): boolean {
  if (process.platform === 'win32') {
    return fs.existsSync(filePath);
  }

  try {
    fs.accessSync(filePath, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

export function findCommand(command: string): string | null {
  if (command.includes(path.sep) || command.includes('/')) {
    return isExecutable(command) ? command : null;
  }

  const envPath = process.env['PATH'] ?? '';
  const pathEntries = envPath.split(path.delimiter).filter(Boolean);
  const extensions = process.platform === 'win32'
    ? (process.env['PATHEXT']?.split(';') ?? ['.EXE', '.CMD', '.BAT'])
    : [''];

  for (const entry of pathEntries) {
    for (const ext of extensions) {
      const candidate = path.join(entry, command + ext);
      if (isExecutable(candidate)) {
        return candidate;
      }
    }
  }

  return null;
}

export function runCommand(
  command: string,
  args: string[],
  options: { cwd?: string; input?: string } = {}
): Promise<{ stdout: string; stderr: string; code: number }> {
  const resolved = findCommand(command);
  if (!resolved) {
    return Promise.reject(new Error(`Command not found: ${command}`));
  }

  return new Promise((resolve, reject) => {
    const proc = spawn(resolved, args, {
      cwd: options.cwd,
      env: process.env
    });

    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (data: Buffer) => {
      stdout += data.toString();
    });

    proc.stderr.on('data', (data: Buffer) => {
      stderr += data.toString();
    });

    if (options.input !== undefined) {
      if (proc.stdin) {
        proc.stdin.write(options.input);
        proc.stdin.end();
      }
    }

    proc.on('close', (code) => {
      resolve({
        stdout,
        stderr,
        code: code ?? 0
      });
    });

    proc.on('error', (error) => {
      reject(error);
    });
  });
}

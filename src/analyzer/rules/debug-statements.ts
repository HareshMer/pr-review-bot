import { Finding } from './secret-scanner.js';
import { DiffBoundaryMap } from '../../github/diff-parser.js';

interface DebugPattern {
  name: string;
  regex: RegExp;
  ruleId: string;
  extensions?: string[];
  message: string;
}

const DEBUG_PATTERNS: DebugPattern[] = [
  {
    name: 'JavaScript Debugger Statement',
    regex: /^\s*debugger\s*;?/,
    ruleId: 'debug-js-debugger',
    extensions: ['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'],
    message: 'Remove `debugger;` statement before merging to prevent runtime pause in production.'
  },
  {
    name: 'Console Debug Log',
    regex: /^\s*console\.(log|debug|dir)\s*\(/,
    ruleId: 'debug-console-log',
    extensions: ['.js', '.jsx', '.ts', '.tsx'],
    message: 'Remove extraneous `console.log` statement or replace with a structured logger (e.g., Pino).'
  },
  {
    name: 'Python Breakpoint / Print',
    regex: /^\s*(breakpoint\(\)|import\s+pdb;\s*pdb\.set_trace\(\))/,
    ruleId: 'debug-python-breakpoint',
    extensions: ['.py'],
    message: 'Remove interactive debug breakpoint before merging.'
  }
];

export class DebugStatementsRule {
  public scan(boundaryMap: DiffBoundaryMap): Finding[] {
    const findings: Finding[] = [];

    for (const parsedFile of boundaryMap.parsedFiles) {
      const filePath = parsedFile.to || parsedFile.from;
      if (!filePath) continue;

      const fileExt = this.getFileExtension(filePath);

      for (const chunk of parsedFile.chunks) {
        for (const change of chunk.changes) {
          if (change.type === 'add' && change.ln) {
            // Strip leading '+'
            const lineText = change.content.startsWith('+') ? change.content.slice(1) : change.content;

            for (const pattern of DEBUG_PATTERNS) {
              if (pattern.extensions && !pattern.extensions.includes(fileExt)) {
                continue;
              }

              // Suppress console.log in test files and CLI scripts
              if (pattern.ruleId === 'debug-console-log' && this.isExemptFromConsoleLogging(filePath)) {
                continue;
              }

              if (pattern.regex.test(lineText)) {
                findings.push({
                  path: filePath,
                  line: change.ln,
                  severity: 'SUGGESTION',
                  category: 'BEST_PRACTICE',
                  title: `Debug Artifact: ${pattern.name}`,
                  message: pattern.message,
                  source: 'RULE',
                  ruleId: pattern.ruleId
                });
                break;
              }
            }
          }
        }
      }
    }

    return findings;
  }

  private isExemptFromConsoleLogging(filePath: string): boolean {
    const normalized = filePath.replace(/\\/g, '/').toLowerCase();
    // Test files
    if (
      normalized.includes('/tests/') ||
      normalized.includes('/test/') ||
      normalized.includes('/__tests__/') ||
      normalized.endsWith('.test.ts') ||
      normalized.endsWith('.test.js') ||
      normalized.endsWith('.spec.ts') ||
      normalized.endsWith('.spec.js')
    ) {
      return true;
    }
    // CLI & build scripts
    if (
      normalized.startsWith('scripts/') ||
      normalized.includes('/scripts/') ||
      normalized.startsWith('bin/') ||
      normalized.includes('/bin/') ||
      normalized.endsWith('/cli.ts') ||
      normalized.endsWith('/cli.js') ||
      normalized === 'cli.ts' ||
      normalized === 'cli.js'
    ) {
      return true;
    }
    return false;
  }

  private getFileExtension(filename: string): string {
    const lastDot = filename.lastIndexOf('.');
    if (lastDot === -1) return '';
    return filename.slice(lastDot).toLowerCase();
  }
}

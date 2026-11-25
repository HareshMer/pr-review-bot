import { DiffBoundaryMap } from '../../github/diff-parser.js';
import { Finding } from './secret-scanner.js';

export type BannedModuleClassification =
  | 'CONFIRMED_PROHIBITED'
  | 'HISTORICAL_SUPPLY_CHAIN_RISK'
  | 'CONTEXTUALLY_DANGEROUS_API'
  | 'DEPRECATED_LIBRARY'
  | 'MAINTAINABILITY_SUGGESTION';

export interface BannedModuleRule {
  moduleName: string;
  matchSubpaths: boolean;
  severity: 'CRITICAL' | 'WARNING' | 'SUGGESTION';
  category: 'SECURITY' | 'BEST_PRACTICE';
  ruleId: string;
  classification: BannedModuleClassification;
  title: string;
  message: string;
  suggestion?: string;
}

export const BANNED_MODULE_CATALOG: BannedModuleRule[] = [
  {
    moduleName: 'flatmap-stream',
    matchSubpaths: true,
    severity: 'CRITICAL',
    category: 'SECURITY',
    ruleId: 'import-prohibited-flatmap-stream',
    classification: 'CONFIRMED_PROHIBITED',
    title: 'Prohibited Malicious Module: flatmap-stream',
    message: 'Prohibited malicious package flatmap-stream detected. This package was created solely for malicious payload injection and must be removed immediately.'
  },
  {
    moduleName: 'event-stream',
    matchSubpaths: true,
    severity: 'WARNING',
    category: 'SECURITY',
    ruleId: 'import-supply-chain-event-stream',
    classification: 'HISTORICAL_SUPPLY_CHAIN_RISK',
    title: 'Supply Chain Risk: event-stream',
    message: 'Package event-stream carries historical supply-chain vulnerability risks (v3.3.6 compromise). Audit lockfile to ensure dependency integrity.'
  },
  {
    moduleName: 'node-ipc',
    matchSubpaths: true,
    severity: 'WARNING',
    category: 'SECURITY',
    ruleId: 'import-supply-chain-node-ipc',
    classification: 'HISTORICAL_SUPPLY_CHAIN_RISK',
    title: 'Supply Chain Risk: node-ipc',
    message: 'Package node-ipc carries historical supply-chain risk (protestware payload in v10.1.1-10.1.2). Audit lockfile to verify safe version.'
  },
  {
    moduleName: 'child_process',
    matchSubpaths: true,
    severity: 'WARNING',
    category: 'SECURITY',
    ruleId: 'import-dangerous-child-process',
    classification: 'CONTEXTUALLY_DANGEROUS_API',
    title: 'Contextually Dangerous Module: child_process',
    message: 'Contextually dangerous execution module child_process imported. Ensure command strings are never constructed from unsanitized user inputs to prevent Command Injection (RCE). Banned in client/browser bundles.'
  },
  {
    moduleName: 'vm',
    matchSubpaths: true,
    severity: 'WARNING',
    category: 'SECURITY',
    ruleId: 'import-dangerous-vm',
    classification: 'CONTEXTUALLY_DANGEROUS_API',
    title: 'Contextually Dangerous Module: vm',
    message: 'Contextually dangerous module vm imported. Node.js vm contexts are not secure sandboxes and can be escaped. Avoid running untrusted code.'
  },
  {
    moduleName: 'crypto-js',
    matchSubpaths: true,
    severity: 'WARNING',
    category: 'SECURITY',
    ruleId: 'import-dangerous-crypto-js',
    classification: 'CONTEXTUALLY_DANGEROUS_API',
    title: 'Contextually Risky Module: crypto-js',
    message: 'Module crypto-js imported. Often misused with insecure ECB defaults or weak ciphers. Recommend native Node.js crypto module or Web Crypto API.',
    suggestion: "import crypto from 'node:crypto';"
  },
  {
    moduleName: 'request',
    matchSubpaths: true,
    severity: 'SUGGESTION',
    category: 'BEST_PRACTICE',
    ruleId: 'import-deprecated-request',
    classification: 'DEPRECATED_LIBRARY',
    title: 'Deprecated Library: request',
    message: 'Deprecated HTTP library request imported. The request library was officially deprecated in 2020. Migrate to native fetch, undici, or axios.',
    suggestion: "import fetch from 'node-fetch';"
  },
  {
    moduleName: 'moment',
    matchSubpaths: true,
    severity: 'SUGGESTION',
    category: 'BEST_PRACTICE',
    ruleId: 'import-maintainability-moment',
    classification: 'MAINTAINABILITY_SUGGESTION',
    title: 'Maintainability Concern: moment',
    message: 'Legacy date library moment imported. Moment.js is in maintenance mode and introduces significant bundle size overhead. Consider date-fns, dayjs, or native Intl.',
    suggestion: "import { format } from 'date-fns';"
  },
  {
    moduleName: 'lodash',
    matchSubpaths: false, // Root import only! Cherry-picked subpaths (e.g. lodash/debounce) are permitted.
    severity: 'SUGGESTION',
    category: 'BEST_PRACTICE',
    ruleId: 'import-maintainability-lodash',
    classification: 'MAINTAINABILITY_SUGGESTION',
    title: 'Bundle Bloat Concern: Root lodash import',
    message: 'Root lodash import detected. Importing root lodash inflates bundle size. Use cherry-picked subpath imports (e.g. lodash/debounce) or native ES6+ methods.',
    suggestion: "import debounce from 'lodash/debounce';"
  }
];

const SUPPORTED_EXTENSIONS = new Set([
  '.js',
  '.jsx',
  '.ts',
  '.tsx',
  '.mjs',
  '.cjs',
  '.vue',
  '.svelte'
]);

interface ExtractedImport {
  specifier: string;
  line: number;
}

export class BannedImportsRule {
  constructor(private catalog: BannedModuleRule[] = BANNED_MODULE_CATALOG) { }

  public scan(boundaryMap: DiffBoundaryMap): Finding[] {
    const findings: Finding[] = [];

    for (const parsedFile of boundaryMap.parsedFiles) {
      const filePath = parsedFile.to || parsedFile.from;
      if (!filePath) continue;

      const ext = this.getFileExtension(filePath);
      if (!SUPPORTED_EXTENSIONS.has(ext)) {
        continue;
      }

      // Extract all imports from added lines using stateful lexical tokenization
      const imports = this.extractImportsFromDiff(parsedFile);

      for (const imp of imports) {
        const matchedRule = this.matchRule(imp.specifier);
        if (matchedRule) {
          findings.push({
            path: filePath,
            line: imp.line,
            severity: matchedRule.severity,
            category: matchedRule.category,
            title: matchedRule.title,
            message: matchedRule.message,
            suggestion: matchedRule.suggestion,
            source: 'RULE',
            ruleId: matchedRule.ruleId
          });
        }
      }
    }

    return findings;
  }

  /**
   * Stateful lexical tokenizer running across diff chunks.
   * Tracks syntax across context lines while strictly emitting findings ONLY on added lines.
   */
  private extractImportsFromDiff(parsedFile: any): ExtractedImport[] {
    const extracted: ExtractedImport[] = [];

    let inBlockComment = false;
    let pendingImportOrExport: 'import' | 'export' | null = null;
    let pendingFrom = false;
    let importStartLine = 0;
    let importHasAddedLines = false;

    for (const chunk of parsedFile.chunks) {
      for (const change of chunk.changes) {
        // Deleted lines are completely skipped: they must never advance line numbers or trigger findings
        if (change.type === 'del') {
          continue;
        }

        const currentLineNum = change.type === 'add' ? change.ln : change.ln2;
        if (!currentLineNum) continue;

        const isAdd = change.type === 'add';
        const rawContent = change.content;
        const lineContent = rawContent.startsWith('+') || rawContent.startsWith(' ')
          ? rawContent.slice(1)
          : rawContent;

        let idx = 0;
        const len = lineContent.length;

        while (idx < len) {
          // 1. Skip Block Comments
          if (inBlockComment) {
            const endIdx = lineContent.indexOf('*/', idx);
            if (endIdx === -1) {
              idx = len; // Remainder of line is in block comment
            } else {
              idx = endIdx + 2;
              inBlockComment = false;
            }
            continue;
          }

          // 2. Skip Whitespace
          while (idx < len && /\s/.test(lineContent[idx])) {
            idx++;
          }
          if (idx >= len) break;

          // 3. Check for Single-Line or Block Comment Start
          if (lineContent[idx] === '/' && idx + 1 < len) {
            if (lineContent[idx + 1] === '/') {
              break; // Rest of line is comment
            }
            if (lineContent[idx + 1] === '*') {
              inBlockComment = true;
              idx += 2;
              continue;
            }
          }

          // 4. Skip String Literals (unless we are expecting an import/from specifier)
          if (lineContent[idx] === "'" || lineContent[idx] === '"' || lineContent[idx] === '`') {
            const quote = lineContent[idx];
            const startQuoteIdx = idx;
            idx++;
            let strVal = '';
            let escaped = false;
            let isDynamicTemplate = false;

            while (idx < len) {
              const char = lineContent[idx];
              if (escaped) {
                strVal += char;
                escaped = false;
                idx++;
                continue;
              }
              if (char === '\\') {
                escaped = true;
                idx++;
                continue;
              }
              if (quote === '`' && char === '$' && idx + 1 < len && lineContent[idx + 1] === '{') {
                isDynamicTemplate = true;
                break;
              }
              if (char === quote) {
                idx++; // past closing quote
                break;
              }
              strVal += char;
              idx++;
            }

            // If template literal contains ${...}, it is dynamic: ignore
            if (isDynamicTemplate) {
              pendingImportOrExport = null;
              pendingFrom = false;
              continue;
            }

            // Check if this string literal is an import specifier!
            const isTargetSpecifier = (pendingImportOrExport === 'import' && (pendingFrom || !lineContent.slice(0, startQuoteIdx).includes('{'))) ||
              (pendingImportOrExport === 'export' && pendingFrom);

            if (isTargetSpecifier && strVal.length > 0) {
              if (isAdd || importHasAddedLines) {
                extracted.push({
                  specifier: strVal,
                  line: isAdd ? currentLineNum : importStartLine
                });
              }
              pendingImportOrExport = null;
              pendingFrom = false;
              importHasAddedLines = false;
            }

            continue;
          }

          // 5. Read Identifiers / Keywords
          if (/[a-zA-Z0-9_$]/.test(lineContent[idx])) {
            const startWordIdx = idx;
            while (idx < len && /[a-zA-Z0-9_$]/.test(lineContent[idx])) {
              idx++;
            }
            const word = lineContent.slice(startWordIdx, idx);

            // Handle require("pkg")
            if (word === 'require') {
              let afterIdx = idx;
              while (afterIdx < len && /\s/.test(lineContent[afterIdx])) afterIdx++;
              if (afterIdx < len && lineContent[afterIdx] === '(') {
                afterIdx++;
                while (afterIdx < len && /\s/.test(lineContent[afterIdx])) afterIdx++;
                if (afterIdx < len && (lineContent[afterIdx] === "'" || lineContent[afterIdx] === '"')) {
                  const reqQuote = lineContent[afterIdx];
                  afterIdx++;
                  let reqStr = '';
                  while (afterIdx < len && lineContent[afterIdx] !== reqQuote) {
                    reqStr += lineContent[afterIdx];
                    afterIdx++;
                  }
                  if (afterIdx < len && lineContent[afterIdx] === reqQuote && reqStr.length > 0) {
                    if (isAdd) {
                      extracted.push({ specifier: reqStr, line: currentLineNum });
                    }
                    idx = afterIdx + 1;
                    continue;
                  }
                }
              }
            }

            // Handle dynamic import("pkg")
            if (word === 'import') {
              let afterIdx = idx;
              while (afterIdx < len && /\s/.test(lineContent[afterIdx])) afterIdx++;
              if (afterIdx < len && lineContent[afterIdx] === '(') {
                afterIdx++;
                while (afterIdx < len && /\s/.test(lineContent[afterIdx])) afterIdx++;
                if (afterIdx < len && (lineContent[afterIdx] === "'" || lineContent[afterIdx] === '"')) {
                  const impQuote = lineContent[afterIdx];
                  afterIdx++;
                  let impStr = '';
                  while (afterIdx < len && lineContent[afterIdx] !== impQuote) {
                    impStr += lineContent[afterIdx];
                    afterIdx++;
                  }
                  if (afterIdx < len && lineContent[afterIdx] === impQuote && impStr.length > 0) {
                    if (isAdd) {
                      extracted.push({ specifier: impStr, line: currentLineNum });
                    }
                    idx = afterIdx + 1;
                    continue;
                  }
                }
              }
            }

            if (word === 'import') {
              pendingImportOrExport = 'import';
              importStartLine = currentLineNum;
              if (isAdd) importHasAddedLines = true;
            } else if (word === 'export') {
              pendingImportOrExport = 'export';
              importStartLine = currentLineNum;
              if (isAdd) importHasAddedLines = true;
            } else if (word === 'from' && pendingImportOrExport !== null) {
              pendingFrom = true;
              if (isAdd) importHasAddedLines = true;
            } else if (pendingImportOrExport !== null && isAdd) {
              importHasAddedLines = true;
            }

            continue;
          }

          // 6. Statement Terminator
          if (lineContent[idx] === ';') {
            pendingImportOrExport = null;
            pendingFrom = false;
            importHasAddedLines = false;
          }

          idx++;
        }
      }
    }

    return extracted;
  }

  /**
   * Matches a module specifier against the banned module catalog.
   */
  private matchRule(specifier: string): BannedModuleRule | null {
    if (!specifier || specifier.startsWith('.') || specifier.startsWith('/')) {
      return null; // Ignore relative or absolute local filesystem paths
    }

    const normalized = specifier.trim();
    // Resolve root package name (e.g. '@scope/pkg/sub' -> '@scope/pkg'; 'lodash/get' -> 'lodash')
    const rootPkg = normalized.startsWith('@')
      ? normalized.split('/').slice(0, 2).join('/')
      : normalized.split('/')[0];

    for (const rule of this.catalog) {
      if (rule.matchSubpaths) {
        if (normalized === rule.moduleName || normalized.startsWith(`${rule.moduleName}/`) || rootPkg === rule.moduleName) {
          return rule;
        }
      } else {
        // Exact root match only (e.g. lodash root vs lodash/debounce)
        if (normalized === rule.moduleName) {
          return rule;
        }
      }
    }

    return null;
  }

  private getFileExtension(filename: string): string {
    const lastDot = filename.lastIndexOf('.');
    if (lastDot === -1) return '';
    return filename.slice(lastDot).toLowerCase();
  }
}


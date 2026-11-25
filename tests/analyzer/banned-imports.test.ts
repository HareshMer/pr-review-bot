import { describe, it, expect } from 'vitest';
import { BannedImportsRule } from '../../src/analyzer/rules/banned-imports.js';
import { DiffParser } from '../../src/github/diff-parser.js';
import { ReviewableFile } from '../../src/github/diff-service.js';

describe('BannedImportsRule (Lexical Tokenizer)', () => {
  const parser = new DiffParser();
  const rule = new BannedImportsRule();

  it('should detect static ES module named and default imports', () => {
    const files: ReviewableFile[] = [
      {
        filename: 'src/runner.ts',
        patch: `@@ -1,1 +1,3 @@
+import { exec, spawn } from 'child_process';
+import vm from 'vm';
 return true;`,
        additions: 2,
        deletions: 0,
        changes: 2
      }
    ];

    const boundary = parser.parseReviewableFiles(files);
    const findings = rule.scan(boundary);

    expect(findings).toHaveLength(2);
    expect(findings[0].ruleId).toBe('import-dangerous-child-process');
    expect(findings[0].severity).toBe('WARNING');
    expect(findings[1].ruleId).toBe('import-dangerous-vm');
  });

  it('should detect side-effect imports for prohibited malicious packages', () => {
    const files: ReviewableFile[] = [
      {
        filename: 'src/index.ts',
        patch: `@@ -1,1 +1,2 @@
+import 'flatmap-stream';
 export default {};`,
        additions: 1,
        deletions: 0,
        changes: 1
      }
    ];

    const boundary = parser.parseReviewableFiles(files);
    const findings = rule.scan(boundary);

    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('import-prohibited-flatmap-stream');
    expect(findings[0].severity).toBe('CRITICAL');
  });

  it('should detect CommonJS require() with static string specifiers', () => {
    const files: ReviewableFile[] = [
      {
        filename: 'src/legacy.cjs',
        patch: `@@ -1,1 +1,2 @@
+const cp = require("child_process");
 module.exports = cp;`,
        additions: 1,
        deletions: 0,
        changes: 1
      }
    ];

    const boundary = parser.parseReviewableFiles(files);
    const findings = rule.scan(boundary);

    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('import-dangerous-child-process');
  });

  it('should detect static dynamic import() statements', () => {
    const files: ReviewableFile[] = [
      {
        filename: 'src/fetcher.ts',
        patch: `@@ -1,1 +1,2 @@
+const req = await import('request');
 return req;`,
        additions: 1,
        deletions: 0,
        changes: 1
      }
    ];

    const boundary = parser.parseReviewableFiles(files);
    const findings = rule.scan(boundary);

    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('import-deprecated-request');
    expect(findings[0].severity).toBe('SUGGESTION');
  });

  it('should detect re-exports from banned packages', () => {
    const files: ReviewableFile[] = [
      {
        filename: 'src/reexport.ts',
        patch: `@@ -1,1 +1,2 @@
+export * from 'event-stream';
 return true;`,
        additions: 1,
        deletions: 0,
        changes: 1
      }
    ];

    const boundary = parser.parseReviewableFiles(files);
    const findings = rule.scan(boundary);

    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('import-supply-chain-event-stream');
  });

  it('should detect multiline imports spanning across lines', () => {
    const files: ReviewableFile[] = [
      {
        filename: 'src/multiline.ts',
        patch: `@@ -1,1 +1,5 @@
+import {
+  exec,
+  spawn
+} from 'child_process';
 return true;`,
        additions: 4,
        deletions: 0,
        changes: 4
      }
    ];

    const boundary = parser.parseReviewableFiles(files);
    const findings = rule.scan(boundary);

    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('import-dangerous-child-process');
  });

  it('should detect multiline import where declaration starts on context line and specifier is on added line', () => {
    const files: ReviewableFile[] = [
      {
        filename: 'src/split.ts',
        patch: `@@ -1,3 +1,4 @@
 import {
   somethingElse
+} from 'child_process';
 return true;`,
        additions: 1,
        deletions: 0,
        changes: 1
      }
    ];

    const boundary = parser.parseReviewableFiles(files);
    const findings = rule.scan(boundary);

    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('import-dangerous-child-process');
    expect(findings[0].line).toBe(3);
  });

  it('should detect package subpaths for subpath-enabled rules', () => {
    const files: ReviewableFile[] = [
      {
        filename: 'src/crypto.ts',
        patch: `@@ -1,1 +1,2 @@
+import md5 from 'crypto-js/md5';
 return md5;`,
        additions: 1,
        deletions: 0,
        changes: 1
      }
    ];

    const boundary = parser.parseReviewableFiles(files);
    const findings = rule.scan(boundary);

    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('import-dangerous-crypto-js');
  });

  it('should flag root lodash import but allow cherry-picked lodash subpath imports', () => {
    const files: ReviewableFile[] = [
      {
        filename: 'src/utils.ts',
        patch: `@@ -1,1 +1,3 @@
+import debounce from 'lodash/debounce';
+import _ from 'lodash';
 return true;`,
        additions: 2,
        deletions: 0,
        changes: 2
      }
    ];

    const boundary = parser.parseReviewableFiles(files);
    const findings = rule.scan(boundary);

    // Only root 'lodash' flagged; 'lodash/debounce' permitted
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('import-maintainability-lodash');
    expect(findings[0].line).toBe(2);
  });

  it('should ignore imports inside single-line and multi-line comments', () => {
    const files: ReviewableFile[] = [
      {
        filename: 'src/comments.ts',
        patch: `@@ -1,1 +1,4 @@
+// import { exec } from 'child_process';
+/* import 'flatmap-stream'; */
+/* const cp = require('child_process'); */
 return true;`,
        additions: 3,
        deletions: 0,
        changes: 3
      }
    ];

    const boundary = parser.parseReviewableFiles(files);
    const findings = rule.scan(boundary);

    expect(findings).toHaveLength(0);
  });

  it('should ignore imports inside string literals', () => {
    const files: ReviewableFile[] = [
      {
        filename: 'src/logger.ts',
        patch: `@@ -1,1 +1,3 @@
+const msg1 = "import { exec } from 'child_process';";
+const msg2 = 'const req = require("request");';
 return true;`,
        additions: 2,
        deletions: 0,
        changes: 2
      }
    ];

    const boundary = parser.parseReviewableFiles(files);
    const findings = rule.scan(boundary);

    expect(findings).toHaveLength(0);
  });

  it('should ignore dynamic variable expressions in import() and require()', () => {
    const files: ReviewableFile[] = [
      {
        filename: 'src/dynamic.ts',
        patch: `@@ -1,1 +1,4 @@
+const mod = await import(variableName);
+const pkg = require(getModuleName());
+const tpl = await import(\`./plugins/\${pluginName}\`);
 return true;`,
        additions: 3,
        deletions: 0,
        changes: 3
      }
    ];

    const boundary = parser.parseReviewableFiles(files);
    const findings = rule.scan(boundary);

    expect(findings).toHaveLength(0);
  });

  it('should never flag deleted import lines', () => {
    const files: ReviewableFile[] = [
      {
        filename: 'src/cleanup.ts',
        patch: `@@ -1,3 +1,1 @@
-import 'flatmap-stream';
-const cp = require('child_process');
 return true;`,
        additions: 0,
        deletions: 2,
        changes: 2
      }
    ];

    const boundary = parser.parseReviewableFiles(files);
    const findings = rule.scan(boundary);

    expect(findings).toHaveLength(0);
  });

  it('should ignore non-script files like markdown or JSON', () => {
    const files: ReviewableFile[] = [
      {
        filename: 'README.md',
        patch: `@@ -1,1 +1,2 @@
+import { exec } from 'child_process';
 Documentation only`,
        additions: 1,
        deletions: 0,
        changes: 1
      }
    ];

    const boundary = parser.parseReviewableFiles(files);
    const findings = rule.scan(boundary);

    expect(findings).toHaveLength(0);
  });
});


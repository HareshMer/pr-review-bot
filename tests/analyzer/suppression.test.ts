import { describe, it, expect } from 'vitest';
import {
  isAllowlistedExample,
  isKnownPlaceholder,
  calculateShannonEntropy,
  hasCharacterDiversity
} from '../../src/analyzer/rules/suppression.js';
import { SecretScannerRule } from '../../src/analyzer/rules/secret-scanner.js';
import { DebugStatementsRule } from '../../src/analyzer/rules/debug-statements.js';
import { ReviewAggregator } from '../../src/analyzer/aggregator.js';
import { DiffParser } from '../../src/github/diff-parser.js';
import { ReviewableFile } from '../../src/github/diff-service.js';
import { Finding } from '../../src/analyzer/rules/secret-scanner.js';
import { ReviewFinding } from '../../src/analyzer/llm/schemas.js';

describe('Suppression, Allowlist, Entropy & Aggregator Deduplication', () => {
  const parser = new DiffParser();
  const secretScanner = new SecretScannerRule();
  const debugScanner = new DebugStatementsRule();
  const aggregator = new ReviewAggregator();

  describe('Authoritative Allowlist Validation', () => {
    it('should match exact complete canonical examples only', () => {
      expect(isAllowlistedExample('AKIAIOSFODNN7EXAMPLE')).toBe(true);
      expect(isAllowlistedExample('ASIAIOSFODNN7EXAMPLE')).toBe(true);
      expect(isAllowlistedExample('wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')).toBe(true);
      expect(isAllowlistedExample('https://hooks.slack.com/' + 'services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX')).toBe(true);

      // Rejects partial, prefix, or 1-character modified values
      expect(isAllowlistedExample('AKIAIOSFODNN7EXAMPLA')).toBe(false);
      expect(isAllowlistedExample('AKIAIOSFODNN7EXAMPLE_EXTRA')).toBe(false);
      expect(isAllowlistedExample('PREFIX_AKIAIOSFODNN7EXAMPLE')).toBe(false);
      expect(isAllowlistedExample('')).toBe(false);
    });
  });

  describe('Shannon Entropy and Character Diversity Calculations', () => {
    it('should compute exact Shannon entropy for candidate strings', () => {
      // String of identical characters has 0 entropy
      expect(calculateShannonEntropy('aaaaaaaaaaaaaaaaaaaa')).toBe(0);

      // Low entropy strings
      const lowEntropy = 'aabbccaabbccaabbccaa';
      expect(calculateShannonEntropy(lowEntropy)).toBeLessThan(3.0);

      // High entropy random string (diverse characters)
      const highEntropy = 'P@ssw0rd!#$xYz987123';
      const score = calculateShannonEntropy(highEntropy);
      expect(score).toBeGreaterThanOrEqual(3.4);
    });

    it('should enforce character diversity (at least 3 distinct classes)', () => {
      // 1 class: only digits
      expect(hasCharacterDiversity('12345678901234567890', 3)).toBe(false);
      // 2 classes: digits and lowercase
      expect(hasCharacterDiversity('1234567890abcdefghij', 3)).toBe(false);
      // 3 classes: digits, lowercase, uppercase
      expect(hasCharacterDiversity('1234567890abcdefABCD', 3)).toBe(true);
      // 4 classes: digits, lowercase, uppercase, symbols
      expect(hasCharacterDiversity('1234567890abc!@#ABCD', 3)).toBe(true);
    });

    it('should recognize exact curated placeholders', () => {
      expect(isKnownPlaceholder('YOUR_API_KEY_HERE')).toBe(true);
      expect(isKnownPlaceholder('REPLACE_WITH_YOUR_KEY')).toBe(true);
      expect(isKnownPlaceholder('CHANGE_ME')).toBe(true);

      expect(isKnownPlaceholder('real_random_secret_string_123456')).toBe(false);
    });
  });

  describe('Generic Credential Assignment Heuristic', () => {
    it('should reject candidates shorter than 20 characters (boundary test)', () => {
      // Exactly 19 characters: length boundary
      const files: ReviewableFile[] = [
        {
          filename: 'src/auth.ts',
          patch: `@@ -1,1 +1,2 @@
+const password = "P@ssw0rd!#$xYz98712";
 return true;`,
          additions: 1,
          deletions: 0,
          changes: 1
        }
      ];

      const boundary = parser.parseReviewableFiles(files);
      const findings = secretScanner.scan(files, boundary);
      expect(findings).toHaveLength(0);
    });

    it('should flag candidate strings with length >= 20, 3+ classes, and entropy >= 3.4', () => {
      // Exactly 20 characters with high entropy and diversity
      const files: ReviewableFile[] = [
        {
          filename: 'src/auth.ts',
          patch: `@@ -1,1 +1,2 @@
+const password = "P@ssw0rd!#$xYz987123";
 return true;`,
          additions: 1,
          deletions: 0,
          changes: 1
        }
      ];

      const boundary = parser.parseReviewableFiles(files);
      const findings = secretScanner.scan(files, boundary);
      expect(findings).toHaveLength(1);
      expect(findings[0].ruleId).toBe('secret-generic-credential');
      expect(findings[0].severity).toBe('WARNING');
    });

    it('should suppress known placeholders even if length >= 20', () => {
      const files: ReviewableFile[] = [
        {
          filename: 'src/auth.ts',
          patch: `@@ -1,1 +1,2 @@
+const api_key = "REPLACE_WITH_YOUR_KEY";
 return true;`,
          additions: 1,
          deletions: 0,
          changes: 1
        }
      ];

      const boundary = parser.parseReviewableFiles(files);
      const findings = secretScanner.scan(files, boundary);
      expect(findings).toHaveLength(0);
    });
  });

  describe('Debug Statement File Exemptions', () => {
    it('should flag console.log and debugger in production source files', () => {
      const files: ReviewableFile[] = [
        {
          filename: 'src/services/api.ts',
          patch: `@@ -1,1 +1,3 @@
+console.log("calling api");
+debugger;
 return true;`,
          additions: 2,
          deletions: 0,
          changes: 2
        }
      ];

      const boundary = parser.parseReviewableFiles(files);
      const findings = debugScanner.scan(boundary);

      expect(findings).toHaveLength(2);
      expect(findings.some(f => f.ruleId === 'debug-console-log')).toBe(true);
      expect(findings.some(f => f.ruleId === 'debug-js-debugger')).toBe(true);
    });

    it('should suppress console.log in test files and CLI scripts while preserving debugger;', () => {
      const files: ReviewableFile[] = [
        {
          filename: 'tests/unit/api.test.ts',
          patch: `@@ -1,1 +1,3 @@
+console.log("test output");
+debugger;
 return true;`,
          additions: 2,
          deletions: 0,
          changes: 2
        },
        {
          filename: 'scripts/build.ts',
          patch: `@@ -1,1 +1,2 @@
+console.log("Build completed in 5s");
 return true;`,
          additions: 1,
          deletions: 0,
          changes: 1
        }
      ];

      const boundary = parser.parseReviewableFiles(files);
      const findings = debugScanner.scan(boundary);

      // console.log suppressed in test file and build script
      // debugger; preserved in test file
      expect(findings).toHaveLength(1);
      expect(findings[0].path).toBe('tests/unit/api.test.ts');
      expect(findings[0].ruleId).toBe('debug-js-debugger');
    });
  });

  describe('Aggregator Deduplication & Identity Integrity', () => {
    const mockBoundary = {
      validLinesPerFile: new Map([['src/app.ts', new Set([10, 20])]]),
      parsedFiles: []
    };

    it('should preserve multiple distinct deterministic rules on the same line', () => {
      const ruleFindings: Finding[] = [
        {
          path: 'src/app.ts',
          line: 10,
          severity: 'CRITICAL',
          category: 'SECURITY',
          title: 'Exposed AWS Key',
          message: 'Found AWS key',
          source: 'RULE',
          ruleId: 'secret-aws-access-key'
        },
        {
          path: 'src/app.ts',
          line: 10,
          severity: 'WARNING',
          category: 'SECURITY',
          title: 'Dangerous child_process Import',
          message: 'Found child_process',
          source: 'RULE',
          ruleId: 'import-dangerous-child-process'
        }
      ];

      const result = aggregator.aggregate(ruleFindings, [], 'PR Summary', mockBoundary);

      // Both distinct deterministic rules on line 10 must be preserved
      expect(result.validInlineFindings).toHaveLength(2);
      expect(result.validInlineFindings.map(f => f.ruleId)).toEqual([
        'secret-aws-access-key',
        'import-dangerous-child-process'
      ]);
    });

    it('should preserve distinct AI findings on the same line across different categories or titles', () => {
      const aiFindings: ReviewFinding[] = [
        {
          path: 'src/app.ts',
          line: 20,
          severity: 'CRITICAL',
          category: 'SECURITY',
          title: 'SQL Injection',
          message: 'Unsanitized input in query',
          confidence: 0.95
        },
        {
          path: 'src/app.ts',
          line: 20,
          severity: 'WARNING',
          category: 'BUG',
          title: 'Null Pointer Dereference',
          message: 'Object may be undefined',
          confidence: 0.85
        }
      ];

      const result = aggregator.aggregate([], aiFindings, 'PR Summary', mockBoundary);

      expect(result.validInlineFindings).toHaveLength(2);
      expect(result.validInlineFindings[0].category).toBe('SECURITY');
      expect(result.validInlineFindings[1].category).toBe('BUG');
    });

    it('should deduplicate AI findings when a deterministic rule covers the same line and category', () => {
      const ruleFindings: Finding[] = [
        {
          path: 'src/app.ts',
          line: 10,
          severity: 'CRITICAL',
          category: 'SECURITY',
          title: 'Exposed Secret',
          message: 'Rule found secret',
          source: 'RULE',
          ruleId: 'secret-aws-access-key'
        }
      ];

      const aiFindings: ReviewFinding[] = [
        {
          path: 'src/app.ts',
          line: 10,
          severity: 'CRITICAL',
          category: 'SECURITY',
          title: 'Potential credential leak',
          message: 'AI found secret',
          confidence: 0.9
        }
      ];

      const result = aggregator.aggregate(ruleFindings, aiFindings, 'PR Summary', mockBoundary);

      // AI finding deduplicated against deterministic rule; Rule takes precedence
      expect(result.validInlineFindings).toHaveLength(1);
      expect(result.validInlineFindings[0].source).toBe('RULE');
      expect(result.validInlineFindings[0].confidence).toBe(1.0);
    });
  });
});


import { describe, it, expect, vi } from 'vitest';
import { DiffSanitizer, SecretMatchSpan } from '../../src/analyzer/rules/sanitizer.js';
import { ReviewableFile } from '../../src/github/diff-service.js';
import { ReviewOrchestrator } from '../../src/analyzer/orchestrator.js';
import { DiffParser } from '../../src/github/diff-parser.js';
import { SecretScannerRule } from '../../src/analyzer/rules/secret-scanner.js';
import { DebugStatementsRule } from '../../src/analyzer/rules/debug-statements.js';
import { ReviewAggregator } from '../../src/analyzer/aggregator.js';
import { ReviewPublisher } from '../../src/github/review-publisher.js';

describe('DiffSanitizer & Pre-Flight Gemini Request Gate', () => {
  const sanitizer = new DiffSanitizer();

  it('should sanitize credentials on added lines while preserving line count, newlines, and hunk headers', () => {
    const originalPatch = `@@ -1,3 +1,5 @@
 const a = 1;
+const AWS_KEY = "AKIA1234567890ABCDEF";
+const DB_URI = "postgres://admin:secret123@db:5432/main";
 const b = 2;`;

    const originalFiles: ReviewableFile[] = [
      {
        filename: 'src/config.ts',
        patch: originalPatch,
        additions: 2,
        deletions: 0,
        changes: 2
      }
    ];

    const spans: SecretMatchSpan[] = [
      {
        filePath: 'src/config.ts',
        line: 2,
        rawSecret: 'AKIA1234567890ABCDEF',
        redactionPlaceholder: '[REDACTED_AWS_ACCESS_KEY]'
      },
      {
        filePath: 'src/config.ts',
        line: 3,
        rawSecret: 'secret123',
        redactionPlaceholder: '[REDACTED_DATABASE_PASSWORD]'
      }
    ];

    const sanitizedFiles = sanitizer.sanitizeReviewableFiles(originalFiles, spans);

    // 1. Original file objects must NOT be mutated
    expect(originalFiles[0].patch).toContain('AKIA1234567890ABCDEF');
    expect(originalFiles[0].patch).toContain('secret123');

    // 2. Sanitized file contains redaction tokens and no raw secrets
    expect(sanitizedFiles[0].patch).not.toContain('AKIA1234567890ABCDEF');
    expect(sanitizedFiles[0].patch).not.toContain('secret123');
    expect(sanitizedFiles[0].patch).toContain('[REDACTED_AWS_ACCESS_KEY]');
    expect(sanitizedFiles[0].patch).toContain('[REDACTED_DATABASE_PASSWORD]');

    // 3. Line count and newline invariant
    const origLines = originalFiles[0].patch.split('\n');
    const sanitLines = sanitizedFiles[0].patch.split('\n');
    expect(sanitLines.length).toBe(origLines.length);

    // 4. Hunk header unchanged
    expect(sanitLines[0]).toBe('@@ -1,3 +1,5 @@');
  });

  it('should redact multiline private key blocks line-by-line without shifting lines', () => {
    const multilineSecret = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0m5kYf7v1234567890
d4B5r8P1Q9abcdefghijklmnopqr
-----END RSA PRIVATE KEY-----`;

    const originalPatch = `@@ -10,1 +10,6 @@
 function loadKey() {
+${multilineSecret}
 }`;

    const originalFiles: ReviewableFile[] = [
      {
        filename: 'certs/key.pem',
        patch: originalPatch,
        additions: 4,
        deletions: 0,
        changes: 4
      }
    ];

    const spans: SecretMatchSpan[] = [
      {
        filePath: 'certs/key.pem',
        line: 11,
        rawSecret: multilineSecret,
        redactionPlaceholder: '[REDACTED_PRIVATE_KEY]'
      }
    ];

    const sanitizedFiles = sanitizer.sanitizeReviewableFiles(originalFiles, spans);

    expect(sanitizedFiles[0].patch).not.toContain('MIIEowIBAAKCAQEA0m5kYf7v1234567890');
    expect(sanitizedFiles[0].patch).toContain('[REDACTED_PRIVATE_KEY]_START');
    expect(sanitizedFiles[0].patch).toContain('[REDACTED_PRIVATE_KEY]_BODY');
    expect(sanitizedFiles[0].patch).toContain('[REDACTED_PRIVATE_KEY]_END');

    // Exactly identical line count
    expect(sanitizedFiles[0].patch.split('\n').length).toBe(originalPatch.split('\n').length);
  });

  it('should inspect complete serialized payload and fail closed when unredacted credential exists', () => {
    const safePayload = 'Reviewing pull request diff without any credentials';
    expect(sanitizer.inspectPayload(safePayload).safe).toBe(true);

    const unsafePayloadWithGoogle = 'User added API key AIzaSyD-MockGeminiKeyForTest12345678901 in config';
    const check1 = sanitizer.inspectPayload(unsafePayloadWithGoogle);
    expect(check1.safe).toBe(false);
    expect(check1.matchedRuleId).toBe('secret-google-api-key');

    const unsafePayloadWithDB = 'Database configured as postgres://admin:superSecretPassword123@db:5432/main';
    const check2 = sanitizer.inspectPayload(unsafePayloadWithDB);
    expect(check2.safe).toBe(false);
    expect(check2.matchedRuleId).toBe('secret-database-uri');

    // Allowlisted documented example is considered safe
    const allowlistedPayload = 'AWS example key AKIAIOSFODNN7EXAMPLE in documentation';
    expect(sanitizer.inspectPayload(allowlistedPayload).safe).toBe(true);
  });

  it('should abort Gemini dispatch and continue review safely when pre-flight gate detects unredacted secret', async () => {
    const mockCreateReview = vi.fn().mockResolvedValue({ data: { id: 100 } });
    const mockOctokit: any = {
      rest: {
        pulls: {
          createReview: mockCreateReview
        }
      }
    };

    const mockGithubFactory: any = {
      getInstallationClient: vi.fn().mockResolvedValue(mockOctokit)
    };

    const mockDiffService: any = {
      getDiffFetchResult: vi.fn().mockResolvedValue({
        reviewableFiles: [
          {
            filename: 'src/main.ts',
            patch: '@@ -1,1 +1,2 @@\n+const a = 1;\n',
            additions: 1,
            deletions: 0,
            changes: 1
          }
        ],
        skippedFiles: [],
        totalChangedLines: 1,
        totalFilesReturned: 1,
        isTruncated: false
      })
    };

    const mockGeminiClient: any = {
      reviewDiff: vi.fn()
    };

    const publisher = new ReviewPublisher();
    vi.spyOn(publisher, 'hasReviewForCommit').mockResolvedValue(false);

    const testSanitizer = new DiffSanitizer();
    // Simulate gate detecting an unredacted credential that bypassed earlier sanitization
    vi.spyOn(testSanitizer, 'inspectPayload').mockReturnValue({
      safe: false,
      matchedRuleId: 'secret-google-api-key'
    });

    const orchestrator = new ReviewOrchestrator(
      mockGithubFactory,
      mockDiffService,
      new DiffParser(),
      new SecretScannerRule(),
      new DebugStatementsRule(),
      mockGeminiClient,
      new ReviewAggregator(),
      publisher,
      testSanitizer
    );

    const payload: any = {
      action: 'opened',
      number: 1,
      pull_request: {
        number: 1,
        title: 'PR with credential',
        body: 'Clean PR description',
        head: { sha: 'sha-secret-title-test' }
      },
      repository: { name: 'repo', owner: { login: 'org' } },
      installation: { id: 123 }
    };

    await orchestrator.handlePullRequest(payload);

    // 1. Gemini reviewDiff was NEVER called (Fail-closed pre-flight gate blocked dispatch!)
    expect(mockGeminiClient.reviewDiff).not.toHaveBeenCalled();

    // 2. Review was still published with explanatory security warning
    expect(mockCreateReview).toHaveBeenCalledTimes(1);
    const reviewBody = mockCreateReview.mock.calls[0][0].body;
    expect(reviewBody).toContain('Automated AI deep review was withheld as a security safeguard');
  });
});

import { describe, it, expect } from 'vitest';
import { SecretScannerRule } from '../../src/analyzer/rules/secret-scanner.js';
import { DebugStatementsRule } from '../../src/analyzer/rules/debug-statements.js';
import { DiffParser } from '../../src/github/diff-parser.js';
import { ReviewableFile } from '../../src/github/diff-service.js';

describe('Deterministic Rule Engine (Secret & Debug Scanning)', () => {
  const parser = new DiffParser();
  const secretScanner = new SecretScannerRule();
  const debugScanner = new DebugStatementsRule();

  it('should detect exposed AWS access keys and GitHub PATs on added lines', () => {
    const files: ReviewableFile[] = [
      {
        filename: 'src/credentials.ts',
        patch: `@@ -1,2 +1,4 @@
 const service = "auth";
+const AWS_KEY = "AKIA1234567890ABCDEF";
+const GITHUB_TOKEN = "ghp_123456789012345678901234567890123456";
 return true;`,
        additions: 2,
        deletions: 0,
        changes: 2
      }
    ];

    const boundary = parser.parseReviewableFiles(files);
    const findings = secretScanner.scan(files, boundary);

    expect(findings.length).toBe(2);
    expect(findings[0].category).toBe('SECURITY');
    expect(findings[0].severity).toBe('CRITICAL');
    expect(findings[0].title).toContain('AWS Access Key');
    expect(findings[0].ruleId).toBe('secret-aws-access-key');
    expect(findings[1].title).toContain('GitHub Personal Access Token');
    expect(findings[1].ruleId).toBe('secret-github-pat');
  });

  it('should detect Google / Gemini API keys (39 chars)', () => {
    const files: ReviewableFile[] = [
      {
        filename: 'src/ai.ts',
        patch: `@@ -1,1 +1,2 @@
+const GEMINI_KEY = "AIzaSyD-MockGeminiKeyForTest12345678901";
 return true;`,
        additions: 1,
        deletions: 0,
        changes: 1
      }
    ];

    const boundary = parser.parseReviewableFiles(files);
    const findings = secretScanner.scan(files, boundary);

    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('secret-google-api-key');
    expect(findings[0].severity).toBe('CRITICAL');
    expect(findings[0].message).not.toContain('AIzaSyD');
  });

  it('should detect AWS STS temporary keys and AWS secret access keys', () => {
    const files: ReviewableFile[] = [
      {
        filename: 'src/aws.ts',
        patch: `@@ -1,1 +1,3 @@
+const STS_KEY = "${'ASIA' + '1234567890ABCDEF'}";
+const aws_secret_access_key = "${'wJalrXUtnFEMI/K7MDENG/bPxRfiCY' + '1234567890'}";
 return true;`,
        additions: 2,
        deletions: 0,
        changes: 2
      }
    ];

    const boundary = parser.parseReviewableFiles(files);
    const findings = secretScanner.scan(files, boundary);

    expect(findings).toHaveLength(2);
    expect(findings[0].ruleId).toBe('secret-aws-temporary-key');
    expect(findings[1].ruleId).toBe('secret-aws-secret-key');
  });

  it('should detect GitHub fine-grained and OAuth/App tokens', () => {
    const files: ReviewableFile[] = [
      {
        filename: 'src/github.ts',
        patch: `@@ -1,1 +1,3 @@
+const FINE_GRAINED = "github_pat_11AAAAAAA0123456789012345678901234567890123456789012345678901234567890123456789012";
+const OAUTH = "gho_123456789012345678901234567890123456";
 return true;`,
        additions: 2,
        deletions: 0,
        changes: 2
      }
    ];

    const boundary = parser.parseReviewableFiles(files);
    const findings = secretScanner.scan(files, boundary);

    expect(findings).toHaveLength(2);
    expect(findings[0].ruleId).toBe('secret-github-fine-grained-pat');
    expect(findings[1].ruleId).toBe('secret-github-oauth-app-token');
  });

  it('should detect Stripe, Slack, NPM, PyPI, SendGrid, and Twilio credentials', () => {
    const files: ReviewableFile[] = [
      {
        filename: 'src/services.ts',
        patch: `@@ -1,1 +1,7 @@
+const STRIPE = "${'sk_live_' + '51Abcdef1234567890Abcdef12'}";
+const SLACK_BOT = "${'xoxb-' + '123456789012-1234567890123-abcdefghijklmnopqrstuvwx'}";
+const NPM = "npm_123456789012345678901234567890123456";
+const PYPI = "pypi-AgEIcHlwaS5vcmcCJDEyMzQ1Njc4LTkwMTItMzQ1Ni03ODkwLTEyMzQ1Njc4OTA";
+const SENDGRID = "SG.1234567890123456789012.1234567890123456789012345678901234567890123";
+const twilio_auth_token = "0123456789abcdef0123456789abcdef";
 return true;`,
        additions: 6,
        deletions: 0,
        changes: 6
      }
    ];

    const boundary = parser.parseReviewableFiles(files);
    const findings = secretScanner.scan(files, boundary);

    expect(findings).toHaveLength(6);
    expect(findings.map(f => f.ruleId)).toEqual([
      'secret-stripe-secret-key',
      'secret-slack-bot-token',
      'secret-npm-token',
      'secret-pypi-token',
      'secret-sendgrid-api-key',
      'secret-twilio-auth-token'
    ]);
  });

  it('should detect database URIs with passwords including percent-encoded and special characters', () => {
    const files: ReviewableFile[] = [
      {
        filename: 'src/db.ts',
        patch: `@@ -1,1 +1,4 @@
+const PG = "postgres://admin:P%40ss%21w0rd@db.internal:5432/main";
+const MONGO = "mongodb+srv://user:p@ss!word@cluster0.abcde.mongodb.net/prod";
+const REDIS = "redis://:complex+p%20ssword@redis.host:6379/0";
 return true;`,
        additions: 3,
        deletions: 0,
        changes: 3
      }
    ];

    const boundary = parser.parseReviewableFiles(files);
    const findings = secretScanner.scan(files, boundary);

    expect(findings).toHaveLength(3);
    expect(findings.every(f => f.ruleId === 'secret-database-uri')).toBe(true);
    expect(findings[0].message).not.toContain('P%40ss%21w0rd');
  });

  it('should ignore database URIs without passwords', () => {
    const files: ReviewableFile[] = [
      {
        filename: 'src/db.ts',
        patch: `@@ -1,1 +1,4 @@
+const PG = "postgres://readonly@db.internal:5432/main";
+const REDIS = "redis://localhost:6379";
+const MONGO = "mongodb://cluster0.abcde.mongodb.net/prod";
 return true;`,
        additions: 3,
        deletions: 0,
        changes: 3
      }
    ];

    const boundary = parser.parseReviewableFiles(files);
    const findings = secretScanner.scan(files, boundary);

    expect(findings).toHaveLength(0);
  });

  it('should detect multiline private keys when header is on unchanged context line and body is added', () => {
    const files: ReviewableFile[] = [
      {
        filename: 'certs/server.key',
        patch: `@@ -1,2 +1,5 @@
 -----BEGIN RSA PRIVATE KEY-----
+MIIEowIBAAKCAQEA0m5kYf7v...
+d4B5r8P1Q9...
+-----END RSA PRIVATE KEY-----
 const port = 443;`,
        additions: 3,
        deletions: 0,
        changes: 3
      }
    ];

    const boundary = parser.parseReviewableFiles(files);
    const findings = secretScanner.scan(files, boundary);

    expect(findings.length).toBeGreaterThanOrEqual(2);
    expect(findings[0].ruleId).toBe('secret-private-key');
    expect(findings[0].title).toContain('Private Key');
  });

  it('should detect Encrypted PEM, PGP, and PuTTY private keys', () => {
    const files: ReviewableFile[] = [
      {
        filename: 'certs/keys.ts',
        patch: `@@ -1,1 +1,4 @@
+-----BEGIN ENCRYPTED PRIVATE KEY-----
+-----BEGIN PGP PRIVATE KEY BLOCK-----
+PuTTY-User-Key-File-2: ssh-rsa
 return true;`,
        additions: 3,
        deletions: 0,
        changes: 3
      }
    ];

    const boundary = parser.parseReviewableFiles(files);
    const findings = secretScanner.scan(files, boundary);

    expect(findings).toHaveLength(3);
    expect(findings.every(f => f.ruleId === 'secret-private-key')).toBe(true);
  });

  it('should suppress exact allowlisted documentation examples and detect one-character modifications', () => {
    const files: ReviewableFile[] = [
      {
        filename: 'docs/examples.ts',
        patch: `@@ -1,1 +1,3 @@
+const CANONICAL_AWS = "${'AKIA' + 'IOSFODNN7EXAMPLE'}";
+const TAMPERED_AWS = "${'AKIA' + 'IOSFODNN7EXAMPLA'}";
 return true;`,
        additions: 2,
        deletions: 0,
        changes: 2
      }
    ];

    const boundary = parser.parseReviewableFiles(files);
    const findings = secretScanner.scan(files, boundary);

    // Exact allowlisted key suppressed; 1-character modification flagged!
    expect(findings).toHaveLength(1);
    expect(findings[0].line).toBe(2);
    expect(findings[0].ruleId).toBe('secret-aws-access-key');
  });

  it('should detect debugger statements and console.log in code', () => {
    const files: ReviewableFile[] = [
      {
        filename: 'src/app.ts',
        patch: `@@ -5,2 +5,4 @@
 function run() {
+  debugger;
+  console.log("debug test");
 }`,
        additions: 2,
        deletions: 0,
        changes: 2
      }
    ];

    const boundary = parser.parseReviewableFiles(files);
    const findings = debugScanner.scan(boundary);

    expect(findings.length).toBe(2);
    expect(findings[0].title).toContain('JavaScript Debugger');
    expect(findings[1].title).toContain('Console Debug Log');
    expect(findings[0].severity).toBe('SUGGESTION');
  });

  it('should ignore deleted or unchanged lines', () => {
    const files: ReviewableFile[] = [
      {
        filename: 'src/app.ts',
        patch: `@@ -5,3 +5,2 @@
-  debugger;
-  const AWS_KEY = "AKIA1234567890ABCDEF";
   return true;`,
        additions: 0,
        deletions: 2,
        changes: 2
      }
    ];

    const boundary = parser.parseReviewableFiles(files);

    expect(secretScanner.scan(files, boundary)).toHaveLength(0);
    expect(debugScanner.scan(boundary)).toHaveLength(0);
  });
});

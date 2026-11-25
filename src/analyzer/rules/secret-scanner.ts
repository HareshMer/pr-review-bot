import { ReviewableFile } from '../../github/diff-service.js';
import { DiffBoundaryMap } from '../../github/diff-parser.js';
import { SecretMatchSpan } from './sanitizer.js';
import {
  isAllowlistedExample,
  isKnownPlaceholder,
  calculateShannonEntropy,
  hasCharacterDiversity
} from './suppression.js';

export interface Finding {
  path: string;
  line: number;
  severity: 'CRITICAL' | 'WARNING' | 'SUGGESTION';
  category: 'BUG' | 'SECURITY' | 'PERFORMANCE' | 'CODE_QUALITY' | 'BEST_PRACTICE';
  title: string;
  message: string;
  suggestion?: string;
  source: 'RULE' | 'AI';
  ruleId?: string;
}

export interface SecretScanResult {
  findings: Finding[];
  matchSpans: SecretMatchSpan[];
}

interface SecretPattern {
  name: string;
  regex: RegExp;
  severity: 'CRITICAL' | 'WARNING';
  ruleId: string;
  description: string;
  suggestion?: string;
  redactionToken: string;
}

const PROVIDER_PATTERNS: SecretPattern[] = [
  {
    name: 'Google Cloud / Gemini API Key',
    regex: /\b(AIza[0-9A-Za-z-_]{35})\b/,
    severity: 'CRITICAL',
    ruleId: 'secret-google-api-key',
    description: 'Exposed Google Cloud / Gemini API Key detected.',
    suggestion: 'process.env.GEMINI_API_KEY',
    redactionToken: '[REDACTED_GOOGLE_API_KEY]'
  },
  {
    name: 'AWS Access Key ID',
    regex: /\b(AKIA[0-9A-Z]{16})\b/,
    severity: 'CRITICAL',
    ruleId: 'secret-aws-access-key',
    description: 'Exposed AWS Access Key ID detected.',
    suggestion: 'process.env.AWS_ACCESS_KEY_ID',
    redactionToken: '[REDACTED_AWS_ACCESS_KEY]'
  },
  {
    name: 'AWS Temporary Access Key ID (STS)',
    regex: /\b(ASIA[0-9A-Z]{16})\b/,
    severity: 'CRITICAL',
    ruleId: 'secret-aws-temporary-key',
    description: 'Exposed AWS STS Temporary Access Key ID detected.',
    suggestion: 'process.env.AWS_ACCESS_KEY_ID',
    redactionToken: '[REDACTED_AWS_TEMPORARY_KEY]'
  },
  {
    name: 'AWS Secret Access Key',
    regex: /(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[:=]\s*["']?([0-9a-zA-Z/+]{40})["']?/i,
    severity: 'CRITICAL',
    ruleId: 'secret-aws-secret-key',
    description: 'Exposed AWS Secret Access Key assignment detected.',
    suggestion: 'process.env.AWS_SECRET_ACCESS_KEY',
    redactionToken: '[REDACTED_AWS_SECRET_KEY]'
  },
  {
    name: 'GitHub Personal Access Token (Classic)',
    regex: /\b(ghp_[a-zA-Z0-9]{36})\b/,
    severity: 'CRITICAL',
    ruleId: 'secret-github-pat',
    description: 'Exposed GitHub Classic Personal Access Token detected.',
    suggestion: 'process.env.GITHUB_TOKEN',
    redactionToken: '[REDACTED_GITHUB_PAT]'
  },
  {
    name: 'GitHub Personal Access Token (Fine-Grained)',
    regex: /\b(github_pat_[a-zA-Z0-9_]{82})\b/,
    severity: 'CRITICAL',
    ruleId: 'secret-github-fine-grained-pat',
    description: 'Exposed GitHub Fine-Grained Personal Access Token detected.',
    suggestion: 'process.env.GITHUB_TOKEN',
    redactionToken: '[REDACTED_GITHUB_FINE_GRAINED_PAT]'
  },
  {
    name: 'GitHub OAuth / App Token',
    regex: /\b(gh[ousr]_[a-zA-Z0-9]{36})\b/,
    severity: 'CRITICAL',
    ruleId: 'secret-github-oauth-app-token',
    description: 'Exposed GitHub OAuth, App, or Refresh Token detected.',
    suggestion: 'process.env.GITHUB_TOKEN',
    redactionToken: '[REDACTED_GITHUB_APP_TOKEN]'
  },
  {
    name: 'Stripe Live Secret Key',
    regex: /\b(sk_live_[0-9a-zA-Z]{24,})\b/,
    severity: 'CRITICAL',
    ruleId: 'secret-stripe-secret-key',
    description: 'Exposed Stripe Live Secret Key detected.',
    suggestion: 'process.env.STRIPE_SECRET_KEY',
    redactionToken: '[REDACTED_STRIPE_SECRET_KEY]'
  },
  {
    name: 'Stripe Live Restricted Key',
    regex: /\b(rk_live_[0-9a-zA-Z]{24,})\b/,
    severity: 'CRITICAL',
    ruleId: 'secret-stripe-restricted-key',
    description: 'Exposed Stripe Live Restricted Key detected.',
    suggestion: 'process.env.STRIPE_RESTRICTED_KEY',
    redactionToken: '[REDACTED_STRIPE_RESTRICTED_KEY]'
  },
  {
    name: 'Slack Bot OAuth Token',
    regex: /\b(xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32})\b/,
    severity: 'CRITICAL',
    ruleId: 'secret-slack-bot-token',
    description: 'Exposed Slack Bot OAuth Token detected.',
    suggestion: 'process.env.SLACK_BOT_TOKEN',
    redactionToken: '[REDACTED_SLACK_BOT_TOKEN]'
  },
  {
    name: 'Slack User OAuth Token',
    regex: /\b(xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32})\b/,
    severity: 'CRITICAL',
    ruleId: 'secret-slack-user-token',
    description: 'Exposed Slack User OAuth Token detected.',
    suggestion: 'process.env.SLACK_USER_TOKEN',
    redactionToken: '[REDACTED_SLACK_USER_TOKEN]'
  },
  {
    name: 'Slack Incoming Webhook URL',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/,
    severity: 'CRITICAL',
    ruleId: 'secret-slack-webhook',
    description: 'Exposed Slack Incoming Webhook URL detected.',
    suggestion: 'process.env.SLACK_WEBHOOK_URL',
    redactionToken: '[REDACTED_SLACK_WEBHOOK]'
  },
  {
    name: 'NPM Access Token',
    regex: /\b(npm_[a-zA-Z0-9]{36})\b/,
    severity: 'CRITICAL',
    ruleId: 'secret-npm-token',
    description: 'Exposed NPM Access Token detected.',
    suggestion: 'process.env.NPM_TOKEN',
    redactionToken: '[REDACTED_NPM_TOKEN]'
  },
  {
    name: 'PyPI API Token',
    regex: /\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{40,})\b/,
    severity: 'CRITICAL',
    ruleId: 'secret-pypi-token',
    description: 'Exposed PyPI Upload API Token detected.',
    suggestion: 'process.env.PYPI_API_TOKEN',
    redactionToken: '[REDACTED_PYPI_TOKEN]'
  },
  {
    name: 'SendGrid API Key',
    regex: /\b(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})\b/,
    severity: 'CRITICAL',
    ruleId: 'secret-sendgrid-api-key',
    description: 'Exposed SendGrid API Key detected.',
    suggestion: 'process.env.SENDGRID_API_KEY',
    redactionToken: '[REDACTED_SENDGRID_API_KEY]'
  },
  {
    name: 'Twilio Auth Token',
    regex: /(?:twilio[_-]?(?:auth[_-]?token|secret|key))\s*[:=]\s*["']?([a-f0-9]{32})["']?/i,
    severity: 'CRITICAL',
    ruleId: 'secret-twilio-auth-token',
    description: 'Exposed Twilio Auth Token assignment detected.',
    suggestion: 'process.env.TWILIO_AUTH_TOKEN',
    redactionToken: '[REDACTED_TWILIO_AUTH_TOKEN]'
  }
];

export class SecretScannerRule {
  /**
   * Scans reviewable files and returns both findings and secret match coordinates.
   */
  public scanWithSpans(files: ReviewableFile[], boundaryMap: DiffBoundaryMap): SecretScanResult {
    const findings: Finding[] = [];
    const matchSpans: SecretMatchSpan[] = [];

    for (const parsedFile of boundaryMap.parsedFiles) {
      const filePath = parsedFile.to || parsedFile.from;
      if (!filePath) continue;

      let inPrivateKey = false;
      let inPuTTYKey = false;

      for (const chunk of parsedFile.chunks) {
        for (const change of chunk.changes) {
          const rawContent = change.content;
          const lineText = rawContent.startsWith('+') || rawContent.startsWith('-') || rawContent.startsWith(' ')
            ? rawContent.slice(1)
            : rawContent;

          // 1. Multiline Private Key Detection (State-aware tracking)
          const isPEMHeader = /-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY(?: BLOCK)?-----/.test(lineText);
          const isPEMFooter = /-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY(?: BLOCK)?-----/.test(lineText);
          const isPuTTYHeader = /^PuTTY-User-Key-File-[23]:/.test(lineText);

          if (isPEMHeader) {
            inPrivateKey = true;
            if (change.type === 'add' && change.ln) {
              findings.push({
                path: filePath,
                line: change.ln,
                severity: 'CRITICAL',
                category: 'SECURITY',
                title: 'Exposed Cryptographic Private Key',
                message: 'Cryptographic Private Key header block detected in source code. This private key must be immediately revoked and rotated.',
                source: 'RULE',
                ruleId: 'secret-private-key'
              });
              matchSpans.push({
                filePath,
                line: change.ln,
                rawSecret: lineText.trim(),
                redactionPlaceholder: '[REDACTED_PRIVATE_KEY_HEADER]'
              });
            }
            continue;
          }

          if (isPuTTYHeader) {
            inPuTTYKey = true;
            if (change.type === 'add' && change.ln) {
              findings.push({
                path: filePath,
                line: change.ln,
                severity: 'CRITICAL',
                category: 'SECURITY',
                title: 'Exposed PuTTY Private Key',
                message: 'PuTTY Private Key header detected in source code. This private key must be immediately revoked and rotated.',
                source: 'RULE',
                ruleId: 'secret-private-key'
              });
              matchSpans.push({
                filePath,
                line: change.ln,
                rawSecret: lineText.trim(),
                redactionPlaceholder: '[REDACTED_PUTTY_PRIVATE_KEY]'
              });
            }
            continue;
          }

          if (inPrivateKey) {
            if (isPEMFooter) {
              inPrivateKey = false;
              if (change.type === 'add' && change.ln) {
                matchSpans.push({
                  filePath,
                  line: change.ln,
                  rawSecret: lineText.trim(),
                  redactionPlaceholder: '[REDACTED_PRIVATE_KEY_FOOTER]'
                });
              }
              continue;
            }

            // Body line within PEM private key block
            if (change.type === 'add' && change.ln) {
              const trimmed = lineText.trim();
              if (trimmed.length > 0) {
                findings.push({
                  path: filePath,
                  line: change.ln,
                  severity: 'CRITICAL',
                  category: 'SECURITY',
                  title: 'Exposed Cryptographic Private Key Material',
                  message: 'Cryptographic private key body material detected. This private key must be immediately revoked and rotated.',
                  source: 'RULE',
                  ruleId: 'secret-private-key'
                });
                matchSpans.push({
                  filePath,
                  line: change.ln,
                  rawSecret: trimmed,
                  redactionPlaceholder: '[REDACTED_PRIVATE_KEY_BODY_LINE]'
                });
              }
            }
            continue;
          }

          if (inPuTTYKey) {
            // PuTTY private keys typically end after Private-MAC line
            const isPuTTYEnd = /^Private-MAC:/i.test(lineText);
            if (change.type === 'add' && change.ln) {
              const trimmed = lineText.trim();
              if (trimmed.length > 0) {
                findings.push({
                  path: filePath,
                  line: change.ln,
                  severity: 'CRITICAL',
                  category: 'SECURITY',
                  title: 'Exposed PuTTY Private Key Material',
                  message: 'PuTTY private key material detected. This key must be immediately revoked and rotated.',
                  source: 'RULE',
                  ruleId: 'secret-private-key'
                });
                matchSpans.push({
                  filePath,
                  line: change.ln,
                  rawSecret: trimmed,
                  redactionPlaceholder: '[REDACTED_PUTTY_BODY_LINE]'
                });
              }
            }
            if (isPuTTYEnd) {
              inPuTTYKey = false;
            }
            continue;
          }

          // Only scan added lines for discrete credentials
          if (change.type !== 'add' || !change.ln) {
            continue;
          }

          let lineFlagged = false;

          // 2. Database URI Connection String Detection
          const dbUriRegex = /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis[s]?|amqp[s]?):\/\/([^\s"']+)/gi;
          let dbMatch: RegExpExecArray | null;
          while ((dbMatch = dbUriRegex.exec(lineText)) !== null) {
            const fullUri = dbMatch[0];
            const afterScheme = dbMatch[1];
            const authorityTerminator = afterScheme.search(/[\/?#]/);
            const authority = authorityTerminator === -1 ? afterScheme : afterScheme.slice(0, authorityTerminator);
            const atIndex = authority.lastIndexOf('@');
            if (atIndex !== -1) {
              const userinfo = authority.slice(0, atIndex);
              const colonIndex = userinfo.indexOf(':');
              if (colonIndex !== -1) {
                const password = userinfo.slice(colonIndex + 1);
                if (password && password.length > 0) {
                  findings.push({
                    path: filePath,
                    line: change.ln,
                    severity: 'CRITICAL',
                    category: 'SECURITY',
                    title: 'Exposed Database Connection URI Credentials',
                    message: 'Database connection string containing embedded credentials detected. Credentials must be revoked and rotated. Use environment variables or a secrets manager.',
                    suggestion: 'process.env.DATABASE_URL',
                    source: 'RULE',
                    ruleId: 'secret-database-uri'
                  });

                  matchSpans.push({
                    filePath,
                    line: change.ln,
                    rawSecret: password,
                    redactionPlaceholder: '[REDACTED_DATABASE_PASSWORD]'
                  });
                  lineFlagged = true;
                  break;
                }
              }
            }
          }

          if (lineFlagged) continue;

          // 3. Provider-Specific Signatures
          for (const pattern of PROVIDER_PATTERNS) {
            const match = pattern.regex.exec(lineText);
            if (match) {
              const secretVal = match[1] || match[0];

              // Check against authoritative documentation example allowlist
              if (isAllowlistedExample(secretVal)) {
                continue;
              }

              findings.push({
                path: filePath,
                line: change.ln,
                severity: pattern.severity,
                category: 'SECURITY',
                title: `Exposed Credential: ${pattern.name}`,
                message: `${pattern.description} Commit history must be cleansed and this credential must be immediately revoked and rotated. Use environment variables or a secret manager.`,
                suggestion: pattern.suggestion,
                source: 'RULE',
                ruleId: pattern.ruleId
              });

              matchSpans.push({
                filePath,
                line: change.ln,
                rawSecret: secretVal,
                redactionPlaceholder: pattern.redactionToken
              });

              lineFlagged = true;
              break;
            }
          }

          if (lineFlagged) continue;

          // 4. Generic Credential Assignment Heuristic (Multi-Factor Entropy Check)
          const genericAssignmentRegex = /(?:password|passwd|secret|api[_-]?key|auth[_-]?token)\s*[:=]\s*["']([^"']+)["']/gi;
          let genericMatch: RegExpExecArray | null;
          while ((genericMatch = genericAssignmentRegex.exec(lineText)) !== null) {
            const candidate = genericMatch[1];
            if (!candidate || candidate.length < 20) {
              continue; // Minimum length: 20 characters
            }

            if (isKnownPlaceholder(candidate)) {
              continue; // Exact placeholder match suppressed
            }

            if (isAllowlistedExample(candidate)) {
              continue; // Allowlisted documentation example suppressed
            }

            if (!hasCharacterDiversity(candidate, 3)) {
              continue; // Must contain at least 3 distinct character classes
            }

            const entropy = calculateShannonEntropy(candidate);
            if (entropy < 3.4) {
              continue; // Shannon entropy must be >= 3.4 bits/character
            }

            findings.push({
              path: filePath,
              line: change.ln,
              severity: 'WARNING',
              category: 'SECURITY',
              title: 'Hardcoded High-Entropy Credential Assignment',
              message: 'High-entropy credential or secret assignment detected. Verify if this is an active credential and move it to environment variables or a secrets manager.',
              suggestion: 'process.env.SECRET_KEY',
              source: 'RULE',
              ruleId: 'secret-generic-credential'
            });

            matchSpans.push({
              filePath,
              line: change.ln,
              rawSecret: candidate,
              redactionPlaceholder: '[REDACTED_GENERIC_CREDENTIAL]'
            });

            lineFlagged = true;
            break;
          }
        }
      }
    }

    return { findings, matchSpans };
  }

  /**
   * Backward-compatible scan method returning Finding[].
   */
  public scan(files: ReviewableFile[], boundaryMap: DiffBoundaryMap): Finding[] {
    const result = this.scanWithSpans(files, boundaryMap);
    return result.findings;
  }
}

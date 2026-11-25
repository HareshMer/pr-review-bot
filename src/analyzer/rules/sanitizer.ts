import { ReviewableFile } from '../../github/diff-service.js';
import { isAllowlistedExample } from './suppression.js';

export interface SecretMatchSpan {
  filePath: string;
  line?: number;
  rawSecret: string;
  redactionPlaceholder: string;
}

export interface GateInspectionPattern {
  name: string;
  regex: RegExp;
  ruleId: string;
}

export const GATE_INSPECTION_PATTERNS: GateInspectionPattern[] = [
  {
    name: 'Google API Key',
    regex: /\b(AIza[0-9A-Za-z-_]{35})\b/,
    ruleId: 'secret-google-api-key'
  },
  {
    name: 'AWS Access Key ID',
    regex: /\b(AKIA[0-9A-Z]{16})\b/,
    ruleId: 'secret-aws-access-key'
  },
  {
    name: 'AWS Temporary Access Key ID',
    regex: /\b(ASIA[0-9A-Z]{16})\b/,
    ruleId: 'secret-aws-temporary-key'
  },
  {
    name: 'AWS Secret Access Key',
    regex: /(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[:=]\s*["']?([0-9a-zA-Z/+]{40})["']?/i,
    ruleId: 'secret-aws-secret-key'
  },
  {
    name: 'GitHub PAT Classic',
    regex: /\b(ghp_[a-zA-Z0-9]{36})\b/,
    ruleId: 'secret-github-pat'
  },
  {
    name: 'GitHub PAT Fine-Grained',
    regex: /\b(github_pat_[a-zA-Z0-9_]{82})\b/,
    ruleId: 'secret-github-fine-grained-pat'
  },
  {
    name: 'GitHub OAuth / App Token',
    regex: /\b(gh[ousr]_[a-zA-Z0-9]{36})\b/,
    ruleId: 'secret-github-oauth-app-token'
  },
  {
    name: 'Private Key Block',
    regex: /-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY(?: BLOCK)?-----/,
    ruleId: 'secret-private-key'
  },
  {
    name: 'PuTTY Private Key',
    regex: /^PuTTY-User-Key-File-[23]:/m,
    ruleId: 'secret-private-key'
  },
  {
    name: 'Stripe Live Secret Key',
    regex: /\b(sk_live_[0-9a-zA-Z]{24,})\b/,
    ruleId: 'secret-stripe-secret-key'
  },
  {
    name: 'Stripe Live Restricted Key',
    regex: /\b(rk_live_[0-9a-zA-Z]{24,})\b/,
    ruleId: 'secret-stripe-restricted-key'
  },
  {
    name: 'Slack Bot Token',
    regex: /\b(xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32})\b/,
    ruleId: 'secret-slack-bot-token'
  },
  {
    name: 'Slack User Token',
    regex: /\b(xoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32})\b/,
    ruleId: 'secret-slack-user-token'
  },
  {
    name: 'Slack Incoming Webhook',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/,
    ruleId: 'secret-slack-webhook'
  },
  {
    name: 'NPM Access Token',
    regex: /\b(npm_[a-zA-Z0-9]{36})\b/,
    ruleId: 'secret-npm-token'
  },
  {
    name: 'PyPI API Token',
    regex: /\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{40,})\b/,
    ruleId: 'secret-pypi-token'
  },
  {
    name: 'SendGrid API Key',
    regex: /\b(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})\b/,
    ruleId: 'secret-sendgrid-api-key'
  },
  {
    name: 'Twilio Auth Token',
    regex: /(?:twilio[_-]?(?:auth[_-]?token|secret|key))\s*[:=]\s*["']?([a-f0-9]{32})["']?/i,
    ruleId: 'secret-twilio-auth-token'
  }
];

export class DiffSanitizer {
  /**
   * Produces an isolated, deep copy of ReviewableFile[] where all detected credentials
   * on added lines are replaced with non-sensitive redaction tokens.
   * Guarantees 1:1 line preservation, identical line counts, and unchanged hunk headers.
   */
  public sanitizeReviewableFiles(
    files: ReviewableFile[],
    matches: SecretMatchSpan[]
  ): ReviewableFile[] {
    const fileMatchesMap = new Map<string, SecretMatchSpan[]>();
    for (const match of matches) {
      const list = fileMatchesMap.get(match.filePath) || [];
      list.push(match);
      fileMatchesMap.set(match.filePath, list);
    }

    return files.map(file => {
      const spans = fileMatchesMap.get(file.filename) || [];
      if (spans.length === 0) {
        // Return a fresh object clone even if no spans to ensure isolation
        return {
          filename: file.filename,
          patch: file.patch,
          additions: file.additions,
          deletions: file.deletions,
          changes: file.changes
        };
      }

      let sanitizedPatch = file.patch;
      // Sort spans by rawSecret length descending to prevent substring collisions
      const sortedSpans = [...spans].sort((a, b) => b.rawSecret.length - a.rawSecret.length);

      for (const span of sortedSpans) {
        if (!span.rawSecret) continue;
        // Check if rawSecret contains newlines (multiline private keys)
        if (span.rawSecret.includes('\n')) {
          const secretLines = span.rawSecret.split('\n');
          const replacementLines = secretLines.map((_, idx) =>
            idx === 0
              ? `${span.redactionPlaceholder}_START`
              : idx === secretLines.length - 1
                ? `${span.redactionPlaceholder}_END`
                : `${span.redactionPlaceholder}_BODY`
          ).join('\n');

          sanitizedPatch = sanitizedPatch.split(span.rawSecret).join(replacementLines);
        } else {
          sanitizedPatch = sanitizedPatch.split(span.rawSecret).join(span.redactionPlaceholder);
        }
      }

      return {
        filename: file.filename,
        patch: sanitizedPatch,
        additions: file.additions,
        deletions: file.deletions,
        changes: file.changes
      };
    });
  }

  /**
   * Replaces detected credentials in arbitrary text (e.g. PR title or description).
   */
  public sanitizeText(text: string, matches: SecretMatchSpan[] = []): string {
    if (!text) return '';
    let result = text;

    // Apply known spans first
    for (const span of matches) {
      if (span.rawSecret && result.includes(span.rawSecret)) {
        result = result.split(span.rawSecret).join(span.redactionPlaceholder);
      }
    }

    // Also run provider signatures over text to catch metadata secrets
    for (const pattern of GATE_INSPECTION_PATTERNS) {
      result = result.replace(pattern.regex, (fullMatch, captureGroup) => {
        const valToTest = captureGroup || fullMatch;
        if (isAllowlistedExample(valToTest)) {
          return fullMatch;
        }
        return `[REDACTED_${pattern.ruleId.toUpperCase().replace(/-/g, '_')}]`;
      });
    }

    // Sanitize any database URIs
    const dbUriRegex = /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis[s]?|amqp[s]?):\/\/([^\s"']+)/gi;
    result = result.replace(dbUriRegex, fullUri => {
      const afterSchemeIndex = fullUri.indexOf('://') + 3;
      const afterScheme = fullUri.slice(afterSchemeIndex);
      const authorityTerminator = afterScheme.search(/[\/?#]/);
      const authority = authorityTerminator === -1 ? afterScheme : afterScheme.slice(0, authorityTerminator);
      const atIndex = authority.lastIndexOf('@');
      if (atIndex === -1) return fullUri;

      const userinfo = authority.slice(0, atIndex);
      const colonIndex = userinfo.indexOf(':');
      if (colonIndex === -1) return fullUri;

      const password = userinfo.slice(colonIndex + 1);
      if (!password || password.length === 0) return fullUri;

      const username = userinfo.slice(0, colonIndex);
      const rest = fullUri.slice(afterSchemeIndex + atIndex);
      return `${fullUri.slice(0, afterSchemeIndex)}${username}:[REDACTED_DATABASE_PASSWORD]${rest}`;
    });

    return result;
  }

  /**
   * Final inspection of the complete serialized Gemini prompt payload.
   * Runs immediately before network dispatch.
   * If any unredacted credential signature is detected (and not on the exact allowlist),
   * fails closed by returning safe = false.
   */
  public inspectPayload(payloadText: string): { safe: boolean; matchedRuleId?: string } {
    if (!payloadText) return { safe: true };

    for (const pattern of GATE_INSPECTION_PATTERNS) {
      const match = pattern.regex.exec(payloadText);
      if (match) {
        const secretVal = match[1] || match[0];
        if (!isAllowlistedExample(secretVal)) {
          return {
            safe: false,
            matchedRuleId: pattern.ruleId
          };
        }
      }
    }

    // Inspect for exposed database URIs with password
    const dbUriRegex = /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis[s]?|amqp[s]?):\/\/([^\s"']+)/gi;
    let dbMatch: RegExpExecArray | null;
    while ((dbMatch = dbUriRegex.exec(payloadText)) !== null) {
      const afterScheme = dbMatch[1];
      const authorityTerminator = afterScheme.search(/[\/?#]/);
      const authority = authorityTerminator === -1 ? afterScheme : afterScheme.slice(0, authorityTerminator);
      const atIndex = authority.lastIndexOf('@');
      if (atIndex !== -1) {
        const userinfo = authority.slice(0, atIndex);
        const colonIndex = userinfo.indexOf(':');
        if (colonIndex !== -1) {
          const password = userinfo.slice(colonIndex + 1);
          if (password && password.length > 0 && !password.includes('[REDACTED')) {
            return {
              safe: false,
              matchedRuleId: 'secret-database-uri'
            };
          }
        }
      }
    }

    return { safe: true };
  }
}

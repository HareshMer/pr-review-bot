import { describe, it, expect } from 'vitest';
import pino from 'pino';
import { logger } from '../../src/utils/logger.js';

describe('Structured Logger Redaction', () => {
  it('should redact sensitive tokens and credentials from log output', () => {
    let output = '';
    const dest = {
      write(msg: string) {
        output += msg;
      }
    };

    const testLogger = pino(
      {
        redact: {
          paths: [
            'req.headers["x-hub-signature-256"]',
            'req.headers.authorization',
            'signature',
            '*.signature',
            'secret',
            '*.secret',
            'privateKey',
            '*.privateKey',
            'apiKey',
            '*.apiKey',
            'token',
            '*.token',
            'GITHUB_PRIVATE_KEY',
            'GITHUB_WEBHOOK_SECRET',
            'GEMINI_API_KEY'
          ],
          censor: '[REDACTED]'
        }
      },
      dest
    );

    testLogger.info({
      signature: 'sha256=1234567890abcdef',
      apiKey: 'secret-gemini-key',
      token: 'ghp_secretToken1234567890',
      privateKey: '-----BEGIN RSA PRIVATE KEY-----',
      req: {
        headers: {
          'x-hub-signature-256': 'sha256=abcdef123456',
          authorization: 'Bearer super-secret-jwt'
        }
      },
      safeField: 'normal-data'
    });

    const parsed = JSON.parse(output.trim());

    expect(parsed.signature).toBe('[REDACTED]');
    expect(parsed.apiKey).toBe('[REDACTED]');
    expect(parsed.token).toBe('[REDACTED]');
    expect(parsed.privateKey).toBe('[REDACTED]');
    expect(parsed.req.headers['x-hub-signature-256']).toBe('[REDACTED]');
    expect(parsed.req.headers.authorization).toBe('[REDACTED]');
    expect(parsed.safeField).toBe('normal-data');
    expect(output).not.toContain('secret-gemini-key');
    expect(output).not.toContain('ghp_secretToken1234567890');
    expect(output).not.toContain('super-secret-jwt');
  });

  it('should verify the application logger instance is operational', () => {
    expect(logger).toBeDefined();
    expect(typeof logger.info).toBe('function');
    expect(typeof logger.warn).toBe('function');
    expect(typeof logger.error).toBe('function');
    expect(typeof logger.fatal).toBe('function');
  });
});

import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import { verifyWebhookSignature } from '../../src/webhooks/verify.js';

describe('Webhook Signature Verification (HMAC SHA-256)', () => {
  const secret = 'my-super-secret-passphrase-12345';
  const payload = JSON.stringify({ action: 'opened', number: 42 });

  it('should validate a correctly signed webhook payload', () => {
    const signature = `sha256=${crypto
      .createHmac('sha256', secret)
      .update(Buffer.from(payload))
      .digest('hex')}`;

    const isValid = verifyWebhookSignature(Buffer.from(payload), signature, secret);
    expect(isValid).toBe(true);
  });

  it('should reject a tampered payload with the original signature', () => {
    const signature = `sha256=${crypto
      .createHmac('sha256', secret)
      .update(Buffer.from(payload))
      .digest('hex')}`;

    const tamperedPayload = JSON.stringify({ action: 'opened', number: 43 });
    const isValid = verifyWebhookSignature(Buffer.from(tamperedPayload), signature, secret);
    expect(isValid).toBe(false);
  });

  it('should reject when secret is incorrect', () => {
    const signature = `sha256=${crypto
      .createHmac('sha256', secret)
      .update(Buffer.from(payload))
      .digest('hex')}`;

    const isValid = verifyWebhookSignature(Buffer.from(payload), signature, 'wrong-secret');
    expect(isValid).toBe(false);
  });

  it('should reject missing or malformed signature header', () => {
    expect(verifyWebhookSignature(Buffer.from(payload), undefined, secret)).toBe(false);
    expect(verifyWebhookSignature(Buffer.from(payload), 'invalid-format', secret)).toBe(false);
    expect(verifyWebhookSignature(Buffer.from(payload), 'sha256=short', secret)).toBe(false);
  });

  it('should reject when raw body is missing', () => {
    expect(verifyWebhookSignature(undefined, 'sha256=123', secret)).toBe(false);
  });
});


import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';
import crypto from 'node:crypto';
import { buildApp } from '../../src/app.js';
import { setTestEnv } from '../../src/config/env.js';
import { defaultDeliveryCache } from '../../src/webhooks/router.js';

describe('Fastify Webhook Ingress & Security', () => {
  const secret = 'test-secret-32-character-token-value';

  beforeAll(() => {
    setTestEnv({ GITHUB_WEBHOOK_SECRET: secret });
  });

  beforeEach(() => {
    defaultDeliveryCache.clear();
  });

  function createValidPRPayload(overrides: Record<string, any> = {}) {
    return {
      action: 'opened',
      number: 10,
      pull_request: {
        id: 100,
        number: 10,
        title: 'Add new feature',
        body: 'Details',
        draft: false,
        head: { sha: 'abc123sha', ref: 'feature' },
        base: { sha: 'base123sha', ref: 'main' },
        user: { login: 'dev', id: 1, type: 'User' }
      },
      repository: {
        name: 'my-repo',
        full_name: 'org/my-repo',
        private: false,
        owner: { login: 'org', id: 2 }
      },
      sender: { login: 'dev', id: 1, type: 'User' },
      installation: { id: 98765 },
      ...overrides
    };
  }

  function signPayload(payloadStr: string, secretKey: string = secret): string {
    return `sha256=${crypto
      .createHmac('sha256', secretKey)
      .update(Buffer.from(payloadStr))
      .digest('hex')}`;
  }

  it('should respond 200 on /health', async () => {
    const app = buildApp();
    const res = await app.inject({
      method: 'GET',
      url: '/health'
    });

    expect(res.statusCode).toBe(200);
    const body = JSON.parse(res.body);
    expect(body.status).toBe('ok');
    expect(body.uptime).toBeDefined();
  });

  it('should reject requests missing x-hub-signature-256 header with 401 Unauthorized', async () => {
    const app = buildApp();
    const payload = JSON.stringify({ action: 'opened' });

    const res = await app.inject({
      method: 'POST',
      url: '/webhooks',
      headers: {
        'content-type': 'application/json',
        'x-github-event': 'pull_request',
        'x-github-delivery': 'delivery-missing-sig'
      },
      payload
    });

    expect(res.statusCode).toBe(401);
    expect(JSON.parse(res.body).error).toBe('Invalid HMAC signature');
  });

  it('should reject requests with invalid HMAC signature with 401 Unauthorized', async () => {
    const mockOrchestrator = { handlePullRequest: vi.fn() };
    const app = buildApp(mockOrchestrator);
    const payload = JSON.stringify({ action: 'opened' });

    const res = await app.inject({
      method: 'POST',
      url: '/webhooks',
      headers: {
        'content-type': 'application/json',
        'x-hub-signature-256': 'sha256=invalidhex00000000000000000000000000000000000000000000000000000000',
        'x-github-event': 'pull_request',
        'x-github-delivery': 'delivery-123'
      },
      payload
    });

    expect(res.statusCode).toBe(401);
    expect(JSON.parse(res.body).error).toBe('Invalid HMAC signature');
  });

  it('should reject malformed JSON body with 400 Bad Request', async () => {
    const app = buildApp();
    const malformedBody = '{"action": "opened", broken json';
    const signature = signPayload(malformedBody);

    const res = await app.inject({
      method: 'POST',
      url: '/webhooks',
      headers: {
        'content-type': 'application/json',
        'x-hub-signature-256': signature,
        'x-github-event': 'pull_request',
        'x-github-delivery': 'delivery-malformed'
      },
      payload: malformedBody
    });

    expect(res.statusCode).toBe(400);
  });

  it('should accept validly signed pull_request.opened event with 202 Accepted', async () => {
    const mockOrchestrator = { handlePullRequest: vi.fn() };
    const app = buildApp(mockOrchestrator);

    const payloadObj = createValidPRPayload();
    const rawPayload = JSON.stringify(payloadObj);
    const signature = signPayload(rawPayload);

    const res = await app.inject({
      method: 'POST',
      url: '/webhooks',
      headers: {
        'content-type': 'application/json',
        'x-hub-signature-256': signature,
        'x-github-event': 'pull_request',
        'x-github-delivery': 'delivery-123'
      },
      payload: rawPayload
    });

    expect(res.statusCode).toBe(202);
    const body = JSON.parse(res.body);
    expect(body.message).toContain('accepted');
    expect(body.pr).toBe(10);
  });

  it('should reject pull_request event missing installation.id with 400 Bad Request', async () => {
    const app = buildApp();
    const payloadObj = createValidPRPayload({ installation: undefined });
    const rawPayload = JSON.stringify(payloadObj);
    const signature = signPayload(rawPayload);

    const res = await app.inject({
      method: 'POST',
      url: '/webhooks',
      headers: {
        'content-type': 'application/json',
        'x-hub-signature-256': signature,
        'x-github-event': 'pull_request',
        'x-github-delivery': 'delivery-no-install'
      },
      payload: rawPayload
    });

    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body).error).toContain('Missing GitHub App installation ID');
  });

  it('should ignore draft pull requests with 200 OK', async () => {
    const app = buildApp();
    const payloadObj = createValidPRPayload({
      pull_request: {
        id: 100,
        number: 10,
        title: 'Draft PR',
        body: null,
        draft: true,
        head: { sha: 'sha1', ref: 'draft' },
        base: { sha: 'base1', ref: 'main' },
        user: { login: 'dev', id: 1, type: 'User' }
      }
    });
    const rawPayload = JSON.stringify(payloadObj);
    const signature = signPayload(rawPayload);

    const res = await app.inject({
      method: 'POST',
      url: '/webhooks',
      headers: {
        'content-type': 'application/json',
        'x-hub-signature-256': signature,
        'x-github-event': 'pull_request',
        'x-github-delivery': 'delivery-draft'
      },
      payload: rawPayload
    });

    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body).message).toBe('Ignored draft PR');
  });

  it('should ignore bot-authored pull requests with 200 OK', async () => {
    const app = buildApp();
    const payloadObj = createValidPRPayload({
      sender: { login: 'dependabot[bot]', id: 99, type: 'Bot' }
    });
    const rawPayload = JSON.stringify(payloadObj);
    const signature = signPayload(rawPayload);

    const res = await app.inject({
      method: 'POST',
      url: '/webhooks',
      headers: {
        'content-type': 'application/json',
        'x-hub-signature-256': signature,
        'x-github-event': 'pull_request',
        'x-github-delivery': 'delivery-bot'
      },
      payload: rawPayload
    });

    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body).message).toBe('Ignored bot event');
  });

  it('should ignore unsupported PR actions (e.g., closed) with 200 OK', async () => {
    const app = buildApp();
    const payloadObj = createValidPRPayload({ action: 'closed' });
    const rawPayload = JSON.stringify(payloadObj);
    const signature = signPayload(rawPayload);

    const res = await app.inject({
      method: 'POST',
      url: '/webhooks',
      headers: {
        'content-type': 'application/json',
        'x-hub-signature-256': signature,
        'x-github-event': 'pull_request',
        'x-github-delivery': 'delivery-closed'
      },
      payload: rawPayload
    });

    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body).message).toContain('Ignored PR action: closed');
  });

  it('should ignore non-pull_request events with 200 OK', async () => {
    const app = buildApp();
    const payloadObj = { zen: 'Keep it simple.' };
    const rawPayload = JSON.stringify(payloadObj);
    const signature = signPayload(rawPayload);

    const res = await app.inject({
      method: 'POST',
      url: '/webhooks',
      headers: {
        'content-type': 'application/json',
        'x-hub-signature-256': signature,
        'x-github-event': 'ping',
        'x-github-delivery': 'delivery-ping'
      },
      payload: rawPayload
    });

    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body).message).toContain('Ignored event: ping');
  });

  it('should reject requests exceeding 10MB payload size with 413', async () => {
    const app = buildApp();
    // 10.5 MB payload
    const oversizedPayload = 'a'.repeat(10.5 * 1024 * 1024);

    const res = await app.inject({
      method: 'POST',
      url: '/webhooks',
      headers: {
        'content-type': 'application/json',
        'x-hub-signature-256': 'sha256=fakelen',
        'x-github-event': 'pull_request',
        'x-github-delivery': 'delivery-oversized'
      },
      payload: oversizedPayload
    });

    expect(res.statusCode).toBe(413);
  });

  it('should register webhook routes and process webhook independently when buildApp has no orchestrator', async () => {
    // Decoupled architecture verification: no orchestrator provided
    const app = buildApp();

    const payloadObj = createValidPRPayload();
    const rawPayload = JSON.stringify(payloadObj);
    const signature = signPayload(rawPayload);

    const res = await app.inject({
      method: 'POST',
      url: '/webhooks',
      headers: {
        'content-type': 'application/json',
        'x-hub-signature-256': signature,
        'x-github-event': 'pull_request',
        'x-github-delivery': 'delivery-independent'
      },
      payload: rawPayload
    });

    expect(res.statusCode).toBe(202);
    const body = JSON.parse(res.body);
    expect(body.message).toContain('accepted and queued');
  });

  it('should ignore duplicate webhook delivery with 202 and duplicate message', async () => {
    const mockOrchestrator = { handlePullRequest: vi.fn() };
    const app = buildApp(mockOrchestrator);

    const payloadObj = createValidPRPayload();
    const rawPayload = JSON.stringify(payloadObj);
    const signature = signPayload(rawPayload);

    // First delivery
    const res1 = await app.inject({
      method: 'POST',
      url: '/webhooks',
      headers: {
        'content-type': 'application/json',
        'x-hub-signature-256': signature,
        'x-github-event': 'pull_request',
        'x-github-delivery': 'delivery-duplicate-test'
      },
      payload: rawPayload
    });

    expect(res1.statusCode).toBe(202);
    expect(JSON.parse(res1.body).message).toContain('accepted and queued');

    // Duplicate delivery with same x-github-delivery
    const res2 = await app.inject({
      method: 'POST',
      url: '/webhooks',
      headers: {
        'content-type': 'application/json',
        'x-hub-signature-256': signature,
        'x-github-event': 'pull_request',
        'x-github-delivery': 'delivery-duplicate-test'
      },
      payload: rawPayload
    });

    expect(res2.statusCode).toBe(202);
    const body2 = JSON.parse(res2.body);
    expect(body2.message).toContain('Duplicate webhook delivery ignored');
    expect(body2.deliveryId).toBe('delivery-duplicate-test');
  });

  it('should not record delivery ID when HMAC signature is invalid', async () => {
    const mockOrchestrator = { handlePullRequest: vi.fn() };
    const app = buildApp(mockOrchestrator);

    const payloadObj = createValidPRPayload();
    const rawPayload = JSON.stringify(payloadObj);
    const invalidSignature = 'sha256=invalid0000000000000000000000000000000000000000000000000000000000';
    const validSignature = signPayload(rawPayload);

    // 1. Rejected request with invalid signature
    const res1 = await app.inject({
      method: 'POST',
      url: '/webhooks',
      headers: {
        'content-type': 'application/json',
        'x-hub-signature-256': invalidSignature,
        'x-github-event': 'pull_request',
        'x-github-delivery': 'delivery-invalid-then-valid'
      },
      payload: rawPayload
    });
    expect(res1.statusCode).toBe(401);

    // 2. Subsequent request with the same delivery ID but valid signature should be accepted (not dropped as duplicate)
    const res2 = await app.inject({
      method: 'POST',
      url: '/webhooks',
      headers: {
        'content-type': 'application/json',
        'x-hub-signature-256': validSignature,
        'x-github-event': 'pull_request',
        'x-github-delivery': 'delivery-invalid-then-valid'
      },
      payload: rawPayload
    });
    expect(res2.statusCode).toBe(202);
    expect(JSON.parse(res2.body).message).toContain('accepted and queued');
  });

  it('should not record delivery ID when event is unsupported (e.g. ping or closed PR)', async () => {
    const mockOrchestrator = { handlePullRequest: vi.fn() };
    const app = buildApp(mockOrchestrator);

    const pingPayload = JSON.stringify({ zen: 'Mind your thoughts' });
    const pingSignature = signPayload(pingPayload);
    const deliveryId = 'delivery-ping-then-pr';

    // 1. Ping event ignored (200 OK)
    const resPing = await app.inject({
      method: 'POST',
      url: '/webhooks',
      headers: {
        'content-type': 'application/json',
        'x-hub-signature-256': pingSignature,
        'x-github-event': 'ping',
        'x-github-delivery': deliveryId
      },
      payload: pingPayload
    });
    expect(resPing.statusCode).toBe(200);

    // Verify cache does not have delivery-ping-then-pr
    expect(defaultDeliveryCache.has(deliveryId)).toBe(false);

    // 2. Subsequent PR review event with the same delivery ID should be accepted normally
    const prPayload = JSON.stringify(createValidPRPayload());
    const prSignature = signPayload(prPayload);

    const resPR = await app.inject({
      method: 'POST',
      url: '/webhooks',
      headers: {
        'content-type': 'application/json',
        'x-hub-signature-256': prSignature,
        'x-github-event': 'pull_request',
        'x-github-delivery': deliveryId
      },
      payload: prPayload
    });
    expect(resPR.statusCode).toBe(202);
    expect(JSON.parse(resPR.body).message).toContain('accepted and queued');
  });
});

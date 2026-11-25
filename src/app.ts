import Fastify, { FastifyInstance } from 'fastify';
import { registerWebhookRoutes, WebhookRouterOptions } from './webhooks/router.js';
import { WebhookOrchestrator } from './webhooks/types.js';
import { logger } from './utils/logger.js';

export function buildApp(orchestrator?: WebhookOrchestrator, routerOptions?: WebhookRouterOptions) {
  const fastify = Fastify({
    loggerInstance: logger,
    bodyLimit: 10 * 1024 * 1024 // 10MB payload limit
  });

  // Preserve raw body buffer for HMAC verification
  fastify.addContentTypeParser(
    'application/json',
    { parseAs: 'buffer' },
    (req, body, done) => {
      try {
        req.rawBody = Buffer.isBuffer(body) ? body : Buffer.from(body);
        const parsed = JSON.parse(body.toString('utf-8'));
        done(null, parsed);
      } catch (err: any) {
        err.statusCode = 400;
        done(err, undefined);
      }
    }
  );

  // Health Check Endpoint
  fastify.get('/health', async () => {
    return {
      status: 'ok',
      uptime: process.uptime(),
      timestamp: new Date().toISOString()
    };
  });

  // Register Webhook Ingress (independent of orchestrator presence)
  registerWebhookRoutes(fastify as any, orchestrator, routerOptions);

  return fastify;
}


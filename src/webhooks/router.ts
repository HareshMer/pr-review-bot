import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { verifyWebhookSignature } from './verify.js';
import { PullRequestWebhookPayload, WebhookOrchestrator } from './types.js';
import { PrReviewConcurrencyManager, DeliveryDeduplicationCache } from './concurrency.js';
import { getEnv } from '../config/env.js';
import { logger } from '../utils/logger.js';

export interface WebhookRouterOptions {
  deliveryCache?: DeliveryDeduplicationCache;
  concurrencyManager?: PrReviewConcurrencyManager;
}

export const defaultDeliveryCache = new DeliveryDeduplicationCache();
export const defaultConcurrencyManager = new PrReviewConcurrencyManager();

export function registerWebhookRoutes(
  fastify: FastifyInstance,
  orchestrator?: WebhookOrchestrator,
  options?: WebhookRouterOptions
): void {
  const deliveryCache = options?.deliveryCache ?? defaultDeliveryCache;
  const concurrencyManager = options?.concurrencyManager ?? defaultConcurrencyManager;

  fastify.post('/webhooks', async (req: FastifyRequest, reply: FastifyReply) => {
    const signature = req.headers['x-hub-signature-256'] as string | undefined;
    const event = req.headers['x-github-event'] as string | undefined;
    const deliveryId = req.headers['x-github-delivery'] as string | undefined;

    logger.debug({ event, deliveryId }, 'Received GitHub webhook request');

    // 1. Signature Verification
    const env = getEnv();
    const rawBody = req.rawBody;
    if (!rawBody) {
      logger.error({ deliveryId }, 'Raw request body buffer unavailable for HMAC verification');
      return reply.code(400).send({ error: 'Raw request body unavailable' });
    }

    const isValid = verifyWebhookSignature(rawBody, signature, env.GITHUB_WEBHOOK_SECRET);

    if (!isValid) {
      logger.warn({ deliveryId }, 'Invalid webhook signature received');
      return reply.code(401).send({ error: 'Invalid HMAC signature' });
    }

    // 2. Event Type Filtering
    if (event !== 'pull_request') {
      logger.info({ event }, 'Ignored non-pull_request event');
      return reply.code(200).send({ message: `Ignored event: ${event}` });
    }

    const payload = req.body as PullRequestWebhookPayload;
    const { action, pull_request, repository, sender } = payload;

    // 3. Action and Actor Filtering
    const reviewableActions = ['opened', 'synchronize', 'reopened'];
    if (!reviewableActions.includes(action)) {
      logger.info({ action, pr: pull_request?.number }, 'Ignored PR action');
      return reply.code(200).send({ message: `Ignored PR action: ${action}` });
    }

    if (pull_request?.draft) {
      logger.info({ pr: pull_request.number }, 'Ignored draft PR');
      return reply.code(200).send({ message: 'Ignored draft PR' });
    }

    if (sender?.type === 'Bot') {
      logger.info({ sender: sender.login, pr: pull_request?.number }, 'Ignored bot-authored PR event');
      return reply.code(200).send({ message: 'Ignored bot event' });
    }

    if (!payload.installation?.id) {
      logger.error({ pr: pull_request?.number }, 'Missing installation ID in webhook payload');
      return reply.code(400).send({ error: 'Missing GitHub App installation ID' });
    }

    // 4. Webhook Delivery Deduplication
    if (deliveryId && deliveryCache.has(deliveryId)) {
      logger.info(
        { deliveryId, pr: pull_request.number, repo: repository.full_name },
        'Duplicate webhook delivery ignored'
      );
      return reply.code(202).send({
        message: 'Duplicate webhook delivery ignored',
        deliveryId
      });
    }

    if (deliveryId) {
      deliveryCache.record(deliveryId);
    }

    // 5. Immediate Acknowledgment to GitHub (Must respond <10s)
    reply.code(202).send({
      message: 'PR review task accepted and queued',
      deliveryId,
      pr: pull_request.number,
      repo: repository.full_name
    });

    // 6. Asynchronous Background Execution via Concurrency Manager (Latest-Head-Wins)
    if (orchestrator) {
      const prKey = PrReviewConcurrencyManager.getPrKey(payload);
      setImmediate(() => {
        concurrencyManager
          .submit(
            prKey,
            {
              payload,
              queuedAt: Date.now()
            },
            async (task) => {
              try {
                logger.info(
                  {
                    pr: task.payload.pull_request.number,
                    repo: task.payload.repository.full_name,
                    sha: task.payload.pull_request.head.sha
                  },
                  'Starting background PR review'
                );
                await orchestrator.handlePullRequest(task.payload);
                logger.info(
                  {
                    pr: task.payload.pull_request.number,
                    repo: task.payload.repository.full_name
                  },
                  'Successfully completed PR review'
                );
              } catch (error) {
                logger.error(
                  {
                    err: error,
                    pr: task.payload.pull_request.number,
                    repo: task.payload.repository.full_name
                  },
                  'Error processing PR review'
                );
              }
            }
          )
          .catch((err) => {
            logger.error({ prKey, err }, 'Unhandled error in PR review concurrency submit');
          });
      });
    } else {
      logger.info(
        { pr: pull_request?.number, repo: repository?.full_name },
        'No review orchestrator configured; webhook accepted without review dispatch'
      );
    }
  });
}


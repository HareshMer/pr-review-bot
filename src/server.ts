import { buildApp } from './app.js';
import { getEnv } from './config/env.js';
import { logger } from './utils/logger.js';
import { GitHubClientFactory } from './github/octokit.js';
import { DiffService } from './github/diff-service.js';
import { DiffParser } from './github/diff-parser.js';
import { SecretScannerRule } from './analyzer/rules/secret-scanner.js';
import { DebugStatementsRule } from './analyzer/rules/debug-statements.js';
import { BannedImportsRule } from './analyzer/rules/banned-imports.js';
import { DiffSanitizer } from './analyzer/rules/sanitizer.js';
import { GeminiReviewClient } from './analyzer/llm/client.js';
import { ReviewAggregator } from './analyzer/aggregator.js';
import { ReviewPublisher } from './github/review-publisher.js';
import { ReviewOrchestrator } from './analyzer/orchestrator.js';

async function bootstrap() {
  const env = getEnv();

  // Instantiate Dependencies
  const githubFactory = new GitHubClientFactory();
  const diffService = new DiffService();
  const diffParser = new DiffParser();
  const secretScanner = new SecretScannerRule();
  const debugScanner = new DebugStatementsRule();
  const bannedImportsScanner = new BannedImportsRule();
  const diffSanitizer = new DiffSanitizer();
  const geminiClient = new GeminiReviewClient();
  const aggregator = new ReviewAggregator();
  const publisher = new ReviewPublisher();

  const orchestrator = new ReviewOrchestrator(
    githubFactory,
    diffService,
    diffParser,
    secretScanner,
    debugScanner,
    geminiClient,
    aggregator,
    publisher,
    diffSanitizer,
    bannedImportsScanner
  );

  // Build Fastify App
  const app = buildApp(orchestrator);

  try {
    const address = await app.listen({ port: env.PORT, host: env.HOST });
    logger.info(`🚀 GitHub PR Review Bot server listening at ${address}`);
    logger.info(`📡 Webhook endpoint ready at ${address}/webhooks`);
    logger.info(`❤️ Health check ready at ${address}/health`);
  } catch (err) {
    logger.fatal({ err }, 'Failed to start server');
    process.exit(1);
  }

  // Graceful Shutdown
  const signals: NodeJS.Signals[] = ['SIGINT', 'SIGTERM'];
  for (const signal of signals) {
    process.on(signal, async () => {
      logger.info(`Received ${signal}, closing server...`);
      await app.close();
      logger.info('Server cleanly terminated.');
      process.exit(0);
    });
  }
}

bootstrap().catch(err => {
  console.error('Bootstrap error:', err);
  process.exit(1);
});


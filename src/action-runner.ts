import fs from 'node:fs';
import { getActionEnv } from './config/env.js';
import { createActionOctokit } from './github/octokit.js';
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
import { logger } from './utils/logger.js';

export interface GitHubActionEventPayload {
  action?: string;
  pull_request?: {
    number: number;
    title: string;
    body?: string | null;
    head: {
      sha: string;
      ref?: string;
    };
  };
  repository?: {
    name: string;
    owner: {
      login: string;
    };
  };
}

export async function runAction(): Promise<void> {
  logger.info('🚀 Starting AI PR Review Bot in GitHub Actions mode');

  const env = getActionEnv();

  // 1. Verify existence of the GitHub Actions event payload file
  if (!fs.existsSync(env.GITHUB_EVENT_PATH)) {
    throw new Error(`GITHUB_EVENT_PATH file not found at: ${env.GITHUB_EVENT_PATH}`);
  }

  // 2. Parse event payload
  const rawPayload = fs.readFileSync(env.GITHUB_EVENT_PATH, 'utf-8');
  let event: GitHubActionEventPayload;
  try {
    event = JSON.parse(rawPayload);
  } catch (err: any) {
    throw new Error(`Failed to parse GITHUB_EVENT_PATH JSON payload: ${err.message}`);
  }

  if (!event.pull_request) {
    logger.warn('Event payload does not contain pull_request data. Skipping review.');
    return;
  }

  // 3. Resolve repository and PR coordinates
  const [repoOwnerFallback, repoNameFallback] = env.GITHUB_REPOSITORY.split('/');
  const owner = event.repository?.owner?.login || repoOwnerFallback;
  const repo = event.repository?.name || repoNameFallback;
  const pullNumber = event.pull_request.number;
  const headSha = event.pull_request.head.sha;
  const title = event.pull_request.title;
  const body = event.pull_request.body;

  if (!owner || !repo) {
    throw new Error(`Unable to determine repository owner and name from GITHUB_REPOSITORY: ${env.GITHUB_REPOSITORY}`);
  }

  logger.info({ owner, repo, pullNumber, headSha }, 'Triggering pull request analysis from GitHub Action');

  // 4. Initialize dependencies using Action credentials
  const octokit = createActionOctokit(env.GITHUB_TOKEN);
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
    null,
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

  // 5. Run review
  await orchestrator.reviewTarget({
    owner,
    repo,
    pullNumber,
    headSha,
    title,
    body,
    octokit
  });

  logger.info({ owner, repo, pullNumber, headSha }, '✅ GitHub Actions PR review completed successfully');
}

// Auto-run if executed directly via CLI
if (
  process.argv[1] &&
  (process.argv[1].endsWith('action-runner.ts') || process.argv[1].endsWith('action-runner.js'))
) {
  runAction().catch(err => {
    logger.fatal({ err }, 'Fatal error during GitHub Action execution');
    process.exit(1);
  });
}

import { Octokit } from '@octokit/rest';
import { PullRequestWebhookPayload } from '../webhooks/types.js';
import { GitHubClientFactory } from '../github/octokit.js';
import { DiffService, DiffFetchResult, ReviewableFile } from '../github/diff-service.js';
import { DiffParser } from '../github/diff-parser.js';
import { SecretScannerRule } from './rules/secret-scanner.js';
import { DebugStatementsRule } from './rules/debug-statements.js';
import { BannedImportsRule } from './rules/banned-imports.js';
import { DiffSanitizer } from './rules/sanitizer.js';
import { GeminiReviewClient, GeminiReviewError } from './llm/client.js';
import { buildReviewUserPrompt } from './llm/prompts.js';
import { ReviewOutput } from './llm/schemas.js';
import { ReviewAggregator } from './aggregator.js';
import { ReviewPublisher } from '../github/review-publisher.js';
import { logger } from '../utils/logger.js';

export interface ReviewTargetParams {
  owner: string;
  repo: string;
  pullNumber: number;
  headSha: string;
  title: string;
  body?: string | null;
  octokit: Octokit;
}

export class ReviewOrchestrator {
  constructor(
    private githubFactory: GitHubClientFactory | null,
    private diffService: DiffService,
    private diffParser: DiffParser,
    private secretScanner: SecretScannerRule,
    private debugScanner: DebugStatementsRule,
    private geminiClient: GeminiReviewClient,
    private aggregator: ReviewAggregator,
    private publisher: ReviewPublisher,
    private diffSanitizer: DiffSanitizer = new DiffSanitizer(),
    private bannedImportsScanner: BannedImportsRule = new BannedImportsRule()
  ) { }

  public async handlePullRequest(payload: PullRequestWebhookPayload): Promise<void> {
    const { pull_request, repository, installation } = payload;
    const owner = repository.owner.login;
    const repo = repository.name;
    const pullNumber = pull_request.number;
    const headSha = pull_request.head.sha;

    if (!installation?.id) {
      throw new Error('Cannot process PR without installation ID');
    }

    if (!this.githubFactory) {
      throw new Error('GitHubClientFactory is required for webhook handlePullRequest');
    }

    logger.info({ owner, repo, pullNumber, headSha }, 'Orchestrating PR review from webhook');

    // 1. Authenticate Octokit client
    const octokit = await this.githubFactory.getInstallationClient(installation.id);

    // 2. Delegate to reviewTarget
    await this.reviewTarget({
      owner,
      repo,
      pullNumber,
      headSha,
      title: pull_request.title,
      body: pull_request.body,
      octokit
    });
  }

  public async reviewTarget(params: ReviewTargetParams): Promise<void> {
    const { owner, repo, pullNumber, title, body, octokit } = params;
    let headSha = params.headSha;

    logger.info({ owner, repo, pullNumber, headSha }, 'Orchestrating PR review');

    // 2. Pre-Analysis Live PR Head Verification
    // Ensure we analyze the current live head SHA rather than a stale queued payload
    if (typeof octokit.rest?.pulls?.get === 'function') {
      try {
        const { data: livePr } = await octokit.rest.pulls.get({
          owner,
          repo,
          pull_number: pullNumber
        });
        if (livePr?.head?.sha && livePr.head.sha !== headSha) {
          logger.info(
            { owner, repo, pullNumber, queuedSha: headSha, liveSha: livePr.head.sha },
            'Live PR head SHA differs from queued payload. Updating to live head SHA.'
          );
          headSha = livePr.head.sha;
        }
      } catch (err: any) {
        logger.debug({ owner, repo, pullNumber, err: err.message }, 'Failed to fetch live PR state; proceeding with payload head SHA');
      }
    }

    // 3. Review Idempotency Check
    // Skip analysis if an active review has already been published by this bot for this exact commit SHA
    const alreadyReviewed = await this.publisher.hasReviewForCommit(
      octokit,
      owner,
      repo,
      pullNumber,
      headSha
    );
    if (alreadyReviewed) {
      logger.info(
        { owner, repo, pullNumber, headSha },
        'Review already exists for this commit SHA; skipping duplicate analysis'
      );
      return;
    }

    // 4. Fetch changed reviewable files with bounded pagination and classification
    const diffResult: DiffFetchResult = typeof (this.diffService as any).getDiffFetchResult === 'function'
      ? await (this.diffService as any).getDiffFetchResult(octokit, owner, repo, pullNumber)
      : {
        reviewableFiles: await this.diffService.getReviewableFiles(octokit, owner, repo, pullNumber),
        skippedFiles: [],
        totalChangedLines: 0,
        totalFilesReturned: 0,
        isTruncated: false
      };

    const reviewableFiles: ReviewableFile[] = diffResult.reviewableFiles;
    if (reviewableFiles.length === 0) {
      logger.info({ owner, repo, pullNumber }, 'No reviewable files found in PR. Skipping review.');
      return;
    }

    // 5. Parse unified diffs into hunk maps
    const boundaryMap = this.diffParser.parseReviewableFiles(reviewableFiles);

    // 6. Run Deterministic Rule Engine (Operates on original diff data)
    const secretScanResult = this.secretScanner.scanWithSpans(reviewableFiles, boundaryMap);
    const secretFindings = secretScanResult.findings;
    const debugFindings = this.debugScanner.scan(boundaryMap);
    const bannedFindings = this.bannedImportsScanner.scan(boundaryMap);
    const deterministicFindings = [...secretFindings, ...debugFindings, ...bannedFindings];

    logger.info(
      { ruleFindingsCount: deterministicFindings.length },
      'Deterministic rule scan completed'
    );

    // 7. Sanitize diffs and PR metadata for Gemini (AI Data Protection: separate sanitized copy)
    const sanitizedFiles = this.diffSanitizer.sanitizeReviewableFiles(
      reviewableFiles,
      secretScanResult.matchSpans
    );

    const concatenatedSanitizedPatches = sanitizedFiles
      .map((f: ReviewableFile) => `--- a/${f.filename}\n+++ b/${f.filename}\n${f.patch}`)
      .join('\n\n');

    const sanitizedTitle = this.diffSanitizer.sanitizeText(
      title,
      secretScanResult.matchSpans
    );
    const sanitizedBody = body
      ? this.diffSanitizer.sanitizeText(body, secretScanResult.matchSpans)
      : null;

    // 8. Pre-Flight Fail-Closed Request Gate: Inspect complete serialized payload
    const serializedPayload = buildReviewUserPrompt(
      sanitizedTitle,
      sanitizedBody,
      concatenatedSanitizedPatches
    );
    const gateCheck = this.diffSanitizer.inspectPayload(serializedPayload);

    let aiOutput: ReviewOutput;
    let modelUsed: string | undefined;
    let isAiDegraded = false;

    if (!gateCheck.safe) {
      logger.warn(
        {
          event: 'GEMINI_DISPATCH_ABORTED_UNREDACTED_SECRET',
          ruleId: gateCheck.matchedRuleId,
          pullNumber,
          owner,
          repo
        },
        'Gemini review dispatch aborted: unredacted credential detected in serialized payload'
      );
      aiOutput = {
        summary: '> [!WARNING]\n> **Automated AI deep review was withheld as a security safeguard**: Unredacted credential material was detected in the pull request metadata or diff. Deterministic security and code quality rules have been evaluated and published below.',
        findings: []
      };
      isAiDegraded = true;
    } else {
      try {
        const reviewResult = await this.geminiClient.reviewDiff(
          sanitizedTitle,
          sanitizedBody,
          concatenatedSanitizedPatches
        );
        aiOutput = (reviewResult as any).output ?? reviewResult;
        modelUsed = reviewResult.modelUsed;
      } catch (error) {
        if (error instanceof GeminiReviewError) {
          logger.warn(
            {
              event: 'GEMINI_REVIEW_FAILED_DEGRADING_TO_RULES',
              code: error.code,
              message: error.message,
              pullNumber,
              owner,
              repo
            },
            'Gemini review cascade failed; gracefully degrading to deterministic rules'
          );
          aiOutput = {
            summary: '> [!WARNING]\n> **AI Semantic Review Unavailable**: The automated AI deep review could not be completed due to temporary upstream service unavailability. Deterministic security and code quality rules have been evaluated and published below.',
            findings: []
          };
          isAiDegraded = true;
        } else {
          // Unexpected runtime/programming errors (TypeError, syntax bug) must NOT be caught
          throw error;
        }
      }
    }

    // 8. Aggregate, Deduplicate, and Validate Diff Boundaries
    const aggregationResult = this.aggregator.aggregate(
      deterministicFindings,
      aiOutput.findings,
      aiOutput.summary,
      boundaryMap
    );

    // 9. Pre-Publication Live Head Check: Do not publish findings for a stale commit
    if (typeof octokit.rest?.pulls?.get === 'function') {
      try {
        const { data: currentPr } = await octokit.rest.pulls.get({
          owner,
          repo,
          pull_number: pullNumber
        });
        if (currentPr?.head?.sha && currentPr.head.sha !== headSha) {
          logger.warn(
            { owner, repo, pullNumber, analyzedSha: headSha, currentSha: currentPr.head.sha },
            'Aborting review publication: PR head SHA advanced while review was running. Stale findings discarded.'
          );
          return;
        }
      } catch (err: any) {
        logger.debug({ owner, repo, pullNumber, err: err.message }, 'Could not re-verify live PR head before publishing');
      }
    }

    // 10. Publish Review to GitHub (with targeted HTTP 422 fallback and metadata options)
    await this.publisher.publishReview(
      octokit,
      owner,
      repo,
      pullNumber,
      headSha,
      aggregationResult,
      {
        skippedFiles: diffResult.skippedFiles,
        isTruncated: diffResult.isTruncated,
        truncationReason: diffResult.truncationReason,
        totalFilesReturned: diffResult.totalFilesReturned,
        totalChangedLines: diffResult.totalChangedLines,
        modelUsed,
        isAiDegraded
      }
    );

    logger.info({ owner, repo, pullNumber, headSha }, 'PR review orchestration finished successfully');
  }
}


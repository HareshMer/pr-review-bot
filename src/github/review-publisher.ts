import { Octokit } from '@octokit/rest';
import { AggregatedFinding, ReviewAggregationResult } from '../analyzer/aggregator.js';
import { SkippedFile } from './diff-service.js';
import { getEnv } from '../config/env.js';
import { logger } from '../utils/logger.js';

interface GitHubReviewComment {
  path: string;
  line: number;
  side: 'RIGHT';
  body: string;
}

export interface ReviewMetadataOptions {
  skippedFiles?: SkippedFile[];
  isTruncated?: boolean;
  truncationReason?: string;
  totalFilesReturned?: number;
  totalChangedLines?: number;
  modelUsed?: string;
  isAiDegraded?: boolean;
  eventOverride?: 'COMMENT' | 'REQUEST_CHANGES' | 'APPROVE';
}

export class ReviewPublisher {
  /**
   * Checks whether the authenticated bot has already posted a review for this exact commit SHA.
   * Matches both bot identity (via login or type) and the structural commit marker in the review body.
   */
  public async hasReviewForCommit(
    octokit: Octokit,
    owner: string,
    repo: string,
    pullNumber: number,
    commitSha: string
  ): Promise<boolean> {
    try {
      let botLogin: string | undefined;
      try {
        const { data: user } = await octokit.rest.users.getAuthenticated();
        botLogin = user?.login;
      } catch {
        // Fallback if token scope does not support getAuthenticated
      }

      const marker = `<!-- ai-pr-review-bot-commit: ${commitSha} -->`;

      if (octokit.paginate && typeof octokit.paginate.iterator === 'function' && octokit.rest?.pulls?.listReviews) {
        const iterator = octokit.paginate.iterator(octokit.rest.pulls.listReviews, {
          owner,
          repo,
          pull_number: pullNumber,
          per_page: 100
        });

        for await (const response of iterator) {
          for (const review of response.data) {
            const matchesAuthor = botLogin
              ? review.user?.login === botLogin
              : (review.user?.type === 'Bot' || review.user?.login?.endsWith('[bot]'));

            const matchesCommit = review.commit_id === commitSha;
            const hasMarker = Boolean(review.body?.includes(marker));

            if (matchesAuthor && matchesCommit && hasMarker) {
              return true;
            }
          }
        }
      } else if (octokit.rest?.pulls?.listReviews) {
        const response = await octokit.rest.pulls.listReviews({
          owner,
          repo,
          pull_number: pullNumber,
          per_page: 100
        });

        for (const review of response.data) {
          const matchesAuthor = botLogin
            ? review.user?.login === botLogin
            : (review.user?.type === 'Bot' || review.user?.login?.endsWith('[bot]'));

          const matchesCommit = review.commit_id === commitSha;
          const hasMarker = Boolean(review.body?.includes(marker));

          if (matchesAuthor && matchesCommit && hasMarker) {
            return true;
          }
        }
      }

      return false;
    } catch (err: any) {
      logger.warn(
        { owner, repo, pullNumber, commitSha, err: err.message },
        'Failed to query existing PR reviews; proceeding with review'
      );
      return false;
    }
  }

  /**
   * Publishes a pull request review with inline comments and an overall summary.
   * If GitHub rejects inline comments with HTTP 422 (comment position error), applies a
   * single targeted fallback that publishes all actionable findings inside the review body.
   */
  public async publishReview(
    octokit: Octokit,
    owner: string,
    repo: string,
    pullNumber: number,
    commitSha: string,
    result: ReviewAggregationResult,
    options?: ReviewMetadataOptions
  ): Promise<void> {
    const env = getEnv();

    // 1. Format individual inline comments
    const comments: GitHubReviewComment[] = result.validInlineFindings.map(finding => ({
      path: finding.path,
      line: finding.line,
      side: 'RIGHT',
      body: this.formatInlineComment(finding)
    }));

    // 2. Format top-level PR review summary with commit marker
    const summaryMarkdown = this.buildSummaryMarkdown(result, commitSha, options);

    // 3. Determine GitHub Review Event ('COMMENT', 'REQUEST_CHANGES', 'APPROVE')
    let reviewEvent = options?.eventOverride ?? env.REVIEW_EVENT_VERDICT;

    const hasCriticalFinding = result.validInlineFindings.some(f => f.severity === 'CRITICAL');
    const hasWarningFinding = result.validInlineFindings.some(f => f.severity === 'WARNING');

    // Precedence rule 1: Critical findings (deterministic or AI) must always request changes
    if (hasCriticalFinding) {
      reviewEvent = 'REQUEST_CHANGES';
    } else if (options?.isAiDegraded) {
      // Precedence rule 2: If AI failed / degraded, never allow APPROVE
      if (reviewEvent === 'APPROVE') {
        reviewEvent = 'COMMENT';
      }
    } else if (hasWarningFinding && reviewEvent === 'APPROVE') {
      // Precedence rule 3: Warning findings suppress APPROVE
      reviewEvent = 'COMMENT';
    }

    logger.info(
      {
        owner,
        repo,
        pullNumber,
        commitSha,
        event: reviewEvent,
        inlineCommentsCount: comments.length
      },
      'Submitting review to GitHub'
    );

    try {
      await octokit.rest.pulls.createReview({
        owner,
        repo,
        pull_number: pullNumber,
        commit_id: commitSha,
        event: reviewEvent,
        body: summaryMarkdown,
        comments
      });

      logger.info({ owner, repo, pullNumber }, 'Successfully published GitHub pull request review');
    } catch (error: any) {
      const isCommentPositionErr = this.isCommentPositionError(error);

      if (isCommentPositionErr && comments.length > 0) {
        logger.warn(
          {
            owner,
            repo,
            pullNumber,
            commitSha,
            err: error.message,
            responseData: error.response?.data
          },
          'GitHub rejected inline comments with 422 Unprocessable Entity (comment position error). Executing single fallback attempt with standalone actionable findings in review body.'
        );

        // Format standalone fallback review body containing all findings and suggestions
        const fallbackSummaryMarkdown = this.buildFallbackSummaryMarkdown(result, commitSha, options);

        try {
          await octokit.rest.pulls.createReview({
            owner,
            repo,
            pull_number: pullNumber,
            commit_id: commitSha,
            event: reviewEvent,
            body: fallbackSummaryMarkdown,
            comments: [] // No inline comments; everything captured in body
          });

          logger.info(
            { owner, repo, pullNumber, commitSha },
            'Successfully published fallback GitHub review without inline comments'
          );
          return;
        } catch (fallbackError: any) {
          logger.error(
            {
              owner,
              repo,
              pullNumber,
              commitSha,
              originalError: error.message,
              originalStatus: error.status || error.statusCode,
              fallbackError: fallbackError.message,
              fallbackStatus: fallbackError.status || fallbackError.statusCode
            },
            'Failed both initial review and fallback review publication'
          );
          throw new Error(
            `Failed to publish PR review: Initial error (${error.message}); Fallback error (${fallbackError.message})`
          );
        }
      }

      // If not a recoverable comment position error, log and rethrow immediately
      logger.error(
        { owner, repo, pullNumber, status: error.status || error.statusCode, err: error.message },
        'Failed to submit review via Octokit'
      );
      throw error;
    }
  }

  public isCommentPositionError(error: any): boolean {
    if (!error) return false;
    const status = error.status || error.statusCode || error.response?.status;
    if (status !== 422) return false;

    const message = (error.message || '').toLowerCase();
    const responseData = error.response?.data;
    const responseMessage = (responseData?.message || '').toLowerCase();
    const errorList = Array.isArray(responseData?.errors) ? responseData.errors : [];

    // Specific phrases from GitHub for inline comment position / diff range errors
    const positionPhrases = [
      'part of the diff',
      'not in diff',
      'could not be anchored',
      'position is not part of the pull request',
      'diff range',
      'outside the diff',
      'diff_position_invalid',
      'line must be part of the diff',
      'pull_request_review_thread',
      'diff hunk'
    ];

    // Check if error message indicates an inline diff/position issue
    const combinedMessage = `${message} ${responseMessage}`;
    if (positionPhrases.some(phrase => combinedMessage.includes(phrase))) {
      return true;
    }

    // Inspect structured errors array
    for (const errItem of errorList) {
      if (typeof errItem === 'string') {
        const lowerItem = errItem.toLowerCase();
        if (positionPhrases.some(phrase => lowerItem.includes(phrase))) {
          return true;
        }
      } else if (typeof errItem === 'object' && errItem !== null) {
        const field = (errItem.field || '').toLowerCase();
        const code = (errItem.code || '').toLowerCase();
        const itemMsg = (errItem.message || '').toLowerCase();

        // Target field errors on line/position/side/diff_hunk
        if (['line', 'position', 'side', 'diff_hunk'].includes(field)) {
          return true;
        }

        if (positionPhrases.some(phrase => itemMsg.includes(phrase) || code.includes(phrase))) {
          return true;
        }
      }
    }

    return false;
  }

  private formatInlineComment(finding: AggregatedFinding): string {
    const severityBadge = {
      CRITICAL: '🚨 **CRITICAL**',
      WARNING: '⚠️ **WARNING**',
      SUGGESTION: '💡 **SUGGESTION**'
    }[finding.severity];

    let markdown = `${severityBadge} [${finding.category}]: **${finding.title}**\n\n${finding.message}\n`;

    if (finding.suggestion && finding.suggestion.trim().length > 0) {
      markdown += `\n\`\`\`suggestion\n${finding.suggestion}\n\`\`\`\n`;
    }

    markdown += `\n> _Reviewed by AI PR Reviewer (${finding.source === 'RULE' ? 'Deterministic Rule' : 'Gemini AI'})_`;

    return markdown;
  }

  private buildSummaryMarkdown(
    result: ReviewAggregationResult,
    commitSha: string,
    options?: ReviewMetadataOptions
  ): string {
    const totalFindings = result.validInlineFindings.length + result.outOfBoundsFindings.length;
    const criticalCount = result.validInlineFindings.filter(f => f.severity === 'CRITICAL').length;
    const warningCount = result.validInlineFindings.filter(f => f.severity === 'WARNING').length;
    const suggestionCount = result.validInlineFindings.filter(f => f.severity === 'SUGGESTION').length;

    let markdown = `<!-- ai-pr-review-bot-commit: ${commitSha} -->\n`;
    markdown += `## 🤖 AI Pull Request Review\n\n`;

    if (options?.isTruncated) {
      const skippedCount = options.skippedFiles?.length ?? 0;
      const returnedCount = options.totalFilesReturned ?? 0;
      const processedCount = Math.max(0, returnedCount - skippedCount);

      markdown += `> [!WARNING]\n`;
      markdown += `> **Incomplete Review**: PR analysis was truncated because it exceeded thresholds (${options.truncationReason}).\n`;
      markdown += `> - **Processed & Analyzed Files**: ${processedCount}\n`;
      markdown += `> - **Skipped Files (Retrieved)**: ${skippedCount}\n`;
      markdown += `> - **Unfetched Files**: Additional changed files in this PR were not fetched or analyzed (exact remaining count unknown from paginated stream).\n\n`;
    }

    markdown += `${result.summary}\n\n`;

    markdown += `### 📊 Review Overview\n`;
    markdown += `- **Total Issues Identified**: ${totalFindings}\n`;
    markdown += `- **Critical**: ${criticalCount} 🚨\n`;
    markdown += `- **Warnings**: ${warningCount} ⚠️\n`;
    markdown += `- **Suggestions**: ${suggestionCount} 💡\n\n`;

    if (result.validInlineFindings.length > 0) {
      markdown += `### 🔍 Actionable Findings Summary\n\n`;
      markdown += `| File | Line | Severity | Category | Title |\n`;
      markdown += `| :--- | :--- | :--- | :--- | :--- |\n`;

      for (const f of result.validInlineFindings) {
        const icon = f.severity === 'CRITICAL' ? '🚨' : f.severity === 'WARNING' ? '⚠️' : '💡';
        markdown += `| \`${f.path}\` | \`${f.line}\` | ${icon} ${f.severity} | ${f.category} | ${f.title} |\n`;
      }
      markdown += `\n`;
    }

    if (result.outOfBoundsFindings.length > 0) {
      markdown += `> [!NOTE]\n`;
      markdown += `> ${result.outOfBoundsFindings.length} observation(s) targeted lines outside the changed diff hunks and were excluded from inline comments.\n\n`;
    }

    if (options?.skippedFiles && options.skippedFiles.length > 0) {
      markdown += `### 📁 Skipped Files Details\n`;
      markdown += `> [!NOTE]\n`;
      markdown += `> ${options.skippedFiles.length} file(s) were excluded from review:\n`;
      for (const sf of options.skippedFiles.slice(0, 15)) {
        markdown += `> - \`${sf.filename}\`: ${sf.details || sf.reason}\n`;
      }
      if (options.skippedFiles.length > 15) {
        markdown += `> - ...and ${options.skippedFiles.length - 15} more files\n`;
      }
      markdown += `\n`;
    }

    if (options?.isAiDegraded) {
      markdown += `---\n*Automated review powered by Fastify & Octokit (Deterministic Rules Only; Gemini AI Unavailable).*`;
    } else if (options?.modelUsed) {
      markdown += `---\n*Automated review powered by Fastify, Octokit & Google Gemini (${options.modelUsed}).*`;
    } else {
      markdown += `---\n*Automated review powered by Fastify, Octokit & Google Gemini.*`;
    }

    return markdown;
  }

  private buildFallbackSummaryMarkdown(
    result: ReviewAggregationResult,
    commitSha: string,
    options?: ReviewMetadataOptions
  ): string {
    let markdown = `<!-- ai-pr-review-bot-commit: ${commitSha} -->\n`;
    markdown += `## 🤖 AI Pull Request Review (Fallback Summary)\n\n`;

    markdown += `> [!WARNING]\n`;
    markdown += `> **Inline Placement Failed (HTTP 422)**: GitHub rejected one or more inline review comments because targeted lines shifted or could not be anchored to diff hunks. All actionable findings and code suggestions are detailed below.\n\n`;

    if (options?.isTruncated) {
      const skippedCount = options.skippedFiles?.length ?? 0;
      const returnedCount = options.totalFilesReturned ?? 0;
      const processedCount = Math.max(0, returnedCount - skippedCount);

      markdown += `> [!WARNING]\n`;
      markdown += `> **Incomplete Review**: PR analysis was truncated (${options.truncationReason}).\n`;
      markdown += `> - **Processed & Analyzed Files**: ${processedCount}\n`;
      markdown += `> - **Skipped Files (Retrieved)**: ${skippedCount}\n`;
      markdown += `> - **Unfetched Files**: Additional changed files in this PR were not fetched or analyzed (exact remaining count unknown from paginated stream).\n\n`;
    }

    markdown += `${result.summary}\n\n`;

    if (result.validInlineFindings.length > 0) {
      markdown += `### 🔍 Actionable Findings Detail\n\n`;

      for (let i = 0; i < result.validInlineFindings.length; i++) {
        const f = result.validInlineFindings[i];
        const icon = f.severity === 'CRITICAL' ? '🚨' : f.severity === 'WARNING' ? '⚠️' : '💡';

        markdown += `#### ${i + 1}. [${icon} ${f.severity}] \`${f.path}:${f.line}\` (${f.category})\n`;
        markdown += `**${f.title}**\n\n`;
        markdown += `${f.message}\n`;

        if (f.suggestion && f.suggestion.trim().length > 0) {
          markdown += `\n\`\`\`suggestion\n${f.suggestion}\n\`\`\`\n`;
        }

        markdown += `\n---\n`;
      }
    }

    if (options?.skippedFiles && options.skippedFiles.length > 0) {
      markdown += `### 📁 Skipped Files Details\n`;
      markdown += `> [!NOTE]\n`;
      markdown += `> ${options.skippedFiles.length} file(s) were excluded from review:\n`;
      for (const sf of options.skippedFiles.slice(0, 15)) {
        markdown += `> - \`${sf.filename}\`: ${sf.details || sf.reason}\n`;
      }
      markdown += `\n`;
    }

    if (options?.isAiDegraded) {
      markdown += `*Automated review powered by Fastify & Octokit (Deterministic Rules Only; Gemini AI Unavailable).*`;
    } else if (options?.modelUsed) {
      markdown += `*Automated review powered by Fastify, Octokit & Google Gemini (${options.modelUsed}).*`;
    } else {
      markdown += `*Automated review powered by Fastify, Octokit & Google Gemini.*`;
    }

    return markdown;
  }
}



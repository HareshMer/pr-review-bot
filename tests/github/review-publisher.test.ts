import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ReviewPublisher } from '../../src/github/review-publisher.js';
import { ReviewAggregationResult } from '../../src/analyzer/aggregator.js';
import { setTestEnv } from '../../src/config/env.js';

describe('ReviewPublisher (Idempotency & Targeted 422 Fallback)', () => {
  let publisher: ReviewPublisher;

  beforeEach(() => {
    publisher = new ReviewPublisher();
    setTestEnv({ REVIEW_EVENT_VERDICT: 'COMMENT' });
  });

  const sampleResult: ReviewAggregationResult = {
    validInlineFindings: [
      {
        path: 'src/auth.ts',
        line: 42,
        severity: 'CRITICAL',
        category: 'SECURITY',
        title: 'SQL Injection',
        message: 'Direct input concatenation in raw query.',
        suggestion: 'db.query("SELECT * FROM users WHERE id = $1", [id]);',
        confidence: 0.95,
        source: 'AI'
      }
    ],
    outOfBoundsFindings: [],
    summary: 'PR introduces security issues.'
  };

  it('should detect existing review for commit when bot identity and commit marker match', async () => {
    const commitSha = 'abc123sha';
    const mockReviews = [
      {
        id: 1,
        commit_id: 'other-sha',
        body: 'Earlier review',
        user: { login: 'ai-pr-reviewer[bot]', type: 'Bot' }
      },
      {
        id: 2,
        commit_id: commitSha,
        body: `## Review\n<!-- ai-pr-review-bot-commit: ${commitSha} -->\nAll good.`,
        user: { login: 'ai-pr-reviewer[bot]', type: 'Bot' }
      }
    ];

    async function* mockIterator() {
      yield { data: mockReviews };
    }

    const mockOctokit: any = {
      rest: {
        users: {
          getAuthenticated: async () => ({ data: { login: 'ai-pr-reviewer[bot]' } })
        },
        pulls: {
          listReviews: async () => ({ data: mockReviews })
        }
      },
      paginate: {
        iterator: () => mockIterator()
      }
    };

    const hasReview = await publisher.hasReviewForCommit(mockOctokit, 'org', 'repo', 1, commitSha);
    expect(hasReview).toBe(true);
  });

  it('should reject existing review when commit ID is mismatched', async () => {
    const mockReviews = [
      {
        id: 1,
        commit_id: 'old-commit-sha',
        body: '<!-- ai-pr-review-bot-commit: old-commit-sha -->',
        user: { login: 'ai-pr-reviewer[bot]', type: 'Bot' }
      }
    ];

    const mockOctokit: any = {
      rest: {
        users: { getAuthenticated: async () => ({ data: { login: 'ai-pr-reviewer[bot]' } }) },
        pulls: { listReviews: async () => ({ data: mockReviews }) }
      },
      paginate: {
        iterator: () => (async function* () { yield { data: mockReviews }; })()
      }
    };

    const hasReview = await publisher.hasReviewForCommit(mockOctokit, 'org', 'repo', 1, 'target-commit-sha');
    expect(hasReview).toBe(false);
  });

  it('should reject review when author is wrong (different bot or human user)', async () => {
    const commitSha = 'target-commit-sha';
    const mockReviews = [
      {
        id: 1,
        commit_id: commitSha,
        body: `<!-- ai-pr-review-bot-commit: ${commitSha} -->`,
        user: { login: 'dependabot[bot]', type: 'Bot' }
      },
      {
        id: 2,
        commit_id: commitSha,
        body: `<!-- ai-pr-review-bot-commit: ${commitSha} -->`,
        user: { login: 'human-dev', type: 'User' }
      }
    ];

    const mockOctokit: any = {
      rest: {
        users: { getAuthenticated: async () => ({ data: { login: 'ai-pr-reviewer[bot]' } }) },
        pulls: { listReviews: async () => ({ data: mockReviews }) }
      },
      paginate: {
        iterator: () => (async function* () { yield { data: mockReviews }; })()
      }
    };

    const hasReview = await publisher.hasReviewForCommit(mockOctokit, 'org', 'repo', 1, commitSha);
    expect(hasReview).toBe(false);
  });

  it('should reject review when commit marker is missing in review body', async () => {
    const commitSha = 'target-commit-sha';
    const mockReviews = [
      {
        id: 1,
        commit_id: commitSha,
        body: 'LGTM! Great work on this PR.',
        user: { login: 'ai-pr-reviewer[bot]', type: 'Bot' }
      }
    ];

    const mockOctokit: any = {
      rest: {
        users: { getAuthenticated: async () => ({ data: { login: 'ai-pr-reviewer[bot]' } }) },
        pulls: { listReviews: async () => ({ data: mockReviews }) }
      },
      paginate: {
        iterator: () => (async function* () { yield { data: mockReviews }; })()
      }
    };

    const hasReview = await publisher.hasReviewForCommit(mockOctokit, 'org', 'repo', 1, commitSha);
    expect(hasReview).toBe(false);
  });

  it('should paginate review history across multiple pages to find matching review', async () => {
    const commitSha = 'target-commit-sha';
    const page1 = [
      {
        id: 1,
        commit_id: 'sha-page-1',
        body: '<!-- ai-pr-review-bot-commit: sha-page-1 -->',
        user: { login: 'ai-pr-reviewer[bot]', type: 'Bot' }
      }
    ];
    const page2 = [
      {
        id: 2,
        commit_id: commitSha,
        body: `<!-- ai-pr-review-bot-commit: ${commitSha} -->`,
        user: { login: 'ai-pr-reviewer[bot]', type: 'Bot' }
      }
    ];

    async function* multiPageIterator() {
      yield { data: page1 };
      yield { data: page2 };
    }

    const mockOctokit: any = {
      rest: {
        users: { getAuthenticated: async () => ({ data: { login: 'ai-pr-reviewer[bot]' } }) },
        pulls: { listReviews: async () => ({ data: [...page1, ...page2] }) }
      },
      paginate: {
        iterator: () => multiPageIterator()
      }
    };

    const hasReview = await publisher.hasReviewForCommit(mockOctokit, 'org', 'repo', 1, commitSha);
    expect(hasReview).toBe(true);
  });

  it('should successfully submit normal batch review with inline comments and commit marker', async () => {
    const mockCreateReview = vi.fn().mockResolvedValue({ data: { id: 100 } });
    const mockOctokit: any = {
      rest: {
        pulls: {
          createReview: mockCreateReview
        }
      }
    };

    await publisher.publishReview(mockOctokit, 'org', 'repo', 1, 'sha-123', sampleResult);

    expect(mockCreateReview).toHaveBeenCalledTimes(1);
    const callArgs = mockCreateReview.mock.calls[0][0];
    expect(callArgs.commit_id).toBe('sha-123');
    expect(callArgs.comments).toHaveLength(1);
    expect(callArgs.comments[0].line).toBe(42);
    expect(callArgs.body).toContain('<!-- ai-pr-review-bot-commit: sha-123 -->');
  });

  it('should apply targeted fallback when GitHub returns 422 for invalid inline comment positions', async () => {
    const commentPosition422 = new Error('Validation Failed: Pull request review comment line must be part of the diff');
    (commentPosition422 as any).status = 422;
    (commentPosition422 as any).response = {
      status: 422,
      data: {
        message: 'Validation Failed',
        errors: ['Pull request review comment line must be part of the diff']
      }
    };

    const mockCreateReview = vi
      .fn()
      .mockRejectedValueOnce(commentPosition422)
      .mockResolvedValueOnce({ data: { id: 200 } });

    const mockOctokit: any = {
      rest: {
        pulls: {
          createReview: mockCreateReview
        }
      }
    };

    await publisher.publishReview(mockOctokit, 'org', 'repo', 1, 'sha-422', sampleResult);

    // Initial batch call failed, followed by exactly 1 fallback call
    expect(mockCreateReview).toHaveBeenCalledTimes(2);

    const fallbackCallArgs = mockCreateReview.mock.calls[1][0];
    expect(fallbackCallArgs.commit_id).toBe('sha-422');
    expect(fallbackCallArgs.comments).toEqual([]); // No inline comments
    expect(fallbackCallArgs.body).toContain('<!-- ai-pr-review-bot-commit: sha-422 -->');
    expect(fallbackCallArgs.body).toContain('Inline Placement Failed (HTTP 422)');
    expect(fallbackCallArgs.body).toContain('SQL Injection');
    expect(fallbackCallArgs.body).toContain('```suggestion');
  });

  it('should immediately rethrow non-comment-position 422 errors without attempting fallback', async () => {
    const lockedPr422 = new Error('Pull request is locked');
    (lockedPr422 as any).status = 422;
    (lockedPr422 as any).response = {
      status: 422,
      data: {
        message: 'Cannot review a locked pull request',
        errors: [{ resource: 'PullRequest', code: 'locked' }]
      }
    };

    const mockCreateReview = vi.fn().mockRejectedValue(lockedPr422);
    const mockOctokit: any = {
      rest: {
        pulls: {
          createReview: mockCreateReview
        }
      }
    };

    await expect(
      publisher.publishReview(mockOctokit, 'org', 'repo', 1, 'sha-locked', sampleResult)
    ).rejects.toThrow('Pull request is locked');

    // Exactly 1 attempt; no fallback triggered
    expect(mockCreateReview).toHaveBeenCalledTimes(1);
  });

  it('should immediately rethrow non-422 errors (e.g. 403 Forbidden) without fallback', async () => {
    const error403 = new Error('Resource not accessible by integration');
    (error403 as any).status = 403;

    const mockCreateReview = vi.fn().mockRejectedValue(error403);
    const mockOctokit: any = {
      rest: {
        pulls: {
          createReview: mockCreateReview
        }
      }
    };

    await expect(
      publisher.publishReview(mockOctokit, 'org', 'repo', 1, 'sha-403', sampleResult)
    ).rejects.toThrow('Resource not accessible by integration');

    expect(mockCreateReview).toHaveBeenCalledTimes(1);
  });

  it('should capture both original and fallback errors if fallback also fails', async () => {
    const comment422 = new Error('Line not in diff');
    (comment422 as any).status = 422;
    (comment422 as any).response = { data: { message: 'Line not in diff' } };

    const fallback500 = new Error('Internal GitHub Server Error');
    (fallback500 as any).status = 500;

    const mockCreateReview = vi
      .fn()
      .mockRejectedValueOnce(comment422)
      .mockRejectedValueOnce(fallback500);

    const mockOctokit: any = {
      rest: {
        pulls: {
          createReview: mockCreateReview
        }
      }
    };

    await expect(
      publisher.publishReview(mockOctokit, 'org', 'repo', 1, 'sha-both-fail', sampleResult)
    ).rejects.toThrow('Failed to publish PR review: Initial error (Line not in diff); Fallback error (Internal GitHub Server Error)');

    expect(mockCreateReview).toHaveBeenCalledTimes(2);
  });

  describe('isCommentPositionError Unit Tests', () => {
    it('should identify invalid inline-comment line or position as comment position error', () => {
      const err = {
        status: 422,
        response: {
          data: {
            message: 'Validation Failed',
            errors: [{ resource: 'PullRequestReviewComment', field: 'position', code: 'invalid' }]
          }
        }
      };
      expect(publisher.isCommentPositionError(err)).toBe(true);

      const lineErr = {
        status: 422,
        response: {
          data: {
            message: 'Validation Failed',
            errors: [{ resource: 'PullRequestReviewComment', field: 'line', code: 'invalid' }]
          }
        }
      };
      expect(publisher.isCommentPositionError(lineErr)).toBe(true);
    });

    it('should identify invalid diff range as comment position error', () => {
      const diffRangeErr = {
        status: 422,
        message: 'Pull request review comment diff range is invalid',
        response: {
          data: {
            message: 'Validation Failed: diff range outside hunks'
          }
        }
      };
      expect(publisher.isCommentPositionError(diffRangeErr)).toBe(true);
    });

    it('should NOT identify an unrelated 422 containing a path field as a comment position error', () => {
      const pathErr = {
        status: 422,
        response: {
          data: {
            message: 'Validation Failed',
            errors: [{ resource: 'Commit', field: 'path', code: 'invalid' }]
          }
        }
      };
      expect(publisher.isCommentPositionError(pathErr)).toBe(false);

      const filePathErr = {
        status: 422,
        response: {
          data: {
            message: 'Path not found in tree',
            errors: [{ field: 'path', code: 'missing' }]
          }
        }
      };
      expect(publisher.isCommentPositionError(filePathErr)).toBe(false);
    });

    it('should NOT identify an unrelated locked or invalid-state error as a comment position error', () => {
      const lockedErr = {
        status: 422,
        response: {
          data: {
            message: 'Pull request is locked',
            errors: [{ resource: 'PullRequest', code: 'locked' }]
          }
        }
      };
      expect(publisher.isCommentPositionError(lockedErr)).toBe(false);

      const invalidStateErr = {
        status: 422,
        response: {
          data: {
            message: 'Cannot review a closed pull request',
            errors: [{ resource: 'PullRequest', code: 'invalid_state' }]
          }
        }
      };
      expect(publisher.isCommentPositionError(invalidStateErr)).toBe(false);
    });
  });

  it('should immediately rethrow unrelated 422 containing a path field without fallback', async () => {
    const unrelatedPath422 = new Error('Invalid path specified in commit');
    (unrelatedPath422 as any).status = 422;
    (unrelatedPath422 as any).response = {
      status: 422,
      data: {
        message: 'Validation Failed',
        errors: [{ resource: 'Commit', field: 'path', code: 'invalid' }]
      }
    };

    const mockCreateReview = vi.fn().mockRejectedValue(unrelatedPath422);
    const mockOctokit: any = {
      rest: {
        pulls: {
          createReview: mockCreateReview
        }
      }
    };

    await expect(
      publisher.publishReview(mockOctokit, 'org', 'repo', 1, 'sha-path-422', sampleResult)
    ).rejects.toThrow('Invalid path specified in commit');

    // Exactly 1 attempt: no fallback triggered
    expect(mockCreateReview).toHaveBeenCalledTimes(1);
  });

  it('should explicitly distinguish processed, skipped, and unfetched files in review summary when truncated', async () => {
    const mockCreateReview = vi.fn().mockResolvedValue({ data: { id: 300 } });
    const mockOctokit: any = {
      rest: {
        pulls: {
          createReview: mockCreateReview
        }
      }
    };

    await publisher.publishReview(
      mockOctokit,
      'org',
      'repo',
      1,
      'sha-trunc',
      sampleResult,
      {
        isTruncated: true,
        truncationReason: 'MAX_DIFF_LINES_EXCEEDED',
        totalFilesReturned: 10,
        skippedFiles: [
          { filename: 'package-lock.json', reason: 'IGNORED_NAME', details: 'Lockfile excluded' }
        ]
      }
    );

    expect(mockCreateReview).toHaveBeenCalledTimes(1);
    const callArgs = mockCreateReview.mock.calls[0][0];
    const body = callArgs.body;

    expect(body).toContain('**Incomplete Review**');
    expect(body).toContain('- **Processed & Analyzed Files**: 9');
    expect(body).toContain('- **Skipped Files (Retrieved)**: 1');
    expect(body).toContain('- **Unfetched Files**: Additional changed files in this PR were not fetched or analyzed (exact remaining count unknown from paginated stream).');
  });

  describe('Model Attribution & Verdict Precedence', () => {
    it('should attribute specific modelUsed in the review footer', async () => {
      const mockCreateReview = vi.fn().mockResolvedValue({ data: { id: 301 } });
      const mockOctokit: any = { rest: { pulls: { createReview: mockCreateReview } } };

      await publisher.publishReview(mockOctokit, 'org', 'repo', 1, 'sha-model', sampleResult, {
        modelUsed: 'gemini-3.6-flash'
      });

      const body = mockCreateReview.mock.calls[0][0].body;
      expect(body).toContain('Google Gemini (gemini-3.6-flash)');
    });

    it('should display degraded notice in footer when isAiDegraded is true', async () => {
      const mockCreateReview = vi.fn().mockResolvedValue({ data: { id: 302 } });
      const mockOctokit: any = { rest: { pulls: { createReview: mockCreateReview } } };

      await publisher.publishReview(mockOctokit, 'org', 'repo', 1, 'sha-degrade', sampleResult, {
        isAiDegraded: true
      });

      const body = mockCreateReview.mock.calls[0][0].body;
      expect(body).toContain('Deterministic Rules Only; Gemini AI Unavailable');
    });

    it('should downgrade APPROVE to COMMENT when isAiDegraded is true', async () => {
      setTestEnv({ REVIEW_EVENT_VERDICT: 'APPROVE' });
      const mockCreateReview = vi.fn().mockResolvedValue({ data: { id: 303 } });
      const mockOctokit: any = { rest: { pulls: { createReview: mockCreateReview } } };

      const cleanResult: any = { validInlineFindings: [], outOfBoundsFindings: [], summary: 'Clean PR' };
      await publisher.publishReview(mockOctokit, 'org', 'repo', 1, 'sha-appr', cleanResult, {
        isAiDegraded: true
      });

      expect(mockCreateReview.mock.calls[0][0].event).toBe('COMMENT');
    });

    it('should strictly enforce REQUEST_CHANGES when critical finding exists even if isAiDegraded is true', async () => {
      setTestEnv({ REVIEW_EVENT_VERDICT: 'APPROVE' });
      const mockCreateReview = vi.fn().mockResolvedValue({ data: { id: 304 } });
      const mockOctokit: any = { rest: { pulls: { createReview: mockCreateReview } } };

      const criticalResult: any = {
        validInlineFindings: [
          { path: 'file.ts', line: 1, severity: 'CRITICAL', category: 'SECURITY', title: 'Secret', message: 'Leak', source: 'RULE' }
        ],
        outOfBoundsFindings: [],
        summary: 'Critical PR'
      };

      await publisher.publishReview(mockOctokit, 'org', 'repo', 1, 'sha-crit', criticalResult, {
        isAiDegraded: true
      });

      expect(mockCreateReview.mock.calls[0][0].event).toBe('REQUEST_CHANGES');
    });
  });
});


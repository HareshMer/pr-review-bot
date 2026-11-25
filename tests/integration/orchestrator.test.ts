import { describe, it, expect, vi, beforeAll } from 'vitest';
import { ReviewOrchestrator } from '../../src/analyzer/orchestrator.js';
import { DiffParser } from '../../src/github/diff-parser.js';
import { SecretScannerRule } from '../../src/analyzer/rules/secret-scanner.js';
import { DebugStatementsRule } from '../../src/analyzer/rules/debug-statements.js';
import { ReviewAggregator } from '../../src/analyzer/aggregator.js';
import { ReviewPublisher } from '../../src/github/review-publisher.js';
import { GeminiReviewError } from '../../src/analyzer/llm/client.js';
import { setTestEnv } from '../../src/config/env.js';

describe('ReviewOrchestrator Integration Test', () => {
  beforeAll(() => {
    setTestEnv({
      REVIEW_EVENT_VERDICT: 'COMMENT'
    });
  });

  it('should coordinate diff retrieval, rule evaluation, AI review, and batch comment publication', async () => {
    // 1. Mock Octokit
    const mockCreateReview = vi.fn().mockResolvedValue({ data: { id: 1 } });
    const mockOctokit: any = {
      rest: {
        pulls: {
          createReview: mockCreateReview
        }
      }
    };

    const mockGithubFactory: any = {
      getInstallationClient: vi.fn().mockResolvedValue(mockOctokit)
    };

    // 2. Mock DiffService
    const mockDiffService: any = {
      getReviewableFiles: vi.fn().mockResolvedValue([
        {
          filename: 'src/auth.ts',
          patch: `@@ -1,3 +1,5 @@
 import { db } from './db';
+const API_SECRET = "AKIA1234567890ABCDEF";
+debugger;
 export function login() {}`,
          additions: 2,
          deletions: 0,
          changes: 2
        }
      ])
    };

    // 3. Mock Gemini Client
    const mockGeminiClient: any = {
      reviewDiff: vi.fn().mockResolvedValue({
        summary: 'PR adds credentials and debugging code that must be cleaned.',
        findings: [
          {
            path: 'src/auth.ts',
            line: 4, // 'export function login() {}'
            severity: 'SUGGESTION',
            category: 'CODE_QUALITY',
            title: 'Empty function body',
            message: 'Function login is currently empty.',
            suggestion: 'export function login() {\n  return false;\n}',
            confidence: 0.85
          }
        ]
      })
    };

    const diffParser = new DiffParser();
    const secretScanner = new SecretScannerRule();
    const debugScanner = new DebugStatementsRule();
    const aggregator = new ReviewAggregator();
    const publisher = new ReviewPublisher();

    const orchestrator = new ReviewOrchestrator(
      mockGithubFactory,
      mockDiffService,
      diffParser,
      secretScanner,
      debugScanner,
      mockGeminiClient,
      aggregator,
      publisher
    );

    const payload: any = {
      action: 'opened',
      number: 42,
      pull_request: {
        number: 42,
        title: 'Add auth module',
        body: 'Implemented authentication service',
        head: { sha: 'mock-commit-sha-987' }
      },
      repository: {
        name: 'test-repo',
        owner: { login: 'test-org' }
      },
      installation: { id: 12345 }
    };

    await orchestrator.handlePullRequest(payload);

    // Verify Octokit createReview was called with exact arguments
    expect(mockCreateReview).toHaveBeenCalledTimes(1);
    const reviewCallArgs = mockCreateReview.mock.calls[0][0];

    expect(reviewCallArgs.owner).toBe('test-org');
    expect(reviewCallArgs.repo).toBe('test-repo');
    expect(reviewCallArgs.pull_number).toBe(42);
    expect(reviewCallArgs.commit_id).toBe('mock-commit-sha-987');
    expect(reviewCallArgs.event).toBe('REQUEST_CHANGES');

    // Expected findings:
    // 1. Secret rule: Line 2 (AWS Key)
    // 2. Debug rule: Line 3 (debugger;)
    // 3. Gemini AI: Line 4 (empty function)
    expect(reviewCallArgs.comments.length).toBe(3);

    // Check suggestions format
    const secretComment = reviewCallArgs.comments.find((c: any) => c.line === 2);
    expect(secretComment.body).toContain('CRITICAL');
    expect(secretComment.body).toContain('Exposed Credential');

    const debugComment = reviewCallArgs.comments.find((c: any) => c.line === 3);
    expect(debugComment.body).toContain('JavaScript Debugger');

    const aiComment = reviewCallArgs.comments.find((c: any) => c.line === 4);
    expect(aiComment.body).toContain('```suggestion');
    expect(aiComment.body).toContain('export function login()');

    // Check review body markdown summary
    expect(reviewCallArgs.body).toContain('## 🤖 AI Pull Request Review');
    expect(reviewCallArgs.body).toContain('| `src/auth.ts` | `2` | 🚨 CRITICAL |');
  });

  it('should skip review when a review already exists for the commit SHA (idempotency)', async () => {
    const mockCreateReview = vi.fn();
    const mockOctokit: any = {
      rest: {
        pulls: {
          createReview: mockCreateReview,
          get: vi.fn().mockResolvedValue({ data: { head: { sha: 'commit-already-reviewed' } } })
        }
      }
    };

    const mockGithubFactory: any = {
      getInstallationClient: vi.fn().mockResolvedValue(mockOctokit)
    };
    const mockDiffService: any = {
      getDiffFetchResult: vi.fn()
    };
    const mockGeminiClient: any = {
      reviewDiff: vi.fn()
    };
    const publisher = new ReviewPublisher();
    vi.spyOn(publisher, 'hasReviewForCommit').mockResolvedValue(true);

    const orchestrator = new ReviewOrchestrator(
      mockGithubFactory,
      mockDiffService,
      new DiffParser(),
      new SecretScannerRule(),
      new DebugStatementsRule(),
      mockGeminiClient,
      new ReviewAggregator(),
      publisher
    );

    const payload: any = {
      action: 'opened',
      number: 42,
      pull_request: {
        number: 42,
        title: 'Title',
        body: 'Body',
        head: { sha: 'commit-already-reviewed' }
      },
      repository: { name: 'repo', owner: { login: 'org' } },
      installation: { id: 12345 }
    };

    await orchestrator.handlePullRequest(payload);

    expect(publisher.hasReviewForCommit).toHaveBeenCalledWith(
      mockOctokit,
      'org',
      'repo',
      42,
      'commit-already-reviewed'
    );
    expect(mockDiffService.getDiffFetchResult).not.toHaveBeenCalled();
    expect(mockGeminiClient.reviewDiff).not.toHaveBeenCalled();
    expect(mockCreateReview).not.toHaveBeenCalled();
  });

  it('should abort review publication if PR head SHA changed while review was running', async () => {
    const mockCreateReview = vi.fn();
    let getCallCount = 0;
    const mockOctokit: any = {
      rest: {
        pulls: {
          createReview: mockCreateReview,
          get: vi.fn().mockImplementation(() => {
            getCallCount++;
            if (getCallCount === 1) {
              // Pre-analysis check matches initial SHA
              return Promise.resolve({ data: { head: { sha: 'sha-v1' } } });
            }
            // Pre-publication check reveals a newer commit has landed
            return Promise.resolve({ data: { head: { sha: 'sha-v2-newer' } } });
          })
        }
      }
    };

    const mockGithubFactory: any = {
      getInstallationClient: vi.fn().mockResolvedValue(mockOctokit)
    };
    const mockDiffService: any = {
      getDiffFetchResult: vi.fn().mockResolvedValue({
        reviewableFiles: [
          {
            filename: 'index.ts',
            patch: '@@ -1,1 +1,2 @@\n+const x = 1;\n',
            additions: 1,
            deletions: 0,
            changes: 1
          }
        ],
        skippedFiles: [],
        totalChangedLines: 1,
        totalFilesReturned: 1,
        isTruncated: false
      })
    };
    const mockGeminiClient: any = {
      reviewDiff: vi.fn().mockResolvedValue({ summary: 'Looks fine', findings: [] })
    };
    const publisher = new ReviewPublisher();
    vi.spyOn(publisher, 'hasReviewForCommit').mockResolvedValue(false);
    const publishSpy = vi.spyOn(publisher, 'publishReview');

    const orchestrator = new ReviewOrchestrator(
      mockGithubFactory,
      mockDiffService,
      new DiffParser(),
      new SecretScannerRule(),
      new DebugStatementsRule(),
      mockGeminiClient,
      new ReviewAggregator(),
      publisher
    );

    const payload: any = {
      action: 'synchronize',
      number: 42,
      pull_request: {
        number: 42,
        title: 'Title',
        body: 'Body',
        head: { sha: 'sha-v1' }
      },
      repository: { name: 'repo', owner: { login: 'org' } },
      installation: { id: 12345 }
    };

    await orchestrator.handlePullRequest(payload);

    // AI analysis ran on sha-v1, but publish was aborted because head advanced to sha-v2-newer
    expect(mockGeminiClient.reviewDiff).toHaveBeenCalled();
    expect(publishSpy).not.toHaveBeenCalled();
    expect(mockCreateReview).not.toHaveBeenCalled();
  });

  it('should integrate SecretScanner, BannedImports, DebugScanner, and DiffSanitizer end-to-end', async () => {
    const mockCreateReview = vi.fn().mockResolvedValue({ data: { id: 777 } });
    const mockOctokit: any = {
      rest: {
        pulls: {
          createReview: mockCreateReview
        }
      }
    };

    const mockGithubFactory: any = {
      getInstallationClient: vi.fn().mockResolvedValue(mockOctokit)
    };

    const rawPatch = `@@ -1,2 +1,6 @@
 const base = true;
+import { exec } from 'child_process';
+const AWS_KEY = "AKIA1234567890ABCDEF";
+debugger;
 export function handle() {}`;

    const mockDiffService: any = {
      getReviewableFiles: vi.fn().mockResolvedValue([
        {
          filename: 'src/handler.ts',
          patch: rawPatch,
          additions: 3,
          deletions: 0,
          changes: 3
        }
      ])
    };

    let receivedPatchText = '';
    const mockGeminiClient: any = {
      reviewDiff: vi.fn().mockImplementation((title, body, patchText) => {
        receivedPatchText = patchText;
        return Promise.resolve({
          summary: 'Code review completed with findings.',
          findings: []
        });
      })
    };

    const publisher = new ReviewPublisher();
    vi.spyOn(publisher, 'hasReviewForCommit').mockResolvedValue(false);

    const orchestrator = new ReviewOrchestrator(
      mockGithubFactory,
      mockDiffService,
      new DiffParser(),
      new SecretScannerRule(),
      new DebugStatementsRule(),
      mockGeminiClient,
      new ReviewAggregator(),
      publisher
    );

    const payload: any = {
      action: 'opened',
      number: 99,
      pull_request: {
        number: 99,
        title: 'Add handler with dependencies',
        body: 'Implemented handler logic',
        head: { sha: 'sha-stage3b-integration' }
      },
      repository: { name: 'app-repo', owner: { login: 'acme' } },
      installation: { id: 9999 }
    };

    await orchestrator.handlePullRequest(payload);

    // 1. Verify Gemini received SANITIZED diff (raw AWS key was redacted in prompt)
    expect(receivedPatchText).not.toContain('AKIA1234567890ABCDEF');
    expect(receivedPatchText).toContain('[REDACTED_AWS_ACCESS_KEY]');

    // 2. Verify all deterministic findings were detected and published
    expect(mockCreateReview).toHaveBeenCalledTimes(1);
    const publishedComments = mockCreateReview.mock.calls[0][0].comments;

    // Expected 3 inline comments on src/handler.ts:
    // - Line 2: Banned import (child_process)
    // - Line 3: Secret (AWS Key)
    // - Line 4: Debug artifact (debugger;)
    expect(publishedComments).toHaveLength(3);

    const importFinding = publishedComments.find((c: any) => c.line === 2);
    expect(importFinding.body).toContain('child_process');
    expect(importFinding.body).toContain('WARNING');

    const secretFinding = publishedComments.find((c: any) => c.line === 3);
    expect(secretFinding.body).toContain('AWS Access Key');
    expect(secretFinding.body).toContain('CRITICAL');

    const debugFinding = publishedComments.find((c: any) => c.line === 4);
    expect(debugFinding.body).toContain('JavaScript Debugger');
    expect(debugFinding.body).toContain('SUGGESTION');
  });

  describe('Graceful Degradation & Verdict Precedence Suite', () => {
    it('should gracefully degrade and publish deterministic rule findings when Gemini fails with GeminiReviewError', async () => {
      const mockCreateReview = vi.fn().mockResolvedValue({ data: { id: 101 } });
      const mockOctokit: any = {
        rest: {
          pulls: {
            createReview: mockCreateReview,
            get: vi.fn().mockResolvedValue({ data: { head: { sha: 'sha-degrade-1' } } })
          }
        }
      };

      const mockGithubFactory: any = {
        getInstallationClient: vi.fn().mockResolvedValue(mockOctokit)
      };

      const mockDiffService: any = {
        getDiffFetchResult: vi.fn().mockResolvedValue({
          reviewableFiles: [
            {
              filename: 'src/token.ts',
              status: 'modified',
              patch: '@@ -1,2 +1,3 @@\n+const token = "ghp_123456789012345678901234567890123456";\n export const ready = true;',
              additions: 1,
              deletions: 0,
              changes: 1
            }
          ],
          skippedFiles: [],
          totalChangedLines: 1,
          totalFilesReturned: 1,
          isTruncated: false
        })
      };

      const mockGeminiClient: any = {
        reviewDiff: vi.fn().mockRejectedValue(new GeminiReviewError('MAX_RETRIES_EXCEEDED', 'Gemini unavailable'))
      };

      const publisher = new ReviewPublisher();
      vi.spyOn(publisher, 'hasReviewForCommit').mockResolvedValue(false);

      const orchestrator = new ReviewOrchestrator(
        mockGithubFactory,
        mockDiffService,
        new DiffParser(),
        new SecretScannerRule(),
        new DebugStatementsRule(),
        mockGeminiClient,
        new ReviewAggregator(),
        publisher
      );

      const payload: any = {
        action: 'opened',
        number: 88,
        pull_request: {
          number: 88,
          title: 'Add token',
          body: 'Token commit',
          head: { sha: 'sha-degrade-1' }
        },
        repository: { name: 'repo', owner: { login: 'owner' } },
        installation: { id: 1 }
      };

      await orchestrator.handlePullRequest(payload);

      // Verify review was published despite Gemini failure
      expect(mockCreateReview).toHaveBeenCalledTimes(1);
      const call = mockCreateReview.mock.calls[0][0];
      expect(call.body).toContain('AI Semantic Review Unavailable');
      expect(call.body).toContain('Deterministic Rules Only');
      // Secret rule was preserved
      expect(call.comments).toHaveLength(1);
      expect(call.comments[0].body).toContain('GitHub Personal Access Token');
    });

    it('should strictly enforce REQUEST_CHANGES when critical secret exists even if Gemini review fails', async () => {
      setTestEnv({ REVIEW_EVENT_VERDICT: 'APPROVE' }); // Configured to APPROVE by default

      const mockCreateReview = vi.fn().mockResolvedValue({ data: { id: 102 } });
      const mockOctokit: any = {
        rest: {
          pulls: {
            createReview: mockCreateReview,
            get: vi.fn().mockResolvedValue({ data: { head: { sha: 'sha-degrade-2' } } })
          }
        }
      };

      const mockGithubFactory: any = { getInstallationClient: vi.fn().mockResolvedValue(mockOctokit) };
      const mockDiffService: any = {
        getDiffFetchResult: vi.fn().mockResolvedValue({
          reviewableFiles: [
            {
              filename: 'src/aws.ts',
              status: 'added',
              patch: '@@ -0,0 +1,2 @@\n+const key = "AKIA1234567890ABCDEF";',
              additions: 1,
              deletions: 0,
              changes: 1
            }
          ],
          skippedFiles: [],
          totalChangedLines: 1,
          totalFilesReturned: 1,
          isTruncated: false
        })
      };

      const mockGeminiClient: any = {
        reviewDiff: vi.fn().mockRejectedValue(new GeminiReviewError('UPSTREAM_ERROR', '503 Unavailable'))
      };

      const publisher = new ReviewPublisher();
      vi.spyOn(publisher, 'hasReviewForCommit').mockResolvedValue(false);

      const orchestrator = new ReviewOrchestrator(
        mockGithubFactory,
        mockDiffService,
        new DiffParser(),
        new SecretScannerRule(),
        new DebugStatementsRule(),
        mockGeminiClient,
        new ReviewAggregator(),
        publisher
      );

      const payload: any = {
        action: 'opened',
        number: 89,
        pull_request: {
          number: 89,
          title: 'AWS key commit',
          head: { sha: 'sha-degrade-2' }
        },
        repository: { name: 'repo', owner: { login: 'owner' } },
        installation: { id: 1 }
      };

      await orchestrator.handlePullRequest(payload);

      expect(mockCreateReview).toHaveBeenCalledTimes(1);
      // Even though REVIEW_EVENT_VERDICT was 'APPROVE', critical secret forces REQUEST_CHANGES
      expect(mockCreateReview.mock.calls[0][0].event).toBe('REQUEST_CHANGES');
    });

    it('should strictly downgrade APPROVE to COMMENT when clean PR Gemini review fails', async () => {
      setTestEnv({ REVIEW_EVENT_VERDICT: 'APPROVE' });

      const mockCreateReview = vi.fn().mockResolvedValue({ data: { id: 103 } });
      const mockOctokit: any = {
        rest: {
          pulls: {
            createReview: mockCreateReview,
            get: vi.fn().mockResolvedValue({ data: { head: { sha: 'sha-degrade-3' } } })
          }
        }
      };

      const mockGithubFactory: any = { getInstallationClient: vi.fn().mockResolvedValue(mockOctokit) };
      const mockDiffService: any = {
        getDiffFetchResult: vi.fn().mockResolvedValue({
          reviewableFiles: [
            {
              filename: 'src/clean.ts',
              status: 'modified',
              patch: '@@ -1,2 +1,3 @@\n+export const cleanValue = 42;\n',
              additions: 1,
              deletions: 0,
              changes: 1
            }
          ],
          skippedFiles: [],
          totalChangedLines: 1,
          totalFilesReturned: 1,
          isTruncated: false
        })
      };

      const mockGeminiClient: any = {
        reviewDiff: vi.fn().mockRejectedValue(new GeminiReviewError('TIMEOUT', 'Timeout'))
      };

      const publisher = new ReviewPublisher();
      vi.spyOn(publisher, 'hasReviewForCommit').mockResolvedValue(false);

      const orchestrator = new ReviewOrchestrator(
        mockGithubFactory,
        mockDiffService,
        new DiffParser(),
        new SecretScannerRule(),
        new DebugStatementsRule(),
        mockGeminiClient,
        new ReviewAggregator(),
        publisher
      );

      const payload: any = {
        action: 'opened',
        number: 90,
        pull_request: {
          number: 90,
          title: 'Clean code',
          head: { sha: 'sha-degrade-3' }
        },
        repository: { name: 'repo', owner: { login: 'owner' } },
        installation: { id: 1 }
      };

      await orchestrator.handlePullRequest(payload);

      expect(mockCreateReview).toHaveBeenCalledTimes(1);
      // Because AI was unavailable, APPROVE must NEVER be issued; downgraded to COMMENT
      expect(mockCreateReview.mock.calls[0][0].event).toBe('COMMENT');
      expect(mockCreateReview.mock.calls[0][0].body).toContain('AI Semantic Review Unavailable');
    });

    it('should rethrow unexpected TypeError without swallowing it', async () => {
      const mockGithubFactory: any = { getInstallationClient: vi.fn() };
      const mockDiffService: any = {
        getDiffFetchResult: vi.fn().mockResolvedValue({
          reviewableFiles: [
            {
              filename: 'src/file.ts',
              patch: '@@ -1 +1 @@\n+const x = 1;',
              additions: 1,
              deletions: 0,
              changes: 1
            }
          ],
          skippedFiles: []
        })
      };

      const mockGeminiClient: any = {
        reviewDiff: vi.fn().mockRejectedValue(new TypeError('Unexpected runtime null pointer'))
      };

      const publisher = new ReviewPublisher();
      vi.spyOn(publisher, 'hasReviewForCommit').mockResolvedValue(false);

      const orchestrator = new ReviewOrchestrator(
        mockGithubFactory,
        mockDiffService,
        new DiffParser(),
        new SecretScannerRule(),
        new DebugStatementsRule(),
        mockGeminiClient,
        new ReviewAggregator(),
        publisher
      );

      const payload: any = {
        action: 'opened',
        number: 91,
        pull_request: { number: 91, title: 'Test', head: { sha: 'sha-err' } },
        repository: { name: 'repo', owner: { login: 'owner' } },
        installation: { id: 1 }
      };

      await expect(orchestrator.handlePullRequest(payload)).rejects.toThrow(TypeError);
    });
  });
});


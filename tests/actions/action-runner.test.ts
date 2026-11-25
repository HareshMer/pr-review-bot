import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import { runAction } from '../../src/action-runner.js';
import { setActionTestEnv, resetActionEnv } from '../../src/config/env.js';
import { createActionOctokit } from '../../src/github/octokit.js';
import { ReviewOrchestrator } from '../../src/analyzer/orchestrator.js';

describe('GitHub Actions Runner (runAction)', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    resetActionEnv();
    setActionTestEnv({
      GITHUB_TOKEN: 'ghp_action_test_token',
      GITHUB_REPOSITORY: 'test-org/test-repo',
      GITHUB_EVENT_PATH: '/mock/path/github-event.json',
      GEMINI_API_KEY: 'test-gemini-key'
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    resetActionEnv();
  });

  it('should successfully instantiate action Octokit with user-agent', () => {
    const octokit = createActionOctokit('mock-token');
    expect(octokit).toBeDefined();
    expect(typeof octokit.rest.pulls.get).toBe('function');
  });

  it('should throw an error if GITHUB_EVENT_PATH does not exist', async () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(false);

    await expect(runAction()).rejects.toThrow('GITHUB_EVENT_PATH file not found');
  });

  it('should skip review gracefully if the payload is not a pull_request event', async () => {
    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    vi.spyOn(fs, 'readFileSync').mockReturnValue(JSON.stringify({
      action: 'created',
      issue: { number: 42 }
    }));

    const reviewSpy = vi.spyOn(ReviewOrchestrator.prototype, 'reviewTarget');

    await runAction();

    expect(reviewSpy).not.toHaveBeenCalled();
  });

  it('should parse PR event and invoke ReviewOrchestrator.reviewTarget with correct params', async () => {
    const mockPrEvent = {
      action: 'opened',
      pull_request: {
        number: 101,
        title: 'feat: add user authentication',
        body: 'Implements login and JWT verification',
        head: {
          sha: 'commit_sha_1234567890'
        }
      },
      repository: {
        name: 'test-repo',
        owner: {
          login: 'test-org'
        }
      }
    };

    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    vi.spyOn(fs, 'readFileSync').mockReturnValue(JSON.stringify(mockPrEvent));

    const reviewSpy = vi
      .spyOn(ReviewOrchestrator.prototype, 'reviewTarget')
      .mockResolvedValue();

    await runAction();

    expect(reviewSpy).toHaveBeenCalledTimes(1);
    const callArgs = reviewSpy.mock.calls[0][0];

    expect(callArgs.owner).toBe('test-org');
    expect(callArgs.repo).toBe('test-repo');
    expect(callArgs.pullNumber).toBe(101);
    expect(callArgs.headSha).toBe('commit_sha_1234567890');
    expect(callArgs.title).toBe('feat: add user authentication');
    expect(callArgs.body).toBe('Implements login and JWT verification');
    expect(callArgs.octokit).toBeDefined();
  });

  it('should fallback to GITHUB_REPOSITORY if repository is missing in event payload', async () => {
    const mockPrEvent = {
      action: 'synchronize',
      pull_request: {
        number: 77,
        title: 'fix: edge case bug',
        body: null,
        head: {
          sha: 'commit_sha_abcdef'
        }
      }
    };

    vi.spyOn(fs, 'existsSync').mockReturnValue(true);
    vi.spyOn(fs, 'readFileSync').mockReturnValue(JSON.stringify(mockPrEvent));

    const reviewSpy = vi
      .spyOn(ReviewOrchestrator.prototype, 'reviewTarget')
      .mockResolvedValue();

    await runAction();

    expect(reviewSpy).toHaveBeenCalledTimes(1);
    const callArgs = reviewSpy.mock.calls[0][0];
    expect(callArgs.owner).toBe('test-org');
    expect(callArgs.repo).toBe('test-repo');
    expect(callArgs.pullNumber).toBe(77);
  });
});


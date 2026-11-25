import { describe, it, expect, beforeEach } from 'vitest';
import { DiffService } from '../../src/github/diff-service.js';
import { setTestEnv } from '../../src/config/env.js';

describe('DiffService (Bounded Pagination & Missing Patch Taxonomy)', () => {
  let diffService: DiffService;

  beforeEach(() => {
    diffService = new DiffService();
    setTestEnv({
      MAX_DIFF_LINES_PER_PR: 100, // Small limit for testing
      MAX_FILE_SIZE_BYTES: 100 // 100 bytes patch limit for testing
    });
  });

  it('should stream multiple pages using octokit.paginate.iterator and collect all reviewable files', async () => {
    const page1 = [
      { filename: 'src/file1.ts', patch: '@@ -1,1 +1,2 @@\n+const a = 1;', additions: 1, deletions: 0, changes: 1 },
      { filename: 'src/file2.ts', patch: '@@ -1,1 +1,2 @@\n+const b = 2;', additions: 1, deletions: 0, changes: 1 }
    ];
    const page2 = [
      { filename: 'src/file3.ts', patch: '@@ -1,1 +1,2 @@\n+const c = 3;', additions: 1, deletions: 0, changes: 1 }
    ];

    async function* mockIterator() {
      yield { data: page1 };
      yield { data: page2 };
    }

    const mockOctokit: any = {
      rest: {
        pulls: {
          listFiles: async () => ({ data: page1 })
        }
      },
      paginate: {
        iterator: () => mockIterator()
      }
    };

    const result = await diffService.getDiffFetchResult(mockOctokit, 'org', 'repo', 1);

    expect(result.totalFilesReturned).toBe(3);
    expect(result.reviewableFiles).toHaveLength(3);
    expect(result.totalChangedLines).toBe(3);
    expect(result.isTruncated).toBe(false);
  });

  it('should stop pagination early when cumulative lines exceed MAX_DIFF_LINES_PER_PR', async () => {
    setTestEnv({ MAX_DIFF_LINES_PER_PR: 10 });

    const page1 = [
      { filename: 'src/small.ts', patch: 'small diff', additions: 5, deletions: 0, changes: 5 },
      { filename: 'src/large.ts', patch: 'large diff', additions: 10, deletions: 0, changes: 10 } // 5 + 10 = 15 > 10!
    ];
    const page2 = [
      { filename: 'src/unreached.ts', patch: 'unreached', additions: 1, deletions: 0, changes: 1 }
    ];

    let page2Fetched = false;
    async function* mockIterator() {
      yield { data: page1 };
      page2Fetched = true;
      yield { data: page2 };
    }

    const mockOctokit: any = {
      rest: {
        pulls: {
          listFiles: async () => ({ data: page1 })
        }
      },
      paginate: {
        iterator: () => mockIterator()
      }
    };

    const result = await diffService.getDiffFetchResult(mockOctokit, 'org', 'repo', 1);

    expect(result.isTruncated).toBe(true);
    expect(result.truncationReason).toBe('MAX_DIFF_LINES_EXCEEDED');
    expect(result.reviewableFiles).toHaveLength(1);
    expect(result.skippedFiles).toContainEqual(
      expect.objectContaining({ filename: 'src/large.ts', reason: 'EXCEEDED_PR_LINE_LIMIT' })
    );
    // Page 2 should never be fetched because pagination stopped early
    expect(page2Fetched).toBe(false);
  });

  it('should process exactly 1000 files without truncation when exactly 1000 files are returned', async () => {
    // Exactly 1000 files across two pages of 500
    const page1 = Array.from({ length: 500 }, (_, i) => ({
      filename: `src/file_${i}.ts`,
      patch: 'diff',
      additions: 0,
      deletions: 0,
      changes: 0
    }));
    const page2 = Array.from({ length: 500 }, (_, i) => ({
      filename: `src/file_${500 + i}.ts`,
      patch: 'diff',
      additions: 0,
      deletions: 0,
      changes: 0
    }));

    async function* mockIterator() {
      yield { data: page1 };
      yield { data: page2 };
    }

    const mockOctokit: any = {
      rest: {
        pulls: { listFiles: async () => ({ data: page1 }) }
      },
      paginate: {
        iterator: () => mockIterator()
      }
    };

    const result = await diffService.getDiffFetchResult(mockOctokit, 'org', 'repo', 1);

    expect(result.totalFilesReturned).toBe(1000);
    expect(result.reviewableFiles).toHaveLength(1000);
    expect(result.isTruncated).toBe(false);
    expect(result.truncationReason).toBeUndefined();
  });

  it('should process no more than 1000 files and set truncation metadata when 1001 files are available', async () => {
    // Exactly 1000 files + 1 additional file (1001 total available)
    const page1 = Array.from({ length: 1000 }, (_, i) => ({
      filename: `src/file_${i}.ts`,
      patch: 'diff',
      additions: 0,
      deletions: 0,
      changes: 0
    }));
    const page2 = [
      {
        filename: 'src/file_1000_overflow.ts',
        patch: 'diff',
        additions: 0,
        deletions: 0,
        changes: 0
      }
    ];

    let page3Called = false;
    async function* mockIterator() {
      yield { data: page1 };
      yield { data: page2 };
      page3Called = true;
      yield { data: [] };
    }

    const mockOctokit: any = {
      rest: {
        pulls: { listFiles: async () => ({ data: page1 }) }
      },
      paginate: {
        iterator: () => mockIterator()
      }
    };

    const result = await diffService.getDiffFetchResult(mockOctokit, 'org', 'repo', 1);

    // Exactly 1000 files processed, not 1001
    expect(result.totalFilesReturned).toBe(1000);
    expect(result.reviewableFiles).toHaveLength(1000);
    expect(result.isTruncated).toBe(true);
    expect(result.truncationReason).toBe('MAX_PAGINATED_FILES_EXCEEDED');
    expect(result.skippedFiles).toContainEqual(
      expect.objectContaining({
        filename: 'src/file_1000_overflow.ts',
        reason: 'EXCEEDED_PAGE_FILE_LIMIT'
      })
    );
    expect(page3Called).toBe(false);
  });

  it('should accurately classify missing patches according to evidence', async () => {
    const files = [
      { filename: 'src/deleted.ts', status: 'removed', patch: undefined, changes: 10 },
      { filename: 'assets/logo.png', status: 'modified', patch: undefined, changes: 0 },
      { filename: 'old-name.ts', status: 'renamed', patch: undefined, changes: 0 },
      { filename: 'src/huge-generated.js', status: 'modified', patch: undefined, changes: 5000 },
      { filename: 'src/unknown.xyz', status: 'modified', patch: undefined, changes: 0 }
    ];

    const mockOctokit: any = {
      rest: {
        pulls: {
          listFiles: async () => ({ data: files })
        }
      }
    };

    const result = await diffService.getDiffFetchResult(mockOctokit, 'org', 'repo', 1);

    expect(result.reviewableFiles).toHaveLength(0);
    expect(result.skippedFiles).toHaveLength(5);

    expect(result.skippedFiles.find(f => f.filename === 'src/deleted.ts')?.reason).toBe('REMOVED');
    expect(result.skippedFiles.find(f => f.filename === 'assets/logo.png')?.reason).toBe('NO_PATCH_BINARY_EXTENSION');
    expect(result.skippedFiles.find(f => f.filename === 'old-name.ts')?.reason).toBe('NO_PATCH_UNCHANGED_RENAME');
    expect(result.skippedFiles.find(f => f.filename === 'src/huge-generated.js')?.reason).toBe('NO_PATCH_GITHUB_OMITTED');
    expect(result.skippedFiles.find(f => f.filename === 'src/unknown.xyz')?.reason).toBe('NO_PATCH_UNKNOWN');
  });

  it('should enforce MAX_FILE_SIZE_BYTES on patch byte length independently from line count', async () => {
    setTestEnv({
      MAX_FILE_SIZE_BYTES: 20 // 20 bytes patch limit
    });

    const files = [
      {
        filename: 'src/oversized-patch.ts',
        patch: 'a'.repeat(50), // 50 bytes > 20 bytes
        additions: 1,
        deletions: 0,
        changes: 1 // only 1 line change, but patch is 50 bytes!
      }
    ];

    const mockOctokit: any = {
      rest: {
        pulls: {
          listFiles: async () => ({ data: files })
        }
      }
    };

    const result = await diffService.getDiffFetchResult(mockOctokit, 'org', 'repo', 1);

    expect(result.reviewableFiles).toHaveLength(0);
    expect(result.skippedFiles[0].reason).toBe('EXCEEDED_PATCH_SIZE_BYTES');
    expect(result.skippedFiles[0].details).toContain('Patch byte length (50 bytes) exceeded configured limit');
  });

  it('should enforce MAX_FILE_CHANGES_PER_FILE (1000 lines) independently', async () => {
    const files = [
      {
        filename: 'src/huge-diff.ts',
        patch: 'valid patch text',
        additions: 1001,
        deletions: 0,
        changes: 1001 // > 1000 lines
      }
    ];

    const mockOctokit: any = {
      rest: {
        pulls: {
          listFiles: async () => ({ data: files })
        }
      }
    };

    const result = await diffService.getDiffFetchResult(mockOctokit, 'org', 'repo', 1);

    expect(result.reviewableFiles).toHaveLength(0);
    expect(result.skippedFiles[0].reason).toBe('EXCEEDED_FILE_LINE_LIMIT');
  });

  it('should maintain backward-compatible getReviewableFiles public contract', async () => {
    const files = [
      {
        filename: 'src/good.ts',
        patch: 'valid patch',
        additions: 2,
        deletions: 0,
        changes: 2
      }
    ];

    const mockOctokit: any = {
      rest: {
        pulls: {
          listFiles: async () => ({ data: files })
        }
      }
    };

    const reviewable = await diffService.getReviewableFiles(mockOctokit, 'org', 'repo', 1);
    expect(Array.isArray(reviewable)).toBe(true);
    expect(reviewable[0].filename).toBe('src/good.ts');
  });
});

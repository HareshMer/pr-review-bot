import { Octokit } from '@octokit/rest';
import { CONSTANTS } from '../config/constants.js';
import { getEnv } from '../config/env.js';
import { logger } from '../utils/logger.js';

export interface ReviewableFile {
  filename: string;
  patch: string;
  additions: number;
  deletions: number;
  changes: number;
}

export type SkipReason =
  | 'REMOVED'
  | 'IGNORED_EXTENSION'
  | 'IGNORED_NAME'
  | 'IGNORED_PATH'
  | 'NO_PATCH_BINARY_EXTENSION'
  | 'NO_PATCH_UNCHANGED_RENAME'
  | 'NO_PATCH_GITHUB_OMITTED'
  | 'NO_PATCH_UNKNOWN'
  | 'EXCEEDED_FILE_LINE_LIMIT'
  | 'EXCEEDED_PATCH_SIZE_BYTES'
  | 'EXCEEDED_PR_LINE_LIMIT'
  | 'EXCEEDED_PAGE_FILE_LIMIT';

export interface SkippedFile {
  filename: string;
  reason: SkipReason;
  details?: string;
}

export interface DiffFetchResult {
  reviewableFiles: ReviewableFile[];
  skippedFiles: SkippedFile[];
  totalChangedLines: number;
  totalFilesReturned: number;
  isTruncated: boolean;
  truncationReason?: 'MAX_DIFF_LINES_EXCEEDED' | 'MAX_PAGINATED_FILES_EXCEEDED';
}

export class DiffService {
  /**
   * Fetches changed files using bounded pagination (octokit.paginate.iterator) and applies
   * precise multi-layer filtering and resource limit checks.
   * Tracks skipped files with fine-grained reasons and flags if PR analysis is truncated.
   */
  public async getDiffFetchResult(
    octokit: Octokit,
    owner: string,
    repo: string,
    pullNumber: number
  ): Promise<DiffFetchResult> {
    const env = getEnv();
    logger.debug({ owner, repo, pullNumber }, 'Fetching PR changed files with bounded pagination');

    const reviewableFiles: ReviewableFile[] = [];
    const skippedFiles: SkippedFile[] = [];
    let totalChangedLines = 0;
    let totalFilesReturned = 0;
    let isTruncated = false;
    let truncationReason: DiffFetchResult['truncationReason'];

    // Stream pages using octokit.paginate.iterator if available, falling back to listFiles
    if (octokit.paginate && typeof octokit.paginate.iterator === 'function' && octokit.rest?.pulls?.listFiles) {
      const iterator = octokit.paginate.iterator(octokit.rest.pulls.listFiles, {
        owner,
        repo,
        pull_number: pullNumber,
        per_page: 100
      });

      for await (const response of iterator) {
        const pageFiles = response.data;

        for (const file of pageFiles) {
          // 1. Check max total files safety limit across pages
          if (totalFilesReturned >= CONSTANTS.MAX_PAGINATED_FILES) {
            isTruncated = true;
            truncationReason = 'MAX_PAGINATED_FILES_EXCEEDED';
            skippedFiles.push({
              filename: file.filename,
              reason: 'EXCEEDED_PAGE_FILE_LIMIT',
              details: `Total files exceeded maximum safety limit (${CONSTANTS.MAX_PAGINATED_FILES})`
            });
            break;
          }

          totalFilesReturned++;
          const skipDecision = this.evaluateFile(file, totalChangedLines, env);
          if (skipDecision.skip) {
            skippedFiles.push(skipDecision.skippedFile);
            if (skipDecision.stopPagination) {
              isTruncated = true;
              truncationReason = 'MAX_DIFF_LINES_EXCEEDED';
              break;
            }
            continue;
          }

          totalChangedLines += file.changes;
          reviewableFiles.push({
            filename: file.filename,
            patch: file.patch!,
            additions: file.additions,
            deletions: file.deletions,
            changes: file.changes
          });
        }

        if (isTruncated) {
          logger.warn(
            { truncationReason, totalFilesReturned, totalChangedLines },
            'Stopping pagination iterator early due to resource limit'
          );
          break;
        }
      }
    } else {
      // Direct call fallback
      const response = await octokit.rest.pulls.listFiles({
        owner,
        repo,
        pull_number: pullNumber,
        per_page: 100
      });

      for (const file of response.data) {
        if (totalFilesReturned >= CONSTANTS.MAX_PAGINATED_FILES) {
          isTruncated = true;
          truncationReason = 'MAX_PAGINATED_FILES_EXCEEDED';
          skippedFiles.push({
            filename: file.filename,
            reason: 'EXCEEDED_PAGE_FILE_LIMIT',
            details: `Total files exceeded maximum safety limit (${CONSTANTS.MAX_PAGINATED_FILES})`
          });
          break;
        }

        totalFilesReturned++;
        const skipDecision = this.evaluateFile(file, totalChangedLines, env);
        if (skipDecision.skip) {
          skippedFiles.push(skipDecision.skippedFile);
          if (skipDecision.stopPagination) {
            isTruncated = true;
            truncationReason = 'MAX_DIFF_LINES_EXCEEDED';
            break;
          }
          continue;
        }

        totalChangedLines += file.changes;
        reviewableFiles.push({
          filename: file.filename,
          patch: file.patch!,
          additions: file.additions,
          deletions: file.deletions,
          changes: file.changes
        });
      }
    }

    logger.info(
      {
        totalFilesReturned,
        reviewableFiles: reviewableFiles.length,
        skippedFiles: skippedFiles.length,
        totalChangedLines,
        isTruncated
      },
      'PR diff files bounded pagination and classification completed'
    );

    return {
      reviewableFiles,
      skippedFiles,
      totalChangedLines,
      totalFilesReturned,
      isTruncated,
      truncationReason
    };
  }

  /**
   * Backward-compatible public API wrapper returning ReviewableFile[].
   */
  public async getReviewableFiles(
    octokit: Octokit,
    owner: string,
    repo: string,
    pullNumber: number
  ): Promise<ReviewableFile[]> {
    const result = await this.getDiffFetchResult(octokit, owner, repo, pullNumber);
    return result.reviewableFiles;
  }

  private evaluateFile(
    file: any,
    currentCumulativeLines: number,
    env: any
  ): { skip: true; skippedFile: SkippedFile; stopPagination?: boolean } | { skip: false } {
    // 1. Deleted files
    if (file.status === 'removed') {
      return {
        skip: true,
        skippedFile: { filename: file.filename, reason: 'REMOVED', details: 'File was deleted' }
      };
    }

    // 2. Missing patch evaluation
    if (!file.patch) {
      const ext = this.getFileExtension(file.filename);
      if (CONSTANTS.IGNORED_FILE_EXTENSIONS.has(ext)) {
        return {
          skip: true,
          skippedFile: {
            filename: file.filename,
            reason: 'NO_PATCH_BINARY_EXTENSION',
            details: `Known binary extension (${ext}) without diff patch`
          }
        };
      }
      if (file.status === 'renamed' && file.changes === 0) {
        return {
          skip: true,
          skippedFile: {
            filename: file.filename,
            reason: 'NO_PATCH_UNCHANGED_RENAME',
            details: 'File renamed with no content changes'
          }
        };
      }
      if (file.changes > 0) {
        return {
          skip: true,
          skippedFile: {
            filename: file.filename,
            reason: 'NO_PATCH_GITHUB_OMITTED',
            details: `GitHub omitted diff patch (file changes: ${file.changes})`
          }
        };
      }
      return {
        skip: true,
        skippedFile: {
          filename: file.filename,
          reason: 'NO_PATCH_UNKNOWN',
          details: 'Diff patch was not provided by GitHub API'
        }
      };
    }

    // 3. Ignored extensions
    const ext = this.getFileExtension(file.filename);
    if (CONSTANTS.IGNORED_FILE_EXTENSIONS.has(ext)) {
      return {
        skip: true,
        skippedFile: {
          filename: file.filename,
          reason: 'IGNORED_EXTENSION',
          details: `Extension ${ext} is excluded from code review`
        }
      };
    }

    // 4. Ignored exact filenames (e.g. lockfiles)
    const baseName = this.getBaseName(file.filename);
    if (CONSTANTS.IGNORED_FILE_NAMES.has(baseName)) {
      return {
        skip: true,
        skippedFile: {
          filename: file.filename,
          reason: 'IGNORED_NAME',
          details: `Lockfile or generated file ${baseName} is excluded from review`
        }
      };
    }

    // 5. Ignored path prefixes (e.g. dist/, node_modules/)
    if (CONSTANTS.IGNORED_PATH_PREFIXES.some(prefix => file.filename.startsWith(prefix))) {
      return {
        skip: true,
        skippedFile: {
          filename: file.filename,
          reason: 'IGNORED_PATH',
          details: 'File resides in an ignored build artifact or vendor directory'
        }
      };
    }

    // 6. Check patch byte size (Buffer.byteLength measures patch bytes, not complete source file size)
    const patchByteSize = Buffer.byteLength(file.patch, 'utf8');
    if (patchByteSize > env.MAX_FILE_SIZE_BYTES) {
      return {
        skip: true,
        skippedFile: {
          filename: file.filename,
          reason: 'EXCEEDED_PATCH_SIZE_BYTES',
          details: `Patch byte length (${patchByteSize} bytes) exceeded configured limit (${env.MAX_FILE_SIZE_BYTES} bytes)`
        }
      };
    }

    // 7. Check per-file line changes
    if (file.changes > CONSTANTS.MAX_FILE_CHANGES_PER_FILE) {
      return {
        skip: true,
        skippedFile: {
          filename: file.filename,
          reason: 'EXCEEDED_FILE_LINE_LIMIT',
          details: `File changes (${file.changes} lines) exceeded per-file limit (${CONSTANTS.MAX_FILE_CHANGES_PER_FILE} lines)`
        }
      };
    }

    // 8. Cumulative PR line limit check
    if (currentCumulativeLines + file.changes > env.MAX_DIFF_LINES_PER_PR) {
      return {
        skip: true,
        stopPagination: true,
        skippedFile: {
          filename: file.filename,
          reason: 'EXCEEDED_PR_LINE_LIMIT',
          details: `Total lines exceeded max PR threshold (${env.MAX_DIFF_LINES_PER_PR} lines)`
        }
      };
    }

    return { skip: false };
  }

  private getFileExtension(filename: string): string {
    const lastDot = filename.lastIndexOf('.');
    if (lastDot === -1) return '';
    return filename.slice(lastDot).toLowerCase();
  }

  private getBaseName(filename: string): string {
    const parts = filename.split('/');
    return parts[parts.length - 1];
  }
}



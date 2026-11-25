import parseDiff, { File as ParsedFile } from 'parse-diff';
import { ReviewableFile } from './diff-service.js';
import { logger } from '../utils/logger.js';

export interface DiffBoundaryMap {
  /**
   * Set of valid line numbers on the 'RIGHT' (new) side of the diff hunk for each file.
   * Comments can ONLY be posted to lines in this set.
   */
  validLinesPerFile: Map<string, Set<number>>;
  parsedFiles: ParsedFile[];
}

export class DiffParser {
  /**
   * Parses reviewable file patches into unified diff ASTs and builds a lookup map
   * of valid line numbers where GitHub permits inline review comments.
   */
  public parseReviewableFiles(files: ReviewableFile[]): DiffBoundaryMap {
    const validLinesPerFile = new Map<string, Set<number>>();
    const allParsedFiles: ParsedFile[] = [];

    for (const file of files) {
      const validLines = new Set<number>();

      try {
        const patchWithHeader = file.patch.startsWith('---')
          ? file.patch
          : `--- a/${file.filename}\n+++ b/${file.filename}\n${file.patch}`;

        const parsed = parseDiff(patchWithHeader);

        for (const pf of parsed) {
          if (!pf.to) pf.to = file.filename;
          if (!pf.from) pf.from = file.filename;
          allParsedFiles.push(pf);

          for (const chunk of pf.chunks) {
            for (const change of chunk.changes) {
              // In parse-diff:
              // 'add' change has ln (line number in new file)
              // 'normal' context line has ln2 (line number in new file)
              if (change.type === 'add' && change.ln) {
                validLines.add(change.ln);
              } else if (change.type === 'normal' && change.ln2) {
                validLines.add(change.ln2);
              }
            }
          }
        }
      } catch (error) {
        logger.error({ file: file.filename, err: error }, 'Failed to parse diff patch with parse-diff');
      }

      validLinesPerFile.set(file.filename, validLines);
    }

    return {
      validLinesPerFile,
      parsedFiles: allParsedFiles
    };
  }

  /**
   * Helper to verify if a candidate line is within the reviewable diff hunk boundaries.
   */
  public static isLineWithinDiff(
    boundaryMap: Map<string, Set<number>>,
    filePath: string,
    line: number
  ): boolean {
    const allowed = boundaryMap.get(filePath);
    if (!allowed) {
      return false;
    }
    return allowed.has(line);
  }
}

import { describe, it, expect } from 'vitest';
import { DiffParser } from '../../src/github/diff-parser.js';
import { ReviewableFile } from '../../src/github/diff-service.js';

describe('DiffParser & Hunk Boundary Enforcement', () => {
  const samplePatch = `@@ -10,4 +10,6 @@ function test() {
   const a = 1;
+  const b = 2;
+  const c = 3;
   return a;
 }`;

  const files: ReviewableFile[] = [
    {
      filename: 'src/index.ts',
      patch: samplePatch,
      additions: 2,
      deletions: 0,
      changes: 2
    }
  ];

  it('should parse hunk changes and identify valid line numbers on the RIGHT side', () => {
    const parser = new DiffParser();
    const result = parser.parseReviewableFiles(files);

    const validLines = result.validLinesPerFile.get('src/index.ts');
    expect(validLines).toBeDefined();

    // Line 10 is 'const a = 1' (normal context line)
    // Line 11 is 'const b = 2' (added line)
    // Line 12 is 'const c = 3' (added line)
    // Line 13 is 'return a;' (normal context line)
    expect(validLines?.has(10)).toBe(true);
    expect(validLines?.has(11)).toBe(true);
    expect(validLines?.has(12)).toBe(true);
    expect(validLines?.has(13)).toBe(true);

    // Line 1, line 50, line 999 are OUTSIDE the hunk
    expect(validLines?.has(1)).toBe(false);
    expect(validLines?.has(50)).toBe(false);
  });

  it('should accurately verify isLineWithinDiff', () => {
    const parser = new DiffParser();
    const result = parser.parseReviewableFiles(files);

    expect(DiffParser.isLineWithinDiff(result.validLinesPerFile, 'src/index.ts', 11)).toBe(true);
    expect(DiffParser.isLineWithinDiff(result.validLinesPerFile, 'src/index.ts', 99)).toBe(false);
    expect(DiffParser.isLineWithinDiff(result.validLinesPerFile, 'src/other.ts', 11)).toBe(false);
  });

  it('should parse multi-hunk discontinuous diffs separated by hundreds of lines', () => {
    const multiHunkPatch = `@@ -10,3 +10,4 @@ function start() {
   const x = 1;
+  const y = 2;
   return x;
 }
@@ -500,3 +501,4 @@ function end() {
   const a = 10;
+  const b = 20;
   return a;
 }`;

    const parser = new DiffParser();
    const result = parser.parseReviewableFiles([
      { filename: 'src/long.ts', patch: multiHunkPatch, additions: 2, deletions: 0, changes: 2 }
    ]);

    const validLines = result.validLinesPerFile.get('src/long.ts')!;
    // First hunk lines
    expect(validLines.has(10)).toBe(true);
    expect(validLines.has(11)).toBe(true);
    expect(validLines.has(12)).toBe(true);

    // Second hunk lines
    expect(validLines.has(501)).toBe(true);
    expect(validLines.has(502)).toBe(true);
    expect(validLines.has(503)).toBe(true);

    // Discontinuous lines in between MUST be invalid
    expect(validLines.has(50)).toBe(false);
    expect(validLines.has(250)).toBe(false);
    expect(validLines.has(499)).toBe(false);
  });

  it('should correctly handle pure addition diffs (new files)', () => {
    const newFilePatch = `@@ -0,0 +1,3 @@
+export const FOO = 'bar';
+export const BAZ = 'qux';
+export default true;`;

    const parser = new DiffParser();
    const result = parser.parseReviewableFiles([
      { filename: 'src/constants.ts', patch: newFilePatch, additions: 3, deletions: 0, changes: 3 }
    ]);

    const validLines = result.validLinesPerFile.get('src/constants.ts')!;
    expect(validLines.has(1)).toBe(true);
    expect(validLines.has(2)).toBe(true);
    expect(validLines.has(3)).toBe(true);
    expect(validLines.has(4)).toBe(false);
  });

  it('should exclude deleted-only hunks from validLines (no new lines on RIGHT side)', () => {
    const deletionPatch = `@@ -20,4 +20,0 @@
-const oldVar1 = 1;
-const oldVar2 = 2;
-const oldVar3 = 3;
-const oldVar4 = 4;`;

    const parser = new DiffParser();
    const result = parser.parseReviewableFiles([
      { filename: 'src/legacy.ts', patch: deletionPatch, additions: 0, deletions: 4, changes: 4 }
    ]);

    const validLines = result.validLinesPerFile.get('src/legacy.ts')!;
    // Deletions exist only on LEFT side; validLines for RIGHT side should be empty
    expect(validLines.size).toBe(0);
  });

  it('should parse diffs with \\ No newline at end of file marker without throwing', () => {
    const patchWithNoNewline = `@@ -1,2 +1,3 @@
 const a = 1;
+const b = 2;
\\ No newline at end of file`;

    const parser = new DiffParser();
    const result = parser.parseReviewableFiles([
      { filename: 'src/nonewline.ts', patch: patchWithNoNewline, additions: 1, deletions: 0, changes: 1 }
    ]);

    const validLines = result.validLinesPerFile.get('src/nonewline.ts')!;
    expect(validLines.has(2)).toBe(true);
  });
});


import { describe, it, expect } from 'vitest';
import { ReviewAggregator } from '../../src/analyzer/aggregator.js';
import { DiffBoundaryMap } from '../../src/github/diff-parser.js';
import { Finding } from '../../src/analyzer/rules/secret-scanner.js';
import { ReviewFinding } from '../../src/analyzer/llm/schemas.js';

describe('ReviewAggregator', () => {
  const aggregator = new ReviewAggregator();

  const mockBoundaryMap: DiffBoundaryMap = {
    validLinesPerFile: new Map([
      ['src/file.ts', new Set([10, 11, 12])]
    ]),
    parsedFiles: []
  };

  it('should merge rule and AI findings and filter out-of-bounds findings', () => {
    const ruleFindings: Finding[] = [
      {
        path: 'src/file.ts',
        line: 11,
        severity: 'CRITICAL',
        category: 'SECURITY',
        title: 'Rule Found Secret',
        message: 'A secret was found',
        source: 'RULE'
      }
    ];

    const aiFindings: ReviewFinding[] = [
      {
        path: 'src/file.ts',
        line: 12,
        severity: 'WARNING',
        category: 'BUG',
        title: 'Off by one',
        message: 'Loop condition is off by one',
        suggestion: 'i < length',
        confidence: 0.9
      },
      {
        // Line 999 is OUTSIDE diff bounds!
        path: 'src/file.ts',
        line: 999,
        severity: 'SUGGESTION',
        category: 'CODE_QUALITY',
        title: 'Hallucinated or out-of-diff line',
        message: 'This line is outside the PR diff',
        confidence: 0.75
      }
    ];

    const result = aggregator.aggregate(
      ruleFindings,
      aiFindings,
      'AI PR Summary',
      mockBoundaryMap
    );

    // Only line 11 and line 12 should be in valid inline findings
    expect(result.validInlineFindings).toHaveLength(2);
    expect(result.validInlineFindings[0].line).toBe(11); // CRITICAL comes first
    expect(result.validInlineFindings[1].line).toBe(12); // WARNING comes next

    // Line 999 should be captured in outOfBoundsFindings
    expect(result.outOfBoundsFindings).toHaveLength(1);
    expect(result.outOfBoundsFindings[0].line).toBe(999);
  });

  it('should deduplicate findings on the same line with same category', () => {
    const ruleFindings: Finding[] = [
      {
        path: 'src/file.ts',
        line: 10,
        severity: 'CRITICAL',
        category: 'SECURITY',
        title: 'Secret key leak',
        message: 'Detected by rule',
        source: 'RULE'
      }
    ];

    const aiFindings: ReviewFinding[] = [
      {
        path: 'src/file.ts',
        line: 10,
        severity: 'CRITICAL',
        category: 'SECURITY',
        title: 'Potential credential leak',
        message: 'Detected by AI',
        suggestion: 'process.env.SECRET',
        confidence: 0.95
      }
    ];

    const result = aggregator.aggregate(
      ruleFindings,
      aiFindings,
      'Summary',
      mockBoundaryMap
    );

    // Should only have 1 finding for line 10 SECURITY
    expect(result.validInlineFindings).toHaveLength(1);
    expect(result.validInlineFindings[0].source).toBe('RULE');
  });
});


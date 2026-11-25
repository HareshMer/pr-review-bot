import { Finding } from './rules/secret-scanner.js';
import { ReviewFinding } from './llm/schemas.js';
import { DiffBoundaryMap, DiffParser } from '../github/diff-parser.js';
import { CONSTANTS } from '../config/constants.js';
import { logger } from '../utils/logger.js';

export interface AggregatedFinding {
  path: string;
  line: number;
  severity: 'CRITICAL' | 'WARNING' | 'SUGGESTION';
  category: 'BUG' | 'SECURITY' | 'PERFORMANCE' | 'CODE_QUALITY' | 'BEST_PRACTICE';
  title: string;
  message: string;
  suggestion?: string;
  confidence?: number;
  source: 'RULE' | 'AI';
  ruleId?: string;
}

export interface ReviewAggregationResult {
  validInlineFindings: AggregatedFinding[];
  outOfBoundsFindings: AggregatedFinding[];
  summary: string;
}

export class ReviewAggregator {
  public aggregate(
    ruleFindings: Finding[],
    aiFindings: ReviewFinding[],
    aiSummary: string,
    boundaryMap: DiffBoundaryMap
  ): ReviewAggregationResult {
    const combined: AggregatedFinding[] = [];

    // 1. Add rule findings (deterministic rules have confidence 1.0)
    for (const rf of ruleFindings) {
      combined.push({
        ...rf,
        confidence: 1.0
      });
    }

    // 2. Add AI findings
    for (const af of aiFindings) {
      combined.push({
        path: af.path,
        line: af.line,
        severity: af.severity,
        category: af.category,
        title: af.title,
        message: af.message,
        suggestion: af.suggestion,
        confidence: af.confidence,
        source: 'AI'
      });
    }

    // 3. Deduplicate
    const deduped: AggregatedFinding[] = [];
    const seenRuleKeys = new Set<string>(); // path:line:ruleId
    const seenRuleCategories = new Set<string>(); // path:line:category (where rule exists)
    const seenAiKeys = new Set<string>(); // path:line:category:normalizedTitle

    for (const item of combined) {
      if (item.source === 'RULE') {
        const ruleIdKey = item.ruleId
          ? `${item.path}:${item.line}:${item.ruleId}`
          : `${item.path}:${item.line}:${item.title}`;

        if (!seenRuleKeys.has(ruleIdKey)) {
          seenRuleKeys.add(ruleIdKey);
          seenRuleCategories.add(`${item.path}:${item.line}:${item.category}`);
          deduped.push(item);
        }
      } else {
        // AI finding
        // If a deterministic rule already covered this exact path, line, and category:
        // Deduplicate against the rule (rule takes precedence)
        const ruleCategoryKey = `${item.path}:${item.line}:${item.category}`;
        if (seenRuleCategories.has(ruleCategoryKey)) {
          continue;
        }

        const normalizedTitle = item.title.toLowerCase().replace(/[^a-z0-9]/g, '');
        const aiKey = `${item.path}:${item.line}:${item.category}:${normalizedTitle}`;
        if (!seenAiKeys.has(aiKey)) {
          seenAiKeys.add(aiKey);
          deduped.push(item);
        }
      }
    }

    // 4. Sort by severity: CRITICAL first, then WARNING, then SUGGESTION
    const severityWeight: Record<string, number> = {
      CRITICAL: 3,
      WARNING: 2,
      SUGGESTION: 1
    };

    deduped.sort((a, b) => severityWeight[b.severity] - severityWeight[a.severity]);

    // 5. Partition by Diff Hunk Boundaries
    const validInlineFindings: AggregatedFinding[] = [];
    const outOfBoundsFindings: AggregatedFinding[] = [];

    for (const finding of deduped) {
      const isWithinDiff = DiffParser.isLineWithinDiff(
        boundaryMap.validLinesPerFile,
        finding.path,
        finding.line
      );

      if (isWithinDiff) {
        if (validInlineFindings.length < CONSTANTS.MAX_COMMENTS_PER_REVIEW) {
          validInlineFindings.push(finding);
        }
      } else {
        logger.debug(
          { file: finding.path, line: finding.line, title: finding.title },
          'Finding target line is outside diff hunks; omitting as inline comment'
        );
        outOfBoundsFindings.push(finding);
      }
    }

    return {
      validInlineFindings,
      outOfBoundsFindings,
      summary: aiSummary
    };
  }
}


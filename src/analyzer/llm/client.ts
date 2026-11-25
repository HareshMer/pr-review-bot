import { GoogleGenAI } from '@google/genai';
import { CONSTANTS } from '../../config/constants.js';
import { getEnv } from '../../config/env.js';
import { logger } from '../../utils/logger.js';
import { REVIEW_SYSTEM_PROMPT, buildReviewUserPrompt } from './prompts.js';
import {
  ReviewOutput,
  ReviewOutputSchema,
  GEMINI_REVIEW_RESPONSE_SCHEMA
} from './schemas.js';

export type GeminiErrorCode =
  | 'TIMEOUT'
  | 'RATE_LIMITED'
  | 'MAX_RETRIES_EXCEEDED'
  | 'TRUNCATED_OUTPUT'
  | 'MALFORMED_OUTPUT'
  | 'VALIDATION_ERROR'
  | 'UPSTREAM_ERROR';

export class GeminiReviewError extends Error {
  constructor(
    public readonly code: GeminiErrorCode,
    message: string,
    public readonly cause?: unknown
  ) {
    super(message);
    this.name = 'GeminiReviewError';
  }
}

export interface ReviewExecutionResult {
  output: ReviewOutput;
  modelUsed: string;
  attemptsCount: number;
  totalElapsedMs: number;
}

export interface ErrorClassification {
  code: GeminiErrorCode;
  action: 'FAIL_FAST' | 'RETRY_SAME_MODEL' | 'DEGRADE';
  canFailover: boolean;
  message: string;
}

/**
 * Estimates token consumption for diff text.
 * Heuristic: ~3.8 characters per token for code/diffs + 10 tokens per line overhead.
 */
export function estimateDiffTokens(patchText: string): { estimatedTokens: number; lineCount: number } {
  const lineCount = (patchText.match(/\n/g) || []).length + 1;
  const estimatedTokens = Math.ceil(patchText.length / 3.8) + lineCount * 10;
  return { estimatedTokens, lineCount };
}

export class GeminiReviewClient {
  private ai: GoogleGenAI;

  constructor(aiClient?: GoogleGenAI) {
    const env = getEnv();
    this.ai = aiClient || new GoogleGenAI({ apiKey: env.GEMINI_API_KEY });
  }

  /**
   * Reviews unified diff content with Google Gemini using multi-model failover.
   * Enforces:
   * 1. Multi-model cascade across primary and fallback models.
   * 2. Shared 120s bounded total execution deadline strictly preserved across all models and retries.
   * 3. Clamped per-attempt timeout so individual requests never exceed remaining shared deadline.
   * 4. Exponential backoff with jitter and Retry-After support for transient failures (429, 503, 500, network).
   * 5. Structured output enforcement with GEMINI_REVIEW_RESPONSE_SCHEMA.
   * 6. Fast-fail for permanent errors (400, 401, 403, 404).
   * 7. Strict Zod validation without silent failure swallowing.
   */
  public async reviewDiff(
    prTitle: string,
    prDescription: string | null,
    patchText: string
  ): Promise < ReviewExecutionResult > {
      const env = getEnv();
      const prompt = buildReviewUserPrompt(prTitle, prDescription, patchText);

      const tokenBudget = estimateDiffTokens(patchText);
      const candidateModels = [env.GEMINI_MODEL, ...(env.GEMINI_FALLBACK_MODELS || [])];

      logger.debug(
        {
          primaryModel: env.GEMINI_MODEL,
          candidateModels,
          estimatedTokens: tokenBudget.estimatedTokens,
          lineCount: tokenBudget.lineCount
        },
      'Starting Gemini multi-model review cascade'
      );

      const attemptTimeoutMs = env.GEMINI_TIMEOUT_MS;
      const totalDeadlineMs = env.GEMINI_TOTAL_TIMEOUT_MS;
      const maxRetries = env.GEMINI_MAX_RETRIES;
      const baseDelayMs = env.GEMINI_RETRY_BASE_DELAY_MS ?? CONSTANTS.DEFAULT_GEMINI_RETRY_BASE_DELAY_MS;
      const maxDelayMs = env.GEMINI_RETRY_MAX_DELAY_MS ?? CONSTANTS.DEFAULT_GEMINI_RETRY_MAX_DELAY_MS;

      const startTime = Date.now();
      const overallDeadline = startTime + totalDeadlineMs;
      let lastError: unknown;
      let totalAttemptsCount = 0;

      for (let modelIdx = 0; modelIdx < candidateModels.length; modelIdx++) {
        const currentModel = candidateModels[modelIdx];
        const isLastModel = modelIdx === candidateModels.length - 1;

        logger.debug(
          { model: currentModel, modelIdx, totalModels: candidateModels.length },
          'Attempting review with Gemini model'
        );

        for (let attempt = 0; attempt <= maxRetries; attempt++) {
          totalAttemptsCount++;

              const remainingTotalMs = overallDeadline - Date.now();
              if (remainingTotalMs <= 100) {
                throw new GeminiReviewError(
            'TIMEOUT',
                  `Gemini total execution deadline exceeded (${totalDeadlineMs}ms overall deadline elapsed)`,
                  lastError
                );
              }

              // Bound per-attempt timeout to not exceed remaining total deadline
              const currentAttemptTimeout = Math.max(100, Math.min(attemptTimeoutMs, remainingTotalMs));
              const controller = new AbortController();
              let timedOut = false;

              const timeoutId = setTimeout(() => {
                timedOut = true;
                controller.abort(new Error(`Gemini request timed out after ${currentAttemptTimeout}ms`));
              }, currentAttemptTimeout);

              try {
              const response = await this.ai.models.generateContent({
                model: currentModel,
                contents: prompt,
                config: {
                  systemInstruction: REVIEW_SYSTEM_PROMPT,
                  responseMimeType: 'application/json',
                  responseSchema: GEMINI_REVIEW_RESPONSE_SCHEMA,
                  abortSignal: controller.signal,
                  httpOptions: { timeout: currentAttemptTimeout }
                }
              });

              clearTimeout(timeoutId);

              // Check for model output truncation
              const candidate = response.candidates?.[0];
              if (candidate?.finishReason === 'MAX_TOKENS') {
                throw new GeminiReviewError(
                  'TRUNCATED_OUTPUT',
                  'Gemini response was truncated because it reached the maximum output token limit (MAX_TOKENS)'
                );
              }

              const responseText = response.text;
              if (!responseText || responseText.trim().length === 0) {
                throw new GeminiReviewError('MALFORMED_OUTPUT', 'Gemini returned an empty response body');
              }

              let parsedJson: unknown;
              try {
                parsedJson = JSON.parse(responseText);
              } catch (jsonErr) {
                throw new GeminiReviewError(
                  'MALFORMED_OUTPUT',
                  `Failed to parse Gemini response as JSON: ${jsonErr instanceof Error ? jsonErr.message : String(jsonErr)}`,
                  jsonErr
                );
              }

          let validated: ReviewOutput;
                try {
                  validated = ReviewOutputSchema.parse(parsedJson);
                } catch (zodErr) {
                  throw new GeminiReviewError(
                    'VALIDATION_ERROR',
                    `Gemini output failed schema validation: ${zodErr instanceof Error ? zodErr.message : String(zodErr)}`,
                    zodErr
                  );
                }

                const totalElapsedMs = Date.now() - startTime;
                logger.info(
                  {
                    model: currentModel,
                    isFallback: currentModel !== env.GEMINI_MODEL,
                    findingsCount: validated.findings.length,
                    attemptsCount: totalAttemptsCount,
                    totalElapsedMs
                  },
                  'Successfully received and validated Gemini review output'
                );

              return {
                output: validated,
                modelUsed: currentModel,
                attemptsCount: totalAttemptsCount,
                totalElapsedMs
              };
            } catch (error) {
              clearTimeout(timeoutId);
              lastError = error;

          if (timedOut || (error instanceof Error && error.name === 'AbortError')) {
                  lastError = new GeminiReviewError(
                    'TIMEOUT',
                    `Gemini request timed out after ${currentAttemptTimeout}ms (attempt ${attempt + 1})`,
                    error
                  );
                }

                const classification = this.classifyError(lastError);

                // Non-retryable permanent error: fail fast immediately
                if (classification.action === 'FAIL_FAST') {
                  logger.error(
                    { model: currentModel, code: classification.code, message: classification.message },
                    'Non-retryable review error encountered; failing fast'
                  );
                  throw lastError instanceof GeminiReviewError
                    ? lastError
                    : new GeminiReviewError(classification.code, classification.message, lastError);
                }

                // Non-retryable output defect: degrade directly without cycling models
                if (classification.action === 'DEGRADE') {
                  logger.error(
                    { model: currentModel, code: classification.code, message: classification.message },
                    'Generation output defect encountered; routing directly to degradation'
                  );
                  throw lastError instanceof GeminiReviewError
                    ? lastError
                    : new GeminiReviewError(classification.code, classification.message, lastError);
                }

                // Transient error on current model: retry if attempts remain on this model
                if (attempt < maxRetries) {
                  const retryAfterMs = this.extractRetryAfterMs(lastError);
                  const backoffDelayMs = retryAfterMs ?? this.calculateExponentialBackoff(attempt, baseDelayMs, maxDelayMs);

                  if (Date.now() + backoffDelayMs >= overallDeadline) {
                    throw new GeminiReviewError(
                      'TIMEOUT',
                      `Gemini total execution deadline (${totalDeadlineMs}ms) exceeded during retry backoff`,
                      lastError
                    );
                  }

                  logger.warn(
                    { model: currentModel, attempt: attempt + 1, maxRetries, backoffDelayMs, err: lastError },
                    'Transient Gemini error encountered; backing off before retry'
                  );

                  await this.sleep(backoffDelayMs);
                  continue;
                }

                // Retries on this model are exhausted
                logger.warn(
                  { model: currentModel, attemptsOnModel: attempt + 1, isLastModel },
                  'Retries exhausted on current Gemini model'
                );

              if (!isLastModel && classification.canFailover) {
                const nextModel = candidateModels[modelIdx + 1];
                logger.warn(
                  {
                    event: 'GEMINI_MODEL_FAILOVER',
                    fromModel: currentModel,
                    toModel: nextModel,
                    reason: classification.code,
                    totalAttemptsSoFar: totalAttemptsCount
                  },
                  'Failing over to next Gemini candidate model'
                );
                break; // Break inner retry loop -> switch to next model
              }

              if (isLastModel) {
                const finalCode: GeminiErrorCode =
                  classification.code === 'TIMEOUT' ? 'TIMEOUT' : 'MAX_RETRIES_EXCEEDED';
                throw new GeminiReviewError(
                  finalCode,
                  `All configured Gemini models failed. Last error: ${classification.message}`,
                  lastError
                );
              }
            }
          }
    }

        throw new GeminiReviewError(
          'MAX_RETRIES_EXCEEDED',
          `Exhausted all ${totalAttemptsCount} attempts across configured Gemini models`,
          lastError
        );
      }

  public classifyError(error: any): ErrorClassification {
    if (error instanceof GeminiReviewError) {
      if (error.code === 'TRUNCATED_OUTPUT' || error.code === 'MALFORMED_OUTPUT' || error.code === 'VALIDATION_ERROR') {
        return {
          code: error.code,
          action: 'DEGRADE',
          canFailover: false,
          message: error.message
        };
      }
      if (error.code === 'TIMEOUT') {
        return {
          code: 'TIMEOUT',
          action: 'RETRY_SAME_MODEL',
          canFailover: true,
          message: error.message
        };
      }
    }

    const status = this.extractStatusCode(error);
      const msg = (error?.message || '').toLowerCase();

      // 400 Bad Request: Request payload/schema defect -> fail fast
      if (status === 400) {
        return {
          code: 'UPSTREAM_ERROR',
          action: 'FAIL_FAST',
          canFailover: false,
          message: `HTTP 400 Bad Request: ${error.message || 'Invalid request parameters'}`
        };
      }

        // 401 Unauthorized: API key invalid -> fail fast
        if (status === 401 || msg.includes('api_key_invalid') || msg.includes('unauthorized')) {
          return {
            code: 'UPSTREAM_ERROR',
            action: 'FAIL_FAST',
            canFailover: false,
            message: `HTTP 401 Unauthorized: API key is invalid or unauthenticated`
          };
        }

        // 403 Forbidden: Project-wide IAM / billing defect -> fail fast
        if (status === 403) {
          return {
            code: 'UPSTREAM_ERROR',
            action: 'FAIL_FAST',
            canFailover: false,
            message: `HTTP 403 Forbidden: Project permission or billing defect`
          };
        }

        // 404 Not Found: Model unavailable or misconfigured -> fail fast (do not hide bad configuration)
        if (status === 404 || msg.includes('not found') || msg.includes('is unavailable for this api project')) {
          return {
            code: 'UPSTREAM_ERROR',
            action: 'FAIL_FAST',
            canFailover: false,
            message: `HTTP 404 Not Found: Model is unavailable or invalid: ${error.message}`
          };
        }

        // 429 Rate Limit: Check if model-specific or project-wide
        if (status === 429 || msg.includes('429') || msg.includes('rate limit') || msg.includes('resource exhausted')) {
          const isModelScoped = this.isModelSpecificQuota(error);
          return {
            code: 'RATE_LIMITED',
            action: 'RETRY_SAME_MODEL',
            canFailover: isModelScoped, // Only failover if explicit model-specific evidence exists
            message: `HTTP 429 Resource Exhausted: ${error.message}`
          };
        }

        // 503 UNAVAILABLE / 502 Bad Gateway / 504 Gateway Timeout / 500 Internal Error
        if (
      status === 503 ||
            status === 502 ||
            status === 504 ||
            status === 500 ||
            msg.includes('503') ||
            msg.includes('502') ||
            msg.includes('504') ||
            msg.includes('500') ||
            msg.includes('overloaded') ||
            msg.includes('high demand')
    ) {
          return {
            code: 'UPSTREAM_ERROR',
            action: 'RETRY_SAME_MODEL',
            canFailover: true,
            message: `HTTP ${status || 503} Upstream Service Error: ${error.message}`
          };
        }

        // Transient Network Errors
        if (
          msg.includes('econnreset') ||
          msg.includes('etimedout') ||
          msg.includes('network') ||
          msg.includes('fetch failed')
        ) {
          return {
            code: 'UPSTREAM_ERROR',
            action: 'RETRY_SAME_MODEL',
            canFailover: true,
            message: `Network error: ${error.message}`
          };
        }

        // Non-retryable permanent error by default
        return {
          code: 'UPSTREAM_ERROR',
          action: 'FAIL_FAST',
          canFailover: false,
          message: error?.message || 'Unknown upstream error'
        };
      }

  private isModelSpecificQuota(error: any): boolean {
    const msg = (error?.message || '').toLowerCase();
    const details = JSON.stringify(error?.error || error?.response?.data || '').toLowerCase();
    return (
      msg.includes('permodel') ||
      msg.includes('per_model') ||
      details.includes('permodel') ||
      details.includes('per_model')
    );
  }

  private extractStatusCode(error: any): number | undefined {
    return error?.status || error?.statusCode || error?.response?.status;
  }

  private extractRetryAfterMs(error: any): number | null {
    const retryAfter = error?.headers?.get?.('retry-after') || error?.headers?.['retry-after'];
    if (!retryAfter) return null;
    const numeric = Number(retryAfter);
    if (!isNaN(numeric) && numeric > 0) {
      return numeric * 1000;
    }
    const parsedDate = Date.parse(retryAfter);
    if (!isNaN(parsedDate)) {
      return Math.max(0, parsedDate - Date.now());
    }
    return null;
  }

  private calculateExponentialBackoff(attempt: number, baseDelayMs: number, maxDelayMs: number): number {
    const exponential = baseDelayMs * Math.pow(2, attempt);
    const jitter = Math.random() * 0.4 - 0.2; // +/- 20% jitter
    return Math.min(exponential * (1 + jitter), maxDelayMs);
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  GeminiReviewClient,
  GeminiReviewError,
  estimateDiffTokens
} from '../../src/analyzer/llm/client.js';
import { setTestEnv } from '../../src/config/env.js';

describe('GeminiReviewClient Reliability & Security Suite', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setTestEnv({
      GEMINI_TIMEOUT_MS: 5000,
      GEMINI_TOTAL_TIMEOUT_MS: 15000,
      GEMINI_MAX_RETRIES: 2
    });
  });

  it('should successfully parse and validate a valid Gemini review output', async () => {
    const mockGenerateContent = vi.fn().mockResolvedValue({
      candidates: [{ finishReason: 'STOP' }],
      text: JSON.stringify({
        summary: 'PR has minor improvements.',
        findings: [
          {
            path: 'src/index.ts',
            line: 42,
            severity: 'WARNING',
            category: 'BUG',
            title: 'Potential null pointer dereference',
            message: 'User object can be null when unauthenticated.',
            suggestion: 'user?.id',
            confidence: 0.95
          }
        ]
      })
    });

    const mockAi: any = {
      models: { generateContent: mockGenerateContent }
    };

    const client = new GeminiReviewClient(mockAi);
    const result = await client.reviewDiff('PR Title', 'PR Description', '+ const x = 1;');

    expect(result.output.summary).toBe('PR has minor improvements.');
    expect(result.output.findings).toHaveLength(1);
    expect(result.output.findings[0].confidence).toBe(0.95);
    expect(result.output.findings[0].path).toBe('src/index.ts');
    expect(result.modelUsed).toBe('gemini-3.8-flash');

    // Verify responseSchema was passed to Gemini call config
    expect(mockGenerateContent).toHaveBeenCalledTimes(1);
    const callConfig = mockGenerateContent.mock.calls[0][0].config;
    expect(callConfig.responseMimeType).toBe('application/json');
    expect(callConfig.responseSchema).toBeDefined();
    expect(callConfig.responseSchema.type).toBe('OBJECT');
  });

  it('should reject AI findings missing mandatory confidence score with VALIDATION_ERROR', async () => {
    const mockGenerateContent = vi.fn().mockResolvedValue({
      candidates: [{ finishReason: 'STOP' }],
      text: JSON.stringify({
        summary: 'PR summary',
        findings: [
          {
            path: 'src/index.ts',
            line: 10,
            severity: 'CRITICAL',
            category: 'SECURITY',
            title: 'Injection',
            message: 'SQL Injection detected'
            // Missing confidence!
          }
        ]
      })
    });

    const mockAi: any = {
      models: { generateContent: mockGenerateContent }
    };

    const client = new GeminiReviewClient(mockAi);
    await expect(client.reviewDiff('Title', null, '+ diff')).rejects.toThrow(GeminiReviewError);
    await expect(client.reviewDiff('Title', null, '+ diff')).rejects.toMatchObject({
      code: 'VALIDATION_ERROR'
    });
  });

  it('should reject confidence values outside [0, 1] range', async () => {
    const mockGenerateContent = vi.fn().mockResolvedValue({
      candidates: [{ finishReason: 'STOP' }],
      text: JSON.stringify({
        summary: 'PR summary',
        findings: [
          {
            path: 'src/index.ts',
            line: 10,
            severity: 'SUGGESTION',
            category: 'CODE_QUALITY',
            title: 'Style',
            message: 'Improve naming',
            confidence: 1.5 // Invalid! > 1.0
          }
        ]
      })
    });

    const mockAi: any = {
      models: { generateContent: mockGenerateContent }
    };

    const client = new GeminiReviewClient(mockAi);
    await expect(client.reviewDiff('Title', null, '+ diff')).rejects.toMatchObject({
      code: 'VALIDATION_ERROR'
    });
  });

  it('should detect output truncation (MAX_TOKENS) and throw TRUNCATED_OUTPUT', async () => {
    const mockGenerateContent = vi.fn().mockResolvedValue({
      candidates: [{ finishReason: 'MAX_TOKENS' }],
      text: '{"summary": "Incomplete output that was cut off mid-j'
    });

    const mockAi: any = {
      models: { generateContent: mockGenerateContent }
    };

    const client = new GeminiReviewClient(mockAi);
    await expect(client.reviewDiff('Title', null, '+ diff')).rejects.toThrow(
      'Gemini response was truncated because it reached the maximum output token limit (MAX_TOKENS)'
    );
    await expect(client.reviewDiff('Title', null, '+ diff')).rejects.toMatchObject({
      code: 'TRUNCATED_OUTPUT'
    });
  });

  it('should handle malformed JSON syntax and throw MALFORMED_OUTPUT', async () => {
    const mockGenerateContent = vi.fn().mockResolvedValue({
      candidates: [{ finishReason: 'STOP' }],
      text: '{ not valid json }'
    });

    const mockAi: any = {
      models: { generateContent: mockGenerateContent }
    };

    const client = new GeminiReviewClient(mockAi);
    await expect(client.reviewDiff('Title', null, '+ diff')).rejects.toMatchObject({
      code: 'MALFORMED_OUTPUT'
    });
  });

  it('should abort request and throw TIMEOUT when request exceeds attempt timeout', async () => {
    setTestEnv({
      GEMINI_TIMEOUT_MS: 50, // 50ms timeout
      GEMINI_MAX_RETRIES: 0
    });

    const mockGenerateContent = vi.fn().mockImplementation(async ({ config }: any) => {
      return new Promise((resolve, reject) => {
        const signal = config.abortSignal;
        if (signal) {
          signal.addEventListener('abort', () => {
            const err = new Error('The operation was aborted');
            err.name = 'AbortError';
            reject(err);
          });
        }
      });
    });

    const mockAi: any = {
      models: { generateContent: mockGenerateContent }
    };

    const client = new GeminiReviewClient(mockAi);
    await expect(client.reviewDiff('Title', null, '+ diff')).rejects.toMatchObject({
      code: 'TIMEOUT'
    });
  });

  it('should retry on transient HTTP 429 and succeed on subsequent attempt', async () => {
    const rateLimitError = new Error('Resource exhausted (rate limit)');
    (rateLimitError as any).status = 429;

    const successResponse = {
      candidates: [{ finishReason: 'STOP' }],
      text: JSON.stringify({
        summary: 'Successful review after retry',
        findings: []
      })
    };

    const mockGenerateContent = vi
      .fn()
      .mockRejectedValueOnce(rateLimitError)
      .mockResolvedValueOnce(successResponse);

    const mockAi: any = {
      models: { generateContent: mockGenerateContent }
    };

    const client = new GeminiReviewClient(mockAi);
    const result = await client.reviewDiff('Title', null, '+ diff');

    expect(result.output.summary).toBe('Successful review after retry');
    expect(mockGenerateContent).toHaveBeenCalledTimes(2);
  });

  it('should fail immediately on permanent HTTP 400 Bad Request without retrying', async () => {
    const badRequestError = new Error('Invalid request parameters');
    (badRequestError as any).status = 400;

    const mockGenerateContent = vi.fn().mockRejectedValue(badRequestError);

    const mockAi: any = {
      models: { generateContent: mockGenerateContent }
    };

    const client = new GeminiReviewClient(mockAi);
    await expect(client.reviewDiff('Title', null, '+ diff')).rejects.toMatchObject({
      code: 'UPSTREAM_ERROR'
    });

    // Should only be called once; no retries for 400
    expect(mockGenerateContent).toHaveBeenCalledTimes(1);
  });

  it('should enforce bounded total execution deadline across retries', async () => {
    setTestEnv({
      GEMINI_TIMEOUT_MS: 400,
      GEMINI_TOTAL_TIMEOUT_MS: 300, // Total deadline shorter than retries would take
      GEMINI_MAX_RETRIES: 5
    });

    const error503 = new Error('Service Unavailable');
    (error503 as any).status = 503;

    const mockGenerateContent = vi.fn().mockRejectedValue(error503);

    const mockAi: any = {
      models: { generateContent: mockGenerateContent }
    };

    const client = new GeminiReviewClient(mockAi);
    await expect(client.reviewDiff('Title', null, '+ diff')).rejects.toMatchObject({
      code: 'TIMEOUT'
    });
  });

  it('should abort immediately if Retry-After exceeds remaining total execution deadline', async () => {
    setTestEnv({
      GEMINI_TIMEOUT_MS: 1000,
      GEMINI_TOTAL_TIMEOUT_MS: 3000, // 3 seconds deadline
      GEMINI_MAX_RETRIES: 2
    });

    const error429 = new Error('Rate limit exceeded');
    (error429 as any).status = 429;
    // Retry-After of 60 seconds exceeds remaining 3s total deadline
    (error429 as any).headers = { 'retry-after': '60' };

    const mockGenerateContent = vi.fn().mockRejectedValue(error429);
    const mockAi: any = { models: { generateContent: mockGenerateContent } };

    const client = new GeminiReviewClient(mockAi);
    await expect(client.reviewDiff('Title', null, '+ diff')).rejects.toMatchObject({
      code: 'TIMEOUT'
    });
    // Should fail on first attempt when backoff delay check detects 60s > 3s
    expect(mockGenerateContent).toHaveBeenCalledTimes(1);
  });

  it('should throw MAX_RETRIES_EXCEEDED when all retries are exhausted and never exceed configured maxRetries', async () => {
    setTestEnv({
      GEMINI_TIMEOUT_MS: 500,
      GEMINI_TOTAL_TIMEOUT_MS: 10000,
      GEMINI_MAX_RETRIES: 2, // Max 2 retries (3 total attempts: 0, 1, 2)
      GEMINI_FALLBACK_MODELS: []
    });

    const transientError = new Error('503 Service Unavailable');
    (transientError as any).status = 503;

    const mockGenerateContent = vi.fn().mockRejectedValue(transientError);
    const mockAi: any = { models: { generateContent: mockGenerateContent } };

    const client = new GeminiReviewClient(mockAi);
    // Mock sleep to run quickly
    (client as any).sleep = vi.fn().mockResolvedValue(undefined);

    await expect(client.reviewDiff('Title', null, '+ diff')).rejects.toMatchObject({
      code: 'MAX_RETRIES_EXCEEDED'
    });

    // Initial attempt (0) + 2 retries (1, 2) = exactly 3 calls
    expect(mockGenerateContent).toHaveBeenCalledTimes(3);
  });

  describe('Multi-Model Failover Suite', () => {
    it('should fail over to secondary model when primary exhausts retries with 503', async () => {
      setTestEnv({
        GEMINI_MODEL: 'gemini-3.8-flash',
        GEMINI_FALLBACK_MODELS: ['gemini-3.6-flash'],
        GEMINI_MAX_RETRIES: 1, // 1 retry per model (2 attempts per model)
        GEMINI_TOTAL_TIMEOUT_MS: 30000
      });

      const error503 = new Error('503 Service Unavailable');
      (error503 as any).status = 503;

      const successResponse = {
        candidates: [{ finishReason: 'STOP' }],
        text: JSON.stringify({
          summary: 'Review from fallback model',
          findings: []
        })
      };

      // Primary model (gemini-3.8-flash) fails twice (attempt 0, 1)
      // Secondary model (gemini-3.6-flash) succeeds on attempt 0
      const mockGenerateContent = vi
        .fn()
        .mockRejectedValueOnce(error503)
        .mockRejectedValueOnce(error503)
        .mockResolvedValueOnce(successResponse);

      const mockAi: any = { models: { generateContent: mockGenerateContent } };
      const client = new GeminiReviewClient(mockAi);
      (client as any).sleep = vi.fn().mockResolvedValue(undefined);

      const result = await client.reviewDiff('Title', null, '+ diff');

      expect(result.output.summary).toBe('Review from fallback model');
      expect(result.modelUsed).toBe('gemini-3.6-flash');
      expect(mockGenerateContent).toHaveBeenCalledTimes(3);

      // Verify call 1 and 2 used primary model
      expect(mockGenerateContent.mock.calls[0][0].model).toBe('gemini-3.8-flash');
      expect(mockGenerateContent.mock.calls[1][0].model).toBe('gemini-3.8-flash');
      // Verify call 3 used secondary model
      expect(mockGenerateContent.mock.calls[2][0].model).toBe('gemini-3.6-flash');
    });

    it('should fail over across primary and secondary to tertiary model when both fail', async () => {
      setTestEnv({
        GEMINI_MODEL: 'gemini-3.8-flash',
        GEMINI_FALLBACK_MODELS: ['gemini-3.6-flash', 'gemini-3.5-flash-lite'],
        GEMINI_MAX_RETRIES: 0, // 0 retries = 1 attempt per model
        GEMINI_TOTAL_TIMEOUT_MS: 30000
      });

      const error503 = new Error('503 Service Unavailable');
      (error503 as any).status = 503;

      const successResponse = {
        candidates: [{ finishReason: 'STOP' }],
        text: JSON.stringify({
          summary: 'Review from tertiary model',
          findings: []
        })
      };

      const mockGenerateContent = vi
        .fn()
        .mockRejectedValueOnce(error503) // 3.8 fails
        .mockRejectedValueOnce(error503) // 3.6 fails
        .mockResolvedValueOnce(successResponse); // 3.5-lite succeeds

      const mockAi: any = { models: { generateContent: mockGenerateContent } };
      const client = new GeminiReviewClient(mockAi);

      const result = await client.reviewDiff('Title', null, '+ diff');

      expect(result.output.summary).toBe('Review from tertiary model');
      expect(result.modelUsed).toBe('gemini-3.5-flash-lite');
      expect(mockGenerateContent).toHaveBeenCalledTimes(3);
      expect(mockGenerateContent.mock.calls[0][0].model).toBe('gemini-3.8-flash');
      expect(mockGenerateContent.mock.calls[1][0].model).toBe('gemini-3.6-flash');
      expect(mockGenerateContent.mock.calls[2][0].model).toBe('gemini-3.5-flash-lite');
    });

    it('should fail fast on HTTP 401 Unauthorized without attempting fallback models', async () => {
      setTestEnv({
        GEMINI_MODEL: 'gemini-3.8-flash',
        GEMINI_FALLBACK_MODELS: ['gemini-3.6-flash'],
        GEMINI_MAX_RETRIES: 2
      });

      const authError = new Error('API_KEY_INVALID');
      (authError as any).status = 401;

      const mockGenerateContent = vi.fn().mockRejectedValue(authError);
      const mockAi: any = { models: { generateContent: mockGenerateContent } };
      const client = new GeminiReviewClient(mockAi);

      await expect(client.reviewDiff('Title', null, '+ diff')).rejects.toMatchObject({
        code: 'UPSTREAM_ERROR'
      });

      // Must be called only once; no fallback on auth error!
      expect(mockGenerateContent).toHaveBeenCalledTimes(1);
      expect(mockGenerateContent.mock.calls[0][0].model).toBe('gemini-3.8-flash');
    });

    it('should fail fast on HTTP 404 Model Not Found without attempting fallback models', async () => {
      setTestEnv({
        GEMINI_MODEL: 'invalid-model',
        GEMINI_FALLBACK_MODELS: ['gemini-3.6-flash'],
        GEMINI_MAX_RETRIES: 2
      });

      const notFoundError = new Error('models/invalid-model is unavailable for this api project');
      (notFoundError as any).status = 404;

      const mockGenerateContent = vi.fn().mockRejectedValue(notFoundError);
      const mockAi: any = { models: { generateContent: mockGenerateContent } };
      const client = new GeminiReviewClient(mockAi);

      await expect(client.reviewDiff('Title', null, '+ diff')).rejects.toMatchObject({
        code: 'UPSTREAM_ERROR'
      });

      // Must fail fast so misconfigured model is surfaced
      expect(mockGenerateContent).toHaveBeenCalledTimes(1);
    });

    it('should strictly enforce shared 120s deadline across model failover', async () => {
      setTestEnv({
        GEMINI_MODEL: 'gemini-3.8-flash',
        GEMINI_FALLBACK_MODELS: ['gemini-3.6-flash'],
        GEMINI_TIMEOUT_MS: 500,
        GEMINI_TOTAL_TIMEOUT_MS: 300, // Total deadline shorter than delays
        GEMINI_MAX_RETRIES: 1
      });

      const error503 = new Error('503 Service Unavailable');
      (error503 as any).status = 503;

      const mockGenerateContent = vi.fn().mockRejectedValue(error503);
      const mockAi: any = { models: { generateContent: mockGenerateContent } };
      const client = new GeminiReviewClient(mockAi);

      await expect(client.reviewDiff('Title', null, '+ diff')).rejects.toMatchObject({
        code: 'TIMEOUT'
      });
    });
  });

  it('should estimate diff tokens and line count accurately', () => {
    const sampleDiff = `@@ -1,5 +1,6 @@
+const a = 1;
+const b = 2;
+return a + b;`;

    const budget = estimateDiffTokens(sampleDiff);
    expect(budget.lineCount).toBe(4);
    expect(budget.estimatedTokens).toBeGreaterThan(0);
  });
});

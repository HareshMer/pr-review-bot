import { describe, it, expect, beforeEach } from 'vitest';
import { EnvSchema, ActionEnvSchema, getEnv, setTestEnv, resetEnv, getActionEnv, setActionTestEnv, resetActionEnv, normalizePrivateKey } from '../../src/config/env.js';

describe('Environment Variable Validation (Zod)', () => {
  const minimalValidEnv = {
    GITHUB_APP_ID: '123456',
    GITHUB_WEBHOOK_SECRET: 'my-webhook-secret-token',
    GITHUB_PRIVATE_KEY: '-----BEGIN RSA PRIVATE KEY-----\nMIIE...',
    GEMINI_API_KEY: 'mock-gemini-key'
  };

  it('should successfully parse a valid environment configuration with defaults', () => {
    const result = EnvSchema.safeParse(minimalValidEnv);

    expect(result.success).toBe(true);
    if (!result.success) return;

    expect(result.data.GITHUB_APP_ID).toBe(123456);
    expect(result.data.PORT).toBe(3000);
    expect(result.data.HOST).toBe('0.0.0.0');
    expect(result.data.NODE_ENV).toBe('development');
    expect(result.data.LOG_LEVEL).toBe('info');
    expect(result.data.GEMINI_MODEL).toBe('gemini-3.8-flash');
    expect(result.data.GEMINI_FALLBACK_MODELS).toEqual(['gemini-3.6-flash', 'gemini-3.5-flash-lite']);
    expect(result.data.REVIEW_EVENT_VERDICT).toBe('COMMENT');
    expect(result.data.MAX_DIFF_LINES_PER_PR).toBe(15000);
    expect(result.data.MAX_FILE_SIZE_BYTES).toBe(500 * 1024);
    expect(result.data.SMEE_URL).toBeUndefined();
  });

  it('should coerce numeric environment variables from strings', () => {
    const customEnv = {
      ...minimalValidEnv,
      PORT: '8080',
      MAX_DIFF_LINES_PER_PR: '5000',
      MAX_FILE_SIZE_BYTES: '1048576'
    };

    const result = EnvSchema.safeParse(customEnv);
    expect(result.success).toBe(true);
    if (!result.success) return;

    expect(result.data.PORT).toBe(8080);
    expect(result.data.MAX_DIFF_LINES_PER_PR).toBe(5000);
    expect(result.data.MAX_FILE_SIZE_BYTES).toBe(1048576);
  });

  it('should fail when required variables are missing', () => {
    const result = EnvSchema.safeParse({});
    expect(result.success).toBe(false);
    if (result.success) return;

    const errorFields = Object.keys(result.error.flatten().fieldErrors);
    expect(errorFields).toContain('GITHUB_APP_ID');
    expect(errorFields).toContain('GITHUB_WEBHOOK_SECRET');
    expect(errorFields).toContain('GITHUB_PRIVATE_KEY');
    expect(errorFields).toContain('GEMINI_API_KEY');
  });

  it('should reject invalid SMEE_URL format', () => {
    const invalidUrlEnv = {
      ...minimalValidEnv,
      SMEE_URL: 'not-a-valid-url-format'
    };

    const result = EnvSchema.safeParse(invalidUrlEnv);
    expect(result.success).toBe(false);
    if (result.success) return;

    const fieldErrors = result.error.flatten().fieldErrors;
    expect(fieldErrors.SMEE_URL).toBeDefined();
  });

  it('should accept valid SMEE_URL', () => {
    const validUrlEnv = {
      ...minimalValidEnv,
      SMEE_URL: 'https://smee.io/my-custom-channel'
    };

    const result = EnvSchema.safeParse(validUrlEnv);
    expect(result.success).toBe(true);
    if (!result.success) return;

    expect(result.data.SMEE_URL).toBe('https://smee.io/my-custom-channel');
  });

  it('should reject invalid enum values for NODE_ENV, LOG_LEVEL, and REVIEW_EVENT_VERDICT', () => {
    const badEnumEnv = {
      ...minimalValidEnv,
      NODE_ENV: 'staging',
      LOG_LEVEL: 'verbose',
      REVIEW_EVENT_VERDICT: 'REJECT'
    };

    const result = EnvSchema.safeParse(badEnumEnv);
    expect(result.success).toBe(false);
    if (result.success) return;

    const fieldErrors = result.error.flatten().fieldErrors;
    expect(fieldErrors.NODE_ENV).toBeDefined();
    expect(fieldErrors.LOG_LEVEL).toBeDefined();
    expect(fieldErrors.REVIEW_EVENT_VERDICT).toBeDefined();
  });

  describe('GEMINI_FALLBACK_MODELS configuration', () => {
    it('should parse comma-separated fallback models and trim whitespace', () => {
      const customFallbackEnv = {
        ...minimalValidEnv,
        GEMINI_FALLBACK_MODELS: 'gemini-3.6-flash , gemini-3.5-flash-lite '
      };

      const result = EnvSchema.safeParse(customFallbackEnv);
      expect(result.success).toBe(true);
      if (!result.success) return;

      expect(result.data.GEMINI_FALLBACK_MODELS).toEqual(['gemini-3.6-flash', 'gemini-3.5-flash-lite']);
    });

    it('should deduplicate repeated fallback models', () => {
      const duplicateFallbackEnv = {
        ...minimalValidEnv,
        GEMINI_FALLBACK_MODELS: 'gemini-3.6-flash, gemini-3.5-flash-lite, gemini-3.6-flash'
      };

      const result = EnvSchema.safeParse(duplicateFallbackEnv);
      expect(result.success).toBe(true);
      if (!result.success) return;

      expect(result.data.GEMINI_FALLBACK_MODELS).toEqual(['gemini-3.6-flash', 'gemini-3.5-flash-lite']);
    });

    it('should support empty fallback models string', () => {
      const emptyFallbackEnv = {
        ...minimalValidEnv,
        GEMINI_FALLBACK_MODELS: ''
      };

      const result = EnvSchema.safeParse(emptyFallbackEnv);
      expect(result.success).toBe(true);
      if (!result.success) return;

      expect(result.data.GEMINI_FALLBACK_MODELS).toEqual([]);
    });

    it('should reject when primary model is duplicated in fallback models', () => {
      const invalidEnv = {
        ...minimalValidEnv,
        GEMINI_MODEL: 'gemini-3.8-flash',
        GEMINI_FALLBACK_MODELS: 'gemini-3.8-flash, gemini-3.6-flash'
      };

      const result = EnvSchema.safeParse(invalidEnv);
      expect(result.success).toBe(false);
      if (result.success) return;

      const fieldErrors = result.error.flatten().fieldErrors;
      expect(fieldErrors.GEMINI_FALLBACK_MODELS).toBeDefined();
      expect(fieldErrors.GEMINI_FALLBACK_MODELS?.[0]).toContain('Primary model (GEMINI_MODEL) must not be duplicated in GEMINI_FALLBACK_MODELS');
    });
  });

  describe('getEnv & setTestEnv singleton behavior', () => {
    beforeEach(() => {
      resetEnv();
    });

    it('should allow setting test environment overrides', () => {
      setTestEnv({ PORT: 9999, REVIEW_EVENT_VERDICT: 'APPROVE' });
      const env = getEnv();
      expect(env.PORT).toBe(9999);
      expect(env.REVIEW_EVENT_VERDICT).toBe('APPROVE');
      expect(env.NODE_ENV).toBe('test');
    });

    it('should throw an error when required process.env variables are missing', () => {
      const originalEnv = { ...process.env };
      try {
        delete process.env.GITHUB_APP_ID;
        delete process.env.GITHUB_WEBHOOK_SECRET;
        delete process.env.GITHUB_PRIVATE_KEY;
        delete process.env.GEMINI_API_KEY;

        expect(() => getEnv()).toThrow('Invalid environment variables. Check .env configuration.');
      } finally {
        process.env = originalEnv;
      }
    });
  });

  describe('normalizePrivateKey', () => {
    it('should convert escaped \\n characters into real newlines', () => {
      const escapedKey = '-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA0\\n-----END RSA PRIVATE KEY-----';
      const normalized = normalizePrivateKey(escapedKey);
      expect(normalized).toBe('-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0\n-----END RSA PRIVATE KEY-----');
    });

    it('should preserve already valid multiline PEM keys', () => {
      const multilineKey = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0\n-----END RSA PRIVATE KEY-----';
      const normalized = normalizePrivateKey(multilineKey);
      expect(normalized).toBe(multilineKey);
    });

    it('should strip accidental wrapping double or single quotes', () => {
      const quotedKey = '"-----BEGIN RSA PRIVATE KEY-----\\nMIIE...\\n-----END RSA PRIVATE KEY-----"';
      const normalized = normalizePrivateKey(quotedKey);
      expect(normalized).toBe('-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----');

      const singleQuoted = "'-----BEGIN RSA PRIVATE KEY-----\\nMIIE...\\n-----END RSA PRIVATE KEY-----'";
      expect(normalizePrivateKey(singleQuoted)).toBe('-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----');
    });

    it('should return empty string for empty input', () => {
      expect(normalizePrivateKey('')).toBe('');
    });

    it('should automatically normalize GITHUB_PRIVATE_KEY when parsing through EnvSchema', () => {
      const result = EnvSchema.safeParse({
        ...minimalValidEnv,
        GITHUB_PRIVATE_KEY: '-----BEGIN RSA PRIVATE KEY-----\\nLINE1\\nLINE2\\n-----END RSA PRIVATE KEY-----'
      });
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.GITHUB_PRIVATE_KEY).toBe('-----BEGIN RSA PRIVATE KEY-----\nLINE1\nLINE2\n-----END RSA PRIVATE KEY-----');
      }
    });
  });

  describe('GitHub Action Environment Validation (ActionEnvSchema)', () => {
    const minimalValidActionEnv = {
      GITHUB_TOKEN: 'ghp_mock_token_for_actions',
      GITHUB_REPOSITORY: 'owner/test-repo',
      GITHUB_EVENT_PATH: '/path/to/event.json',
      GEMINI_API_KEY: 'mock-gemini-key'
    };

    it('should successfully parse valid GitHub Actions environment variables with defaults', () => {
      const result = ActionEnvSchema.safeParse(minimalValidActionEnv);
      expect(result.success).toBe(true);
      if (!result.success) return;

      expect(result.data.GITHUB_TOKEN).toBe('ghp_mock_token_for_actions');
      expect(result.data.GITHUB_REPOSITORY).toBe('owner/test-repo');
      expect(result.data.GITHUB_EVENT_PATH).toBe('/path/to/event.json');
      expect(result.data.GEMINI_API_KEY).toBe('mock-gemini-key');
      expect(result.data.GEMINI_MODEL).toBe('gemini-3.8-flash');
      expect(result.data.GEMINI_FALLBACK_MODELS).toEqual(['gemini-3.6-flash', 'gemini-3.5-flash-lite']);
      expect(result.data.REVIEW_EVENT_VERDICT).toBe('COMMENT');
    });

    it('should fail when GITHUB_TOKEN or GITHUB_EVENT_PATH is missing in action mode', () => {
      const result = ActionEnvSchema.safeParse({
        GITHUB_REPOSITORY: 'owner/test-repo',
        GEMINI_API_KEY: 'mock-gemini-key'
      });
      expect(result.success).toBe(false);
      if (result.success) return;

      const errorFields = Object.keys(result.error.flatten().fieldErrors);
      expect(errorFields).toContain('GITHUB_TOKEN');
      expect(errorFields).toContain('GITHUB_EVENT_PATH');
    });

    it('should reject when primary model is in fallback list for ActionEnvSchema', () => {
      const result = ActionEnvSchema.safeParse({
        ...minimalValidActionEnv,
        GEMINI_MODEL: 'gemini-3.8-flash',
        GEMINI_FALLBACK_MODELS: 'gemini-3.8-flash,gemini-3.6-flash'
      });
      expect(result.success).toBe(false);
    });

    it('should return singleton cached value in getActionEnv and allow reset', () => {
      setActionTestEnv({ GITHUB_TOKEN: 'custom-action-token' });
      const env1 = getActionEnv();
      expect(env1.GITHUB_TOKEN).toBe('custom-action-token');

      resetActionEnv();
    });
  });
});


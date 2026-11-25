import { z } from 'zod';
import dotenv from 'dotenv';
import { CONSTANTS } from './constants.js';

dotenv.config();

/**
 * Normalizes an RSA/EC private key provided via environment variables.
 * Handles escaped literal newline sequences ("\n" or "\\n"), strips accidental
 * surrounding quotes, and preserves existing valid multiline PEM formats.
 */
export function normalizePrivateKey(rawKey: string): string {
  if (!rawKey) return '';
  let key = rawKey.trim();
  if ((key.startsWith('"') && key.endsWith('"')) || (key.startsWith("'") && key.endsWith("'"))) {
    key = key.slice(1, -1).trim();
  }
  if (key.includes('\\n')) {
    key = key.replace(/\\n/g, '\n');
  }
  return key.trim();
}

export const EnvSchema = z.object({
  PORT: z.coerce.number().default(CONSTANTS.DEFAULT_PORT),
  HOST: z.string().default(CONSTANTS.DEFAULT_HOST),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  LOG_LEVEL: z.enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal']).default('info'),

  // GitHub App
  GITHUB_APP_ID: z.coerce.number(),
  GITHUB_WEBHOOK_SECRET: z.string().min(1, 'GITHUB_WEBHOOK_SECRET is required'),
  GITHUB_PRIVATE_KEY: z
    .string()
    .min(1, 'GITHUB_PRIVATE_KEY is required (PEM RSA private key)')
    .transform(val => normalizePrivateKey(val)),

  // Gemini LLM
  GEMINI_API_KEY: z.string().min(1, 'GEMINI_API_KEY is required'),
  GEMINI_MODEL: z.string().min(1).default(CONSTANTS.DEFAULT_GEMINI_MODEL),
  GEMINI_FALLBACK_MODELS: z
    .string()
    .default(CONSTANTS.DEFAULT_GEMINI_FALLBACK_MODELS.join(','))
    .transform(val => {
      if (!val || val.trim().length === 0) return [];
      return Array.from(new Set(val.split(',').map(m => m.trim()).filter(Boolean)));
    }),
  GEMINI_TIMEOUT_MS: z.coerce.number().default(CONSTANTS.DEFAULT_GEMINI_TIMEOUT_MS),
  GEMINI_TOTAL_TIMEOUT_MS: z.coerce.number().default(CONSTANTS.DEFAULT_GEMINI_TOTAL_TIMEOUT_MS),
  GEMINI_MAX_RETRIES: z.coerce.number().default(CONSTANTS.DEFAULT_GEMINI_MAX_RETRIES),
  GEMINI_RETRY_BASE_DELAY_MS: z.coerce.number().default(CONSTANTS.DEFAULT_GEMINI_RETRY_BASE_DELAY_MS),
  GEMINI_RETRY_MAX_DELAY_MS: z.coerce.number().default(CONSTANTS.DEFAULT_GEMINI_RETRY_MAX_DELAY_MS),

  // Review Behaviour
  REVIEW_EVENT_VERDICT: z.enum(['COMMENT', 'REQUEST_CHANGES', 'APPROVE']).default(CONSTANTS.DEFAULT_REVIEW_VERDICT),
  MAX_DIFF_LINES_PER_PR: z.coerce.number().default(CONSTANTS.MAX_DIFF_LINES_PER_PR),
  MAX_FILE_SIZE_BYTES: z.coerce.number().default(CONSTANTS.MAX_FILE_SIZE_BYTES),

  // Development Webhook Proxy
  SMEE_URL: z.string().url().optional()
}).refine(
  data => !data.GEMINI_FALLBACK_MODELS.includes(data.GEMINI_MODEL),
  {
    message: 'Primary model (GEMINI_MODEL) must not be duplicated in GEMINI_FALLBACK_MODELS',
    path: ['GEMINI_FALLBACK_MODELS']
  }
);

export type Env = z.infer<typeof EnvSchema>;

export const ActionEnvSchema = z.object({
  GITHUB_TOKEN: z.string().min(1, 'GITHUB_TOKEN is required in GitHub Actions mode'),
  GITHUB_REPOSITORY: z.string().min(1, 'GITHUB_REPOSITORY is required (e.g. owner/repo)'),
  GITHUB_EVENT_PATH: z.string().min(1, 'GITHUB_EVENT_PATH is required'),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('production'),
  LOG_LEVEL: z.enum(['trace', 'debug', 'info', 'warn', 'error', 'fatal']).default('info'),

  // Gemini LLM
  GEMINI_API_KEY: z.string().min(1, 'GEMINI_API_KEY is required'),
  GEMINI_MODEL: z.string().min(1).default(CONSTANTS.DEFAULT_GEMINI_MODEL),
  GEMINI_FALLBACK_MODELS: z
    .string()
    .default(CONSTANTS.DEFAULT_GEMINI_FALLBACK_MODELS.join(','))
    .transform(val => {
      if (!val || val.trim().length === 0) return [];
      return Array.from(new Set(val.split(',').map(m => m.trim()).filter(Boolean)));
    }),
  GEMINI_TIMEOUT_MS: z.coerce.number().default(CONSTANTS.DEFAULT_GEMINI_TIMEOUT_MS),
  GEMINI_TOTAL_TIMEOUT_MS: z.coerce.number().default(CONSTANTS.DEFAULT_GEMINI_TOTAL_TIMEOUT_MS),
  GEMINI_MAX_RETRIES: z.coerce.number().default(CONSTANTS.DEFAULT_GEMINI_MAX_RETRIES),
  GEMINI_RETRY_BASE_DELAY_MS: z.coerce.number().default(CONSTANTS.DEFAULT_GEMINI_RETRY_BASE_DELAY_MS),
  GEMINI_RETRY_MAX_DELAY_MS: z.coerce.number().default(CONSTANTS.DEFAULT_GEMINI_RETRY_MAX_DELAY_MS),

  // Review Behaviour
  REVIEW_EVENT_VERDICT: z.enum(['COMMENT', 'REQUEST_CHANGES', 'APPROVE']).default(CONSTANTS.DEFAULT_REVIEW_VERDICT),
  MAX_DIFF_LINES_PER_PR: z.coerce.number().default(CONSTANTS.MAX_DIFF_LINES_PER_PR),
  MAX_FILE_SIZE_BYTES: z.coerce.number().default(CONSTANTS.MAX_FILE_SIZE_BYTES)
}).refine(
  data => !data.GEMINI_FALLBACK_MODELS.includes(data.GEMINI_MODEL),
  {
    message: 'Primary model (GEMINI_MODEL) must not be duplicated in GEMINI_FALLBACK_MODELS',
    path: ['GEMINI_FALLBACK_MODELS']
  }
);

export type ActionEnv = z.infer<typeof ActionEnvSchema>;

let cachedActionEnv: ActionEnv | null = null;

export function getActionEnv(): ActionEnv {
  if (cachedActionEnv) return cachedActionEnv;
  const parsed = ActionEnvSchema.safeParse(process.env);
  if (!parsed.success) {
    const formattedErrors = parsed.error.format();
    console.error('❌ Invalid GitHub Action environment configuration:', JSON.stringify(formattedErrors, null, 2));
    throw new Error(`Invalid GitHub Action environment configuration: ${JSON.stringify(formattedErrors, null, 2)}`);
  }
  cachedActionEnv = parsed.data;
  return cachedActionEnv;
}

export function setActionTestEnv(overrides: Partial<ActionEnv>): void {
  cachedActionEnv = {
    GITHUB_TOKEN: 'mock-gh-token',
    GITHUB_REPOSITORY: 'test-owner/test-repo',
    GITHUB_EVENT_PATH: '/mock/path/event.json',
    NODE_ENV: 'test',
    LOG_LEVEL: 'info',
    GEMINI_API_KEY: 'mock-gemini-key',
    GEMINI_MODEL: CONSTANTS.DEFAULT_GEMINI_MODEL,
    GEMINI_FALLBACK_MODELS: [...CONSTANTS.DEFAULT_GEMINI_FALLBACK_MODELS],
    GEMINI_TIMEOUT_MS: CONSTANTS.DEFAULT_GEMINI_TIMEOUT_MS,
    GEMINI_TOTAL_TIMEOUT_MS: CONSTANTS.DEFAULT_GEMINI_TOTAL_TIMEOUT_MS,
    GEMINI_MAX_RETRIES: CONSTANTS.DEFAULT_GEMINI_MAX_RETRIES,
    GEMINI_RETRY_BASE_DELAY_MS: CONSTANTS.DEFAULT_GEMINI_RETRY_BASE_DELAY_MS,
    GEMINI_RETRY_MAX_DELAY_MS: CONSTANTS.DEFAULT_GEMINI_RETRY_MAX_DELAY_MS,
    REVIEW_EVENT_VERDICT: CONSTANTS.DEFAULT_REVIEW_VERDICT,
    MAX_DIFF_LINES_PER_PR: CONSTANTS.MAX_DIFF_LINES_PER_PR,
    MAX_FILE_SIZE_BYTES: CONSTANTS.MAX_FILE_SIZE_BYTES,
    ...overrides
  } as ActionEnv;
}

export function resetActionEnv(): void {
  cachedActionEnv = null;
}


let parsedEnv: Env;

export function getEnv(): Env {
  if (parsedEnv) {
    return parsedEnv;
  }
  if (cachedActionEnv) {
    return {
      PORT: CONSTANTS.DEFAULT_PORT,
      HOST: CONSTANTS.DEFAULT_HOST,
      NODE_ENV: cachedActionEnv.NODE_ENV,
      LOG_LEVEL: cachedActionEnv.LOG_LEVEL,
      GITHUB_APP_ID: 0,
      GITHUB_WEBHOOK_SECRET: '',
      GITHUB_PRIVATE_KEY: '',
      GEMINI_API_KEY: cachedActionEnv.GEMINI_API_KEY,
      GEMINI_MODEL: cachedActionEnv.GEMINI_MODEL,
      GEMINI_FALLBACK_MODELS: cachedActionEnv.GEMINI_FALLBACK_MODELS,
      GEMINI_TIMEOUT_MS: cachedActionEnv.GEMINI_TIMEOUT_MS,
      GEMINI_TOTAL_TIMEOUT_MS: cachedActionEnv.GEMINI_TOTAL_TIMEOUT_MS,
      GEMINI_MAX_RETRIES: cachedActionEnv.GEMINI_MAX_RETRIES,
      GEMINI_RETRY_BASE_DELAY_MS: cachedActionEnv.GEMINI_RETRY_BASE_DELAY_MS,
      GEMINI_RETRY_MAX_DELAY_MS: cachedActionEnv.GEMINI_RETRY_MAX_DELAY_MS,
      REVIEW_EVENT_VERDICT: cachedActionEnv.REVIEW_EVENT_VERDICT,
      MAX_DIFF_LINES_PER_PR: cachedActionEnv.MAX_DIFF_LINES_PER_PR,
      MAX_FILE_SIZE_BYTES: cachedActionEnv.MAX_FILE_SIZE_BYTES
    };
  }
  const result = EnvSchema.safeParse(process.env);
  if (!result.success) {
    const formattedErrors = result.error.format();
    console.error('❌ Invalid environment variables configuration:', JSON.stringify(formattedErrors, null, 2));
    throw new Error('Invalid environment variables. Check .env configuration.');
  }
  parsedEnv = result.data;
  return parsedEnv;
}

export function setTestEnv(overrides: Partial<Env>): void {
  parsedEnv = {
    PORT: CONSTANTS.DEFAULT_PORT,
    HOST: CONSTANTS.DEFAULT_HOST,
    NODE_ENV: 'test',
    LOG_LEVEL: 'error',
    GITHUB_APP_ID: 123456,
    GITHUB_WEBHOOK_SECRET: 'test-webhook-secret-token-32-chars-long',
    GITHUB_PRIVATE_KEY: 'test-private-key-pem',
    GEMINI_API_KEY: 'test-gemini-api-key',
    GEMINI_MODEL: CONSTANTS.DEFAULT_GEMINI_MODEL,
    GEMINI_FALLBACK_MODELS: [...CONSTANTS.DEFAULT_GEMINI_FALLBACK_MODELS],
    GEMINI_TIMEOUT_MS: CONSTANTS.DEFAULT_GEMINI_TIMEOUT_MS,
    GEMINI_TOTAL_TIMEOUT_MS: CONSTANTS.DEFAULT_GEMINI_TOTAL_TIMEOUT_MS,
    GEMINI_MAX_RETRIES: CONSTANTS.DEFAULT_GEMINI_MAX_RETRIES,
    GEMINI_RETRY_BASE_DELAY_MS: CONSTANTS.DEFAULT_GEMINI_RETRY_BASE_DELAY_MS,
    GEMINI_RETRY_MAX_DELAY_MS: CONSTANTS.DEFAULT_GEMINI_RETRY_MAX_DELAY_MS,
    REVIEW_EVENT_VERDICT: CONSTANTS.DEFAULT_REVIEW_VERDICT,
    MAX_DIFF_LINES_PER_PR: CONSTANTS.MAX_DIFF_LINES_PER_PR,
    MAX_FILE_SIZE_BYTES: CONSTANTS.MAX_FILE_SIZE_BYTES,
    ...overrides
  };
}

export function resetEnv(): void {
  parsedEnv = undefined as any;
}

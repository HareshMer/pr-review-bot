export const CONSTANTS = {
  DEFAULT_PORT: 3000,
  DEFAULT_HOST: '0.0.0.0',
  DEFAULT_LOG_LEVEL: 'info',
  DEFAULT_GEMINI_MODEL: 'gemini-3.8-flash',
  DEFAULT_GEMINI_FALLBACK_MODELS: ['gemini-3.6-flash', 'gemini-3.5-flash-lite'],
  DEFAULT_REVIEW_VERDICT: 'COMMENT' as const,

  // Gemini Reliability Defaults
  DEFAULT_GEMINI_TIMEOUT_MS: 45000, // 45s per attempt timeout
  DEFAULT_GEMINI_TOTAL_TIMEOUT_MS: 120000, // 120s max bounded execution time across all retries
  DEFAULT_GEMINI_MAX_RETRIES: 3,
  DEFAULT_GEMINI_RETRY_BASE_DELAY_MS: 1000,
  DEFAULT_GEMINI_RETRY_MAX_DELAY_MS: 10000,

  // Limits
  MAX_DIFF_LINES_PER_PR: 15000,
  MAX_FILE_SIZE_BYTES: 500 * 1024, // 500 KB patch size limit
  MAX_FILE_CHANGES_PER_FILE: 1000, // Maximum changes per individual file before skipping
  MAX_PAGINATED_FILES: 1000, // Safety bound on total files inspected across all pages
  MAX_COMMENTS_PER_REVIEW: 50,

  // Idempotency & Concurrency (Process-Local)
  IDEMPOTENCY_TTL_MS: 3600000, // 1 hour TTL
  DELIVERY_CACHE_MAX_SIZE: 5000,

  // Files to automatically skip from review
  IGNORED_FILE_EXTENSIONS: new Set([
    '.lock',
    '.svg',
    '.png',
    '.jpg',
    '.jpeg',
    '.gif',
    '.ico',
    '.pdf',
    '.zip',
    '.gz',
    '.tar',
    '.map',
    '.min.js',
    '.min.css'
  ]),

  IGNORED_FILE_NAMES: new Set([
    'package-lock.json',
    'pnpm-lock.yaml',
    'yarn.lock',
    'composer.lock',
    'Cargo.lock',
    'Gemfile.lock',
    'poetry.lock'
  ]),

  IGNORED_PATH_PREFIXES: [
    'dist/',
    'build/',
    'out/',
    '.next/',
    '.nuxt/',
    'coverage/',
    'node_modules/',
    'vendor/'
  ]
};


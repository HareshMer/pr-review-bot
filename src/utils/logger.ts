import pino from 'pino';

const isProduction = process.env.NODE_ENV === 'production';
const logLevel = process.env.LOG_LEVEL || 'info';

export const logger = pino({
  level: logLevel,
  redact: {
    paths: [
      'req.headers["x-hub-signature-256"]',
      'req.headers.authorization',
      'signature',
      '*.signature',
      'secret',
      '*.secret',
      'privateKey',
      '*.privateKey',
      'apiKey',
      '*.apiKey',
      'token',
      '*.token',
      'GITHUB_PRIVATE_KEY',
      'GITHUB_WEBHOOK_SECRET',
      'GEMINI_API_KEY'
    ],
    censor: '[REDACTED]'
  },
  transport: isProduction
    ? undefined
    : {
        target: 'pino-pretty',
        options: {
          colorize: true,
          translateTime: 'SYS:standard',
          ignore: 'pid,hostname'
        }
      }
});

export type Logger = typeof logger;


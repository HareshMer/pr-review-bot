import { describe, it, expect, vi, beforeEach } from 'vitest';
import { GitHubClientFactory } from '../../src/github/octokit.js';
import { setTestEnv } from '../../src/config/env.js';

vi.mock('@octokit/app', () => {
  return {
    App: class MockApp {
      public config: any;
      constructor(config: any) {
        this.config = config;
      }
      async getInstallationOctokit(installationId: number) {
        if (installationId === 99999) {
          throw new Error('Bad credentials or installation revoked');
        }
        return {
          rest: {
            pulls: {}
          }
        };
      }
    }
  };
});

describe('GitHubClientFactory', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setTestEnv({
      GITHUB_APP_ID: 12345,
      GITHUB_WEBHOOK_SECRET: 'webhook-secret',
      GITHUB_PRIVATE_KEY: '-----BEGIN RSA PRIVATE KEY-----\\nLINE1\\n-----END RSA PRIVATE KEY-----'
    });
  });

  it('should instantiate GitHub App with normalized private key', () => {
    const factory = new GitHubClientFactory();
    const appInstance = (factory as any).app;

    expect(appInstance.config.appId).toBe(12345);
    expect(appInstance.config.privateKey).toBe('-----BEGIN RSA PRIVATE KEY-----\nLINE1\n-----END RSA PRIVATE KEY-----');
    expect(appInstance.config.webhooks.secret).toBe('webhook-secret');
  });

  it('should return installation Octokit client for valid installation ID', async () => {
    const factory = new GitHubClientFactory();
    const client = await factory.getInstallationClient(123);
    expect(client).toBeDefined();
    expect(client.rest).toBeDefined();
  });

  it('should catch error and throw controlled error message on failure without leaking private key', async () => {
    const factory = new GitHubClientFactory();
    await expect(factory.getInstallationClient(99999)).rejects.toThrow(
      'Failed to obtain GitHub installation token for installation: 99999'
    );
  });
});

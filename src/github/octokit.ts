import { App } from '@octokit/app';
import { Octokit } from '@octokit/rest';
import { getEnv, normalizePrivateKey } from '../config/env.js';
import { logger } from '../utils/logger.js';

export class GitHubClientFactory {
  private app: App;

  constructor() {
    const env = getEnv();
    const privateKey = normalizePrivateKey(env.GITHUB_PRIVATE_KEY);
    this.app = new App({
      appId: env.GITHUB_APP_ID,
      privateKey,
      webhooks: {
        secret: env.GITHUB_WEBHOOK_SECRET
      },
      Octokit: Octokit
    });
  }

  /**
   * Retrieves an authenticated Octokit instance scoped to a specific repository installation.
   */
  public async getInstallationClient(installationId: number): Promise<Octokit> {
    try {
      const octokit = (await this.app.getInstallationOctokit(installationId)) as unknown as Octokit;
      return octokit;
    } catch (error) {
      logger.error({ installationId, err: error }, 'Failed to authenticate installation Octokit client');
      throw new Error(`Failed to obtain GitHub installation token for installation: ${installationId}`);
    }
  }
}

/**
 * Creates an Octokit instance authenticated with a GitHub Actions GITHUB_TOKEN or Personal Access Token.
 */
export function createActionOctokit(token: string): Octokit {
  return new Octokit({
    auth: token,
    userAgent: 'ai-pr-review-bot-action/1.0.0'
  });
}



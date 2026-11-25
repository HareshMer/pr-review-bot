export interface GitHubUser {
  login: string;
  id: number;
  type: string;
}

export interface GitHubRepository {
  name: string;
  full_name: string;
  private: boolean;
  owner: {
    login: string;
    id: number;
  };
}

export interface GitHubPullRequest {
  id: number;
  number: number;
  title: string;
  body: string | null;
  state: 'open' | 'closed';
  draft: boolean;
  head: {
    sha: string;
    ref: string;
  };
  base: {
    sha: string;
    ref: string;
  };
  user: GitHubUser;
}

export interface PullRequestWebhookPayload {
  action: 'opened' | 'synchronize' | 'reopened' | 'closed' | 'edited' | string;
  number: number;
  pull_request: GitHubPullRequest;
  repository: GitHubRepository;
  sender: GitHubUser;
  installation?: {
    id: number;
  };
}

export interface WebhookOrchestrator {
  handlePullRequest(payload: PullRequestWebhookPayload): Promise<void>;
}


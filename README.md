# 🤖 AI-Powered GitHub PR Reviewer Action

A reusable, automated GitHub Action that provides intelligent, semantic code reviews and instant deterministic security scans on Pull Requests using **Google Gemini 3.8 Flash** (with multi-model failover) and **TypeScript**.

---

## 🚀 Quick Start: Use in Any Repository

Add this workflow to any repository at `.github/workflows/ai-review.yml`:

```yaml
name: "AI PR Review"

on:
  pull_request:
    types: [opened, synchronize]

concurrency:
  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}
  cancel-in-progress: true

permissions:
  contents: read
  pull-requests: write

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: AI PR Review
        uses: HareshMer/ai-pr-reviewer-action@main
        with:
          gemini_api_key: ${{ secrets.GEMINI_API_KEY }}
```

### ⚙️ Action Inputs

| Input | Description | Default | Required |
| :--- | :--- | :---: | :---: |
| `gemini_api_key` | Google Gemini API key. | — | **Yes** |
| `gemini_model` | Primary model for semantic code review. | `gemini-3.8-flash` | No |
| `gemini_fallback_models` | Comma-separated fallback models on transient errors. | `gemini-3.6-flash,gemini-3.5-flash-lite` | No |
| `review_verdict` | Review event verdict (`COMMENT`, `REQUEST_CHANGES`, `APPROVE`). | `COMMENT` | No |
| `github_token` | GitHub token for posting review comments. | `${{ github.token }}` | No |

---

## 🛡️ Key Features

- **Reusable GitHub Action**: Zero server hosting or webhook infrastructure required.
- **Diff Boundary Enforcement**: Comments are strictly bound to changed diff hunks using `parse-diff` to eliminate GitHub `422 Unprocessable Entity` errors.
- **Deterministic Rule Engine**: Instant zero-cost scans for leaked AWS keys, GitHub tokens, Slack webhooks, private keys, and debug statements.
- **Multi-Model Gemini Failover**: Cascades from `gemini-3.8-flash` to `gemini-3.6-flash` and `gemini-3.5-flash-lite` on upstream service load (HTTP 503).
- **Graceful Degradation**: Automatically falls back to deterministic rule findings if all AI models are unreachable.
- **Actionable Inline Comments**: Adds GitHub one-click code replacement suggestion blocks (```` ```suggestion ````).
- **Executive Summary Table**: Compiles findings into an overview table with severity badges (`🚨 CRITICAL`, `⚠️ WARNING`, `💡 SUGGESTION`).

---

## 📁 Project Structure

```
.
├── src/
│   ├── app.ts                 # Fastify app factory (raw body parser & routes)
│   ├── server.ts              # Entry point bootstrap with graceful shutdown
│   ├── config/
│   │   ├── constants.ts       # File exclusions, line limits, and defaults
│   │   └── env.ts             # Zod environment variable validation
│   ├── utils/
│   │   └── logger.ts          # Pino structured logger
│   ├── webhooks/
│   │   ├── verify.ts          # Timing-safe HMAC SHA-256 signature verifier
│   │   ├── types.ts           # GitHub Webhook payload type definitions
│   │   └── router.ts          # Route handler for /webhooks
│   ├── github/
│   │   ├── octokit.ts         # GitHub App installation token client factory
│   │   ├── diff-service.ts    # PR file retrieval and filtering (lockfiles, binaries)
│   │   ├── diff-parser.ts     # Unified diff parser & line boundary map
│   │   └── review-publisher.ts# Octokit review creator & suggestion formatter
│   └── analyzer/
│       ├── rules/
│       │   ├── secret-scanner.ts   # Deterministic credential detector
│       │   └── debug-statements.ts # Deterministic console.log / debugger detector
│       ├── llm/
│       │   ├── client.ts      # Gemini client using @google/genai
│       │   ├── prompts.ts     # System & user prompts with XML delimiters
│       │   └── schemas.ts     # Zod schemas for structured review output
│       ├── aggregator.ts      # Merges & deduplicates findings, filters diff bounds
│       └── orchestrator.ts    # Master PR review workflow orchestrator
├── scripts/
│   └── dev-tunnel.ts          # Smee.io development webhook forwarder
├── tests/
│   ├── webhooks/
│   │   ├── verify.test.ts     # HMAC signature tests
│   │   └── ingress.test.ts    # Fastify ingress integration tests
│   ├── github/
│   │   └── diff-parser.test.ts# Hunk parsing and line boundary tests
│   ├── analyzer/
│   │   ├── rules.test.ts      # Secret and debug statement scanner tests
│   │   └── aggregator.test.ts # Deduplication and filtering tests
│   └── integration/
│       └── orchestrator.test.ts# End-to-end review orchestrator test
├── .env.example
├── package.json
├── tsconfig.json
└── vitest.config.ts
```

---

## 🛠️ Prerequisites & Setup

### 1. Requirements
- **Node.js**: v20+ LTS
- **npm**: v10+
- **Gemini API Key**: Obtainable from Google AI Studio
- **GitHub App**: Configured under your GitHub account or organization

### 2. Installation
```bash
git clone <repo-url>
cd pr-review-bot
npm install
```

### 3. Environment Configuration
Copy the template and configure your credentials:
```bash
cp .env.example .env
```

Edit `.env`:
```ini
# Server
PORT=3000
HOST=0.0.0.0
NODE_ENV=development
LOG_LEVEL=info

# GitHub App Authentication
GITHUB_APP_ID=123456
GITHUB_WEBHOOK_SECRET=your_32_byte_random_secret_hex
GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"

# Gemini LLM Configuration
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-3.8-flash
GEMINI_FALLBACK_MODELS=gemini-3.6-flash,gemini-3.5-flash-lite

# Review Settings
REVIEW_EVENT_VERDICT=COMMENT
MAX_DIFF_LINES_PER_PR=15000
MAX_FILE_SIZE_BYTES=512000

# Smee.io Tunnel (for local development)
SMEE_URL=https://smee.io/your_unique_smee_channel
```

---

## 🔑 GitHub App Setup Guide

1. Go to **GitHub** ➔ **Settings** ➔ **Developer Settings** ➔ **GitHub Apps** ➔ **New GitHub App**.
2. **Name**: `AI PR Review Bot` (or your choice).
3. **Webhook URL**:
   - For local development: Use your `smee.io` channel URL (e.g. `https://smee.io/abc123xyz`).
   - For production: `https://your-domain.com/webhooks`.
4. **Webhook Secret**: Set a strong random secret and copy it into `.env` as `GITHUB_WEBHOOK_SECRET`.
5. **Permissions**:
   - **Repository Permissions**:
     - `Pull requests`: **Read and Write** (Required to read diffs and post review comments)
     - `Contents`: **Read-only** (To read repository configuration files)
     - `Metadata`: **Read-only** (Mandatory default)
6. **Subscribe to Events**:
   - Check **Pull request**.
7. **Generate Private Key**:
   - Click **Generate a private key**.
   - Download the `.pem` file and copy its content into `.env` under `GITHUB_PRIVATE_KEY`.
8. **Install App**:
   - Install the GitHub App on your test repository.

---

## 💻 Running the Application

### Local Development (with Smee.io Webhook Forwarder)
In terminal 1 (Start the Fastify bot server):
```bash
npm run dev
```

In terminal 2 (Start the Smee webhook tunnel):
```bash
npm run dev:tunnel
```

### Production Build & Run
```bash
npm run build
npm start
```

### Running Automated Tests
```bash
npm test
```

### Running Model Smoke Tests
```bash
npm run test:smoke
```

---

## 🛡️ Security Guarantees

1. **Zero Execution**: The bot only parses diff text via static regex and string ASTs. No package installs, builds, or scripts are executed.
2. **Prompt Injection Defense**: Diffs are wrapped inside isolated XML delimiters (`<untrusted_diff>`); the LLM's system prompt strictly confines the model to code review and enforces JSON schema compliance.
3. **Least Privilege**: Only `Pull requests: Read & Write` is requested. No administrative or secrets permissions.
4. **Diff Boundary Invariant**: Comments are strictly verified against diff hunk boundaries to prevent invalid comment placement and GitHub API errors.


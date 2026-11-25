import { PullRequestWebhookPayload } from './types.js';
import { CONSTANTS } from '../config/constants.js';
import { logger } from '../utils/logger.js';

export interface QueuedReviewTask {
  payload: PullRequestWebhookPayload;
  queuedAt: number;
}

interface PrLockState {
  active: boolean;
  activeHeadSha: string;
  pendingTask: QueuedReviewTask | null;
}

/**
 * Manages concurrency and serialization of pull request reviews.
 * Enforces a strict "Latest-Head-Wins" policy per pull request:
 * 1. Only one review execution runs at any time per pull request (owner/repo#number).
 * 2. If a new review request arrives while a review is active, it is buffered as the newest pending task.
 * 3. Atomic Active-to-Pending Handoff: The lock is NOT released before transferring execution to the pending task,
 *    preventing any newly arriving webhook from interleaving or stealing the lock.
 * 4. Guaranteed Lock Cleanup: The state is cleared in a `finally` block when all pending tasks are drained or upon error.
 *
 * NOTE: This concurrency manager is process-local and in-memory only for this MVP.
 */
export class PrReviewConcurrencyManager {
  private states = new Map<string, PrLockState>();

  /**
   * Generates a canonical lock key for a pull request.
   */
  public static getPrKey(payload: PullRequestWebhookPayload): string {
    return `${payload.repository.full_name}#${payload.pull_request.number}`;
  }

  public isBusy(prKey: string): boolean {
    const state = this.states.get(prKey);
    return Boolean(state?.active);
  }

  public getActiveHeadSha(prKey: string): string | undefined {
    return this.states.get(prKey)?.activeHeadSha;
  }

  public getPendingHeadSha(prKey: string): string | undefined {
    return this.states.get(prKey)?.pendingTask?.payload.pull_request.head.sha;
  }

  /**
   * Submits a PR review task for execution.
   * If a review is already running for this PR, buffers this task as the pending task.
   * If no review is running, acquires the lock and processes the task, automatically continuing
   * to any pending tasks atomically before releasing the lock.
   */
  public async submit(
    prKey: string,
    task: QueuedReviewTask,
    processor: (task: QueuedReviewTask) => Promise<void>
  ): Promise<void> {
    let state = this.states.get(prKey);

    if (state && state.active) {
      // Overwrite any previously buffered pending task with the newest incoming task (Latest-Head-Wins)
      state.pendingTask = task;
      logger.info(
        {
          prKey,
          incomingSha: task.payload.pull_request.head.sha,
          activeSha: state.activeHeadSha
        },
        'Active review in progress for PR. Buffered incoming task as latest pending run.'
      );
      return;
    }

    if (!state) {
      state = {
        active: true,
        activeHeadSha: task.payload.pull_request.head.sha,
        pendingTask: null
      };
      this.states.set(prKey, state);
    } else {
      state.active = true;
      state.activeHeadSha = task.payload.pull_request.head.sha;
      state.pendingTask = null;
    }

    // Execute processing loop with ATOMIC HANDOFF
    try {
      let currentTask: QueuedReviewTask | null = task;

      while (currentTask) {
        state.activeHeadSha = currentTask.payload.pull_request.head.sha;
        logger.debug(
          { prKey, headSha: state.activeHeadSha },
          'Executing PR review task under concurrency lock'
        );

        try {
          await processor(currentTask);
        } catch (err) {
          logger.error({ prKey, headSha: state.activeHeadSha, err }, 'Error during PR review task execution');
        }

        // ATOMIC HANDOFF:
        // We inspect and consume pendingTask while state.active is STILL TRUE.
        // A newly arriving webhook calling submit() will see state.active === true and will be placed in pendingTask.
        // The lock is never dropped between task completion and pending task pickup.
        currentTask = state.pendingTask;
        state.pendingTask = null;
      }
    } finally {
      // Release lock completely when all pending tasks are drained or on fatal exception
      this.states.delete(prKey);
      logger.debug({ prKey }, 'Released concurrency lock for PR');
    }
  }
}

/**
 * In-memory TTL cache for GitHub webhook delivery IDs.
 * Used to detect and drop duplicate deliveries.
 *
 * NOTE: This cache is process-local and in-memory only. It is not durable across
 * server restarts or across multiple load-balanced server instances.
 */
export class DeliveryDeduplicationCache {
  private cache = new Map<string, number>();

  constructor(
    private ttlMs: number = CONSTANTS.IDEMPOTENCY_TTL_MS,
    private maxSize: number = CONSTANTS.DELIVERY_CACHE_MAX_SIZE
  ) { }

  public has(deliveryId: string): boolean {
    const timestamp = this.cache.get(deliveryId);
    if (!timestamp) return false;
    if (Date.now() - timestamp > this.ttlMs) {
      this.cache.delete(deliveryId);
      return false;
    }
    // True LRU: refresh recency by moving key to the end of Map insertion order
    // Preserves original recording timestamp so TTL is independent of LRU ordering
    this.cache.delete(deliveryId);
    this.cache.set(deliveryId, timestamp);
    return true;
  }

  public record(deliveryId: string): void {
    if (this.cache.has(deliveryId)) {
      // Re-recording updates timestamp and refreshes recency
      this.cache.delete(deliveryId);
    } else if (this.cache.size >= this.maxSize) {
      // Evict least-recently-used entry (first key in iteration order)
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey) this.cache.delete(oldestKey);
    }
    this.cache.set(deliveryId, Date.now());
  }

  public clear(): void {
    this.cache.clear();
  }
}


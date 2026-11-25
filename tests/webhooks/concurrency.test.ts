import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  PrReviewConcurrencyManager,
  DeliveryDeduplicationCache,
  QueuedReviewTask
} from '../../src/webhooks/concurrency.js';

describe('PrReviewConcurrencyManager (Atomic Handoff & Latest-Head-Wins)', () => {
  let manager: PrReviewConcurrencyManager;

  beforeEach(() => {
    manager = new PrReviewConcurrencyManager();
  });

  function createMockTask(prNumber: number, sha: string): QueuedReviewTask {
    return {
      payload: {
        action: 'synchronize',
        number: prNumber,
        pull_request: {
          number: prNumber,
          head: { sha }
        } as any,
        repository: { full_name: 'test-org/test-repo' } as any,
        sender: {} as any
      },
      queuedAt: Date.now()
    };
  }

  it('should run a single PR review task to completion and release lock', async () => {
    const prKey = 'test-org/test-repo#1';
    const task = createMockTask(1, 'sha-1');
    const executed: string[] = [];

    const processor = vi.fn().mockImplementation(async (t: QueuedReviewTask) => {
      executed.push(t.payload.pull_request.head.sha);
      expect(manager.isBusy(prKey)).toBe(true);
    });

    await manager.submit(prKey, task, processor);

    expect(executed).toEqual(['sha-1']);
    expect(manager.isBusy(prKey)).toBe(false);
  });

  it('should atomically hand off lock to pending task without releasing lock', async () => {
    const prKey = 'test-org/test-repo#1';
    const task1 = createMockTask(1, 'sha-1');
    const task2 = createMockTask(1, 'sha-2');

    const executionOrder: string[] = [];
    let resolveTask1: () => void = () => {};
    const task1Promise = new Promise<void>(res => {
      resolveTask1 = res;
    });

    const processor = vi.fn().mockImplementation(async (t: QueuedReviewTask) => {
      const sha = t.payload.pull_request.head.sha;
      executionOrder.push(`start:${sha}`);

      if (sha === 'sha-1') {
        // While task 1 is running, submit task 2
        await task1Promise;
      }
      executionOrder.push(`finish:${sha}`);
    });

    // Start task 1
    const run1 = manager.submit(prKey, task1, processor);

    // Verify task 1 is active
    expect(manager.isBusy(prKey)).toBe(true);
    expect(manager.getActiveHeadSha(prKey)).toBe('sha-1');

    // Submit task 2 while task 1 is active
    await manager.submit(prKey, task2, processor);

    // Verify task 2 is buffered as pending task
    expect(manager.getPendingHeadSha(prKey)).toBe('sha-2');

    // Let task 1 complete
    resolveTask1();
    await run1;

    // Both should have run in order without lock release in between
    expect(executionOrder).toEqual([
      'start:sha-1',
      'finish:sha-1',
      'start:sha-2',
      'finish:sha-2'
    ]);
    expect(manager.isBusy(prKey)).toBe(false);
  });

  it('should buffer only the latest head SHA when multiple commits arrive while busy', async () => {
    const prKey = 'test-org/test-repo#1';
    const task1 = createMockTask(1, 'sha-1');
    const task2 = createMockTask(1, 'sha-2');
    const task3 = createMockTask(1, 'sha-3');

    const executed: string[] = [];
    let resolveTask1: () => void = () => {};
    const task1Promise = new Promise<void>(res => {
      resolveTask1 = res;
    });

    const processor = vi.fn().mockImplementation(async (t: QueuedReviewTask) => {
      const sha = t.payload.pull_request.head.sha;
      if (sha === 'sha-1') {
        await task1Promise;
      }
      executed.push(sha);
    });

    const run1 = manager.submit(prKey, task1, processor);

    // Two newer commits arrive while task 1 is running
    await manager.submit(prKey, task2, processor);
    await manager.submit(prKey, task3, processor);

    expect(manager.getPendingHeadSha(prKey)).toBe('sha-3'); // sha-2 replaced by sha-3

    resolveTask1();
    await run1;

    // sha-2 was superseded by sha-3; only sha-1 and sha-3 run
    expect(executed).toEqual(['sha-1', 'sha-3']);
    expect(manager.isBusy(prKey)).toBe(false);
  });

  it('should guarantee lock release even if processor throws', async () => {
    const prKey = 'test-org/test-repo#1';
    const task = createMockTask(1, 'sha-faulty');

    const processor = vi.fn().mockRejectedValue(new Error('Fatal review failure'));

    await manager.submit(prKey, task, processor);

    expect(manager.isBusy(prKey)).toBe(false);
  });

  it('should not lose newer pending task if active task fails with exception', async () => {
    const prKey = 'test-org/test-repo#1';
    const task1 = createMockTask(1, 'sha-failing-1');
    const task2 = createMockTask(1, 'sha-pending-2');

    let resolveTask1Wait: () => void = () => {};
    const task1Wait = new Promise<void>(res => {
      resolveTask1Wait = res;
    });

    const executed: string[] = [];
    const processor = vi.fn().mockImplementation(async (t: QueuedReviewTask) => {
      const sha = t.payload.pull_request.head.sha;
      executed.push(sha);

      if (sha === 'sha-failing-1') {
        await task1Wait;
        throw new Error('Task 1 crashed unexpectedly');
      }
    });

    // Start task 1
    const run1 = manager.submit(prKey, task1, processor);

    // Buffer task 2 while task 1 is active
    await manager.submit(prKey, task2, processor);

    // Allow task 1 to finish and throw
    resolveTask1Wait();
    await run1;

    // Verify task 2 was not lost and was executed under the held lock
    expect(executed).toEqual(['sha-failing-1', 'sha-pending-2']);
    expect(manager.isBusy(prKey)).toBe(false);
  });
});

describe('DeliveryDeduplicationCache', () => {
  it('should record delivery IDs and detect duplicates', () => {
    const cache = new DeliveryDeduplicationCache(5000, 10);
    expect(cache.has('delivery-1')).toBe(false);

    cache.record('delivery-1');
    expect(cache.has('delivery-1')).toBe(true);
    expect(cache.has('delivery-2')).toBe(false);
  });

  it('should expire entries past TTL', () => {
    const cache = new DeliveryDeduplicationCache(-1, 10); // Expired immediately
    cache.record('delivery-expired');
    expect(cache.has('delivery-expired')).toBe(false);
  });

  it('should evict oldest entry when capacity is exceeded', () => {
    const cache = new DeliveryDeduplicationCache(5000, 2);
    cache.record('del-1');
    cache.record('del-2');
    cache.record('del-3'); // Evicts del-1

    expect(cache.has('del-1')).toBe(false);
    expect(cache.has('del-2')).toBe(true);
    expect(cache.has('del-3')).toBe(true);
  });

  it('should enforce true LRU eviction: accessing A refreshes recency so B is evicted when D is inserted', () => {
    const cache = new DeliveryDeduplicationCache(5000, 3);

    // 1. Insert A, B, and C when capacity is 3
    cache.record('del-A');
    cache.record('del-B');
    cache.record('del-C');

    // 2. Access A (refreshes recency)
    expect(cache.has('del-A')).toBe(true);

    // 3. Insert D when capacity is 3
    cache.record('del-D');

    // 4. Verify B is evicted (least recently accessed), not A
    expect(cache.has('del-B')).toBe(false);
    expect(cache.has('del-A')).toBe(true);
    expect(cache.has('del-C')).toBe(true);
    expect(cache.has('del-D')).toBe(true);
  });

  it('should expire entries based on original timestamp independently of LRU recency refresh', () => {
    // 50ms TTL, capacity 10
    const cache = new DeliveryDeduplicationCache(50, 10);
    cache.record('del-timed');

    // Access immediately (refreshes LRU position)
    expect(cache.has('del-timed')).toBe(true);

    // Wait past original TTL
    return new Promise<void>(resolve => {
      setTimeout(() => {
        // Must expire despite having been accessed
        expect(cache.has('del-timed')).toBe(false);
        resolve();
      }, 70);
    });
  });
});


import nodeCron from 'node-cron';
import type { Config } from './config.js';
import type { Database } from 'better-sqlite3';
import type { Logger } from 'pino';
import { findPendingAuthorizationOverdue } from './persistence.js';
import { cancelOverdueIntent } from './executor.js';

export function startPendingMonitor(
  config: Config,
  logger: Logger,
  db: Database
): { stop: () => void } {
  const slaSeconds = config.PENDING_AUTHORIZATION_SLA_HOURS * 3600;
  // Run every 5 minutes
  const task = nodeCron.schedule('*/5 * * * *', () => {
    void runOnce(config, logger, db, slaSeconds);
  });
  // Also run once at boot, with a small delay so the server has started
  setTimeout(() => void runOnce(config, logger, db, slaSeconds), 5_000);
  return { stop: () => task.stop() };
}

async function runOnce(
  config: Config,
  logger: Logger,
  db: Database,
  slaSeconds: number
): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  const overdue = findPendingAuthorizationOverdue(db, slaSeconds, now);
  if (overdue.length === 0) return;
  logger.info({ count: overdue.length }, 'pending-monitor: cancelling overdue drafts');
  for (const intent of overdue) {
    try {
      await cancelOverdueIntent(config, logger, db, intent);
    } catch (err) {
      logger.error(
        { err: (err as Error).message, intentId: intent.intent_id },
        'pending-monitor: cancellation threw'
      );
    }
  }
}
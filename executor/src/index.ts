import { pino } from 'pino';
import { loadConfig } from './config.js';
import { buildServer } from './server.js';
import { initDatabase } from './persistence.js';
import { ensureAuditTable } from './audit.js';
import { startPendingMonitor } from './scheduler.js';

async function main() {
  const config = loadConfig();
  const logger = pino({
    level: config.LOG_LEVEL,
    redact: {
      paths: [
        'req.headers.authorization',
        'req.headers["x-fireblocks-api-key"]',
        'req.headers["x-idempotency-key"]',
        'privateKey',
        'FIREBLOCKS_API_PRIVATE_KEY',
      ],
      remove: false,
    },
  });

  logger.info(
    {
      env: config.FIREBLOCKS_ENVIRONMENT,
      port: config.PORT,
      rateLimitMaxDrafts: config.RATE_LIMIT_MAX_DRAFTS,
      rateLimitWindowHours: config.RATE_LIMIT_WINDOW_HOURS,
      slaHours: config.PENDING_AUTHORIZATION_SLA_HOURS,
    },
    'starting fireblocks-path-c-executor'
  );

  const db = initDatabase(config.DATABASE_PATH);
  ensureAuditTable(db);

  const server = buildServer(config, logger, db);
  const monitor = startPendingMonitor(config, logger, db);

const httpServer = server.listen(config.PORT, () => {
    logger.info({ port: config.PORT }, 'listening');
  });

  const shutdown = (signal: string) => {
    logger.info({ signal }, 'shutting down');
    monitor.stop();
    httpServer.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error('fatal startup error:', err.message);
  process.exit(1);
});
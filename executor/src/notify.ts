import type { Config } from './config.js';
import type { Logger } from 'pino';

export type NotificationEvent =
  | { type: 'parse_rejected'; reason: string; intentId: string }
  | { type: 'confirmation_prompt'; intentId: string; payload: Record<string, unknown> }
  | { type: 'confirmation_expired'; intentId: string }
  | { type: 'killswitch_activated'; reason: string }
  | { type: 'killswitch_blocked_command'; intentId: string; reason: string }
  | { type: 'rate_cap_rejected'; currentCount: number; maxDrafts: number; intentId: string }
  | { type: 'rate_cap_tripped'; count: number; maxDrafts: number }
  | { type: 'draft_accepted'; intentId: string; txId: string; state: string }
  | { type: 'submission_failed'; intentId: string; errorClass: string }
  | { type: 'unknown_submission_state'; intentId: string }
  | { type: 'cancellation_attempted'; intentId: string; txId: string }
  | { type: 'cancellation_succeeded'; intentId: string; txId: string }
  | { type: 'cancellation_failed'; intentId: string; txId: string; errorClass: string }
  | { type: 'health_check_failed'; reason: string };

export async function notify(
  config: Config,
  logger: Logger,
  event: NotificationEvent
): Promise<void> {
  // Primary: callback to Mind (Mind posts to Telegram).
  if (config.MIND_CALLBACK_URL) {
    try {
      const response = await fetch(config.MIND_CALLBACK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ event, timestamp: new Date().toISOString() }),
      });
      if (!response.ok) {
        logger.error(
          { status: response.status, eventType: event.type },
          'mind callback returned non-2xx'
        );
      }
    } catch (err) {
      logger.error(
        { err: (err as Error).message, eventType: event.type },
        'mind callback threw — Telegram notification may be delayed'
      );
    }
  }

  // Secondary: direct Telegram fallback (if configured).
  if (config.TELEGRAM_BOT_TOKEN && config.TELEGRAM_CHAT_ID) {
    const text = formatTelegramMessage(event);
    try {
      await fetch(`https://api.telegram.org/bot${config.TELEGRAM_BOT_TOKEN}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: config.TELEGRAM_CHAT_ID,
          text,
          parse_mode: 'HTML',
          disable_web_page_preview: true,
        }),
      });
    } catch (err) {
      logger.error(
        { err: (err as Error).message, eventType: event.type },
        'telegram direct fallback threw'
      );
    }
  }
}

function formatTelegramMessage(event: NotificationEvent): string {
  switch (event.type) {
    case 'parse_rejected':
      return `❌ Parse rejected (intent <code>${event.intentId.slice(0, 8)}</code>): ${escapeHtml(event.reason)}`;
    case 'confirmation_prompt':
      return `⏳ Confirmation required: intent <code>${event.intentId.slice(0, 8)}</code>`;
    case 'confirmation_expired':
      return `⌛ Confirmation expired: <code>${event.intentId.slice(0, 8)}</code>`;
    case 'killswitch_activated':
      return `🛑 Kill switch activated: ${escapeHtml(event.reason)}`;
    case 'killswitch_blocked_command':
      return `🛑 Blocked command (kill switch): <code>${event.intentId.slice(0, 8)}</code>`;
    case 'rate_cap_rejected':
      return `⛔ Rate cap (${event.currentCount}/${event.maxDrafts})`;
    case 'rate_cap_tripped':
      return `🚨 Rate cap tripped at ${event.count}/${event.maxDrafts}; drafting disabled`;
    case 'draft_accepted':
      return `✅ Draft accepted: tx <code>${event.txId.slice(0, 8)}</code>, state ${event.state}`;
    case 'submission_failed':
      return `❌ Submission failed (intent <code>${event.intentId.slice(0, 8)}</code>): ${event.errorClass}`;
    case 'unknown_submission_state':
      return `⚠️ Unknown submission state: <code>${event.intentId.slice(0, 8)}</code>`;
    case 'cancellation_attempted':
      return `🗑️ Auto-cancel attempting: tx <code>${event.txId.slice(0, 8)}</code>`;
    case 'cancellation_succeeded':
      return `✅ Auto-cancel succeeded: tx <code>${event.txId.slice(0, 8)}</code>`;
    case 'cancellation_failed':
      return `❌ Auto-cancel failed: tx <code>${event.txId.slice(0, 8)}</code> (${event.errorClass})`;
    case 'health_check_failed':
      return `⚠️ Health check failed: ${escapeHtml(event.reason)}`;
  }
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
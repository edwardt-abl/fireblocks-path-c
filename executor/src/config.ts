import { z } from 'zod';

const ConfigSchema = z.object({
  PORT: z.coerce.number().int().positive().default(3000),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
  DATABASE_PATH: z.string().min(1).default('./data/state.db'),

  FIREBLOCKS_API_KEY_ID: z.string().min(1, 'FIREBLOCKS_API_KEY_ID required'),
  FIREBLOCKS_API_PRIVATE_KEY: z.string().default(''), // intentionally optional until key ceremony
  FIREBLOCKS_BASE_URL: z.string().url().default('https://api.fireblocks.io'),
  FIREBLOCKS_ENVIRONMENT: z.enum(['TESTNET', 'PRODUCTION']).default('TESTNET'),

  MIND_RELAY_PUBLIC_KEY: z.string().min(1, 'MIND_RELAY_PUBLIC_KEY required (base64 Ed25519)'),
  OPERATOR_ID: z.string().min(1, 'OPERATOR_ID required (Telegram user ID)'),
  CONVERSATION_ID: z.string().min(1, 'CONVERSATION_ID required (Telegram conversation ID)'),

  MIND_CALLBACK_URL: z.string().url().optional(),
  TELEGRAM_BOT_TOKEN: z.string().optional(),
  TELEGRAM_CHAT_ID: z.string().optional(),

  ENVELOPE_REPLAY_WINDOW_SEC: z.coerce.number().int().positive().default(300),
  INTENT_EXPIRY_SEC: z.coerce.number().int().positive().default(900),
  PENDING_AUTHORIZATION_SLA_HOURS: z.coerce.number().int().positive().default(24),
  RATE_LIMIT_WINDOW_HOURS: z.coerce.number().int().positive().default(24),
  RATE_LIMIT_MAX_DRAFTS: z.coerce.number().int().positive().default(5),
});

export type Config = z.infer<typeof ConfigSchema>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = ConfigSchema.safeParse(env);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('; ');
    throw new Error(`Invalid configuration: ${issues}`);
  }

  // Hard gate: this build is Testnet-only. Fail-closed on any other value.
  if (parsed.data.FIREBLOCKS_ENVIRONMENT !== 'TESTNET') {
    throw new Error(
      `FIREBLOCKS_ENVIRONMENT="${parsed.data.FIREBLOCKS_ENVIRONMENT}" is not allowed. This build is Testnet-only.`
    );
  }

  // Validate public key shape.
  try {
    const decoded = Buffer.from(parsed.data.MIND_RELAY_PUBLIC_KEY, 'base64');
    if (decoded.length !== 32) {
      throw new Error(`MIND_RELAY_PUBLIC_KEY must decode to 32 bytes, got ${decoded.length}`);
    }
  } catch (err) {
    throw new Error(`MIND_RELAY_PUBLIC_KEY is not valid base64: ${(err as Error).message}`);
  }

  return parsed.data;
}
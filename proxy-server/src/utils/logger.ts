import pino, { type Logger } from "pino";

export type { Logger } from "pino";

export function createLogger(options?: {
  level?: string;
  name?: string;
}): Logger {
  const level = options?.level ?? "info";
  const name = options?.name ?? "guardian-proxy";

  if (process.env.NODE_ENV !== "production") {
    return pino({
      level,
      name,
      transport: {
        target: "pino-pretty",
      },
    });
  }

  return pino({ level, name });
}

export const logger = createLogger();

const DENY_TTL_MS = 300 * 1000; // matches the original 300s TTL
const SWEEP_INTERVAL_MS = 60 * 1000; // rate-limit the full-map sweep to once/minute

export interface TokenDenyList {
  isDenied(): Promise<boolean>;
  deny(): Promise<void>;
}

const deniedTokens = new Map<string, number>(); // hash -> deniedAt
let lastSweepAt = 0;

function sweepExpired(now: number): void {
  if (now - lastSweepAt < SWEEP_INTERVAL_MS) return;
  lastSweepAt = now;
  for (const [key, deniedAt] of deniedTokens) {
    if (now - deniedAt > DENY_TTL_MS) {
      deniedTokens.delete(key);
    }
  }
}

export function createTokenDenyList(token: string): TokenDenyList {
  let hashPromise: Promise<string> | null = null;
  const getHash = () => (hashPromise ??= hashToken(token));

  return {
    async isDenied() {
      const now = Date.now();
      sweepExpired(now);

      const hash = await getHash();
      const deniedAt = deniedTokens.get(hash);
      if (deniedAt === undefined) return false;
      if (now - deniedAt > DENY_TTL_MS) {
        deniedTokens.delete(hash);
        return false;
      }
      return true;
    },
    async deny() {
      const hash = await getHash();
      deniedTokens.set(hash, Date.now());
    },
  };
}

async function hashToken(token: string): Promise<string> {
  const data = new TextEncoder().encode(token);
  const buf = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

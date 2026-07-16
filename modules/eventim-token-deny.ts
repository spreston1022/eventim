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

export function createTokenDenyList(token: string, scope?: string): TokenDenyList {
  let hashPromise: Promise<string> | null = null;
  const getHash = () => (hashPromise ??= computeKey(token, scope));

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

// Without `scope`, a token denied under one policy instance's config (e.g.
// rejected as an untrusted issuer) stays denied everywhere for the TTL, even
// on another instance where the same issuer is trusted. Mixing in a scope
// (e.g. the policy name) keeps deny verdicts local to the config that made them.
async function computeKey(token: string, scope?: string): Promise<string> {
  const tokenHash = await hashToken(token);
  if (!scope) return tokenHash;
  const scopeHash = await hashToken(scope);
  return `${tokenHash}:${scopeHash}`;
}

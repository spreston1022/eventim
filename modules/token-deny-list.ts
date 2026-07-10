// A legitimate token is, by definition, always a miss here - so this is a
// plain per-isolate in-process Map rather than MemoryZoneReadThroughCache.
// That cache's zone tier is unconditionally consulted on every memory miss
// (no negative-result caching), meaning every valid request would pay a
// real cache-backend round trip just to learn "not denied" - far more
// expensive than the ~30us jwtVerify() this check exists to skip, and for
// no benefit since the zone tier doesn't reliably work on Linode anyway.
// Worst case without cross-isolate sharing: a repeated bad token gets
// independently re-verified (~30us) and re-denied on each isolate it lands
// on, instead of once globally - negligible next to what a real volumetric
// attack would need to cost anything.
const DENY_TTL_MS = 60 * 60 * 1000; // 1 hour
const SWEEP_INTERVAL_MS = 60 * 1000; // rate-limit the full-map sweep to once/minute

const deniedTokens = new Map<string, number>(); // hash -> deniedAt
let lastSweepAt = 0;

// Bounds memory from a sustained attack using many distinct never-repeated
// bad tokens, where lazy per-key expiry (below) would never fire. Rate
// limited so it doesn't become the same per-request O(n) cost this whole
// design is meant to avoid.
function sweepExpired(now: number): void {
  if (now - lastSweepAt < SWEEP_INTERVAL_MS) {
    return;
  }
  lastSweepAt = now;
  for (const [key, deniedAt] of deniedTokens) {
    if (now - deniedAt > DENY_TTL_MS) {
      deniedTokens.delete(key);
    }
  }
}

// scope is the effective expected audience for this check (see
// getEffectiveAudience in dynamic-jwks-policy.ts). One policy instance can
// serve multiple routes expecting different audiences, and audience
// mismatch is the one failure mode that's context-dependent rather than an
// intrinsic property of the token - the same token can be genuinely valid
// for route A's audience while invalid for route B's. Without scoping,
// a wrong-audience rejection on one route would incorrectly block the same
// token on a different route where it would otherwise pass. Other failure
// types (bad signature, expired, malformed) are token-intrinsic and would
// simply get independently re-denied per scope - a minor efficiency cost,
// not a correctness issue.
export function createTokenDenyList(token: string, scope?: string) {
  // Combine two independently-hashed fixed-length digests rather than
  // concatenating raw strings - the token isn't validated as a real JWT at
  // this point, so it could in principle contain whatever separator we'd
  // otherwise pick.
  const keyPromise = scope
    ? Promise.all([hashToken(token), hashToken(scope)]).then(
        ([tokenHash, scopeHash]) => `${tokenHash}:${scopeHash}`,
      )
    : hashToken(token);

  return {
    async isDenied(): Promise<boolean> {
      const now = Date.now();
      sweepExpired(now);

      const key = await keyPromise;
      const deniedAt = deniedTokens.get(key);
      if (deniedAt === undefined) {
        return false;
      }
      if (now - deniedAt > DENY_TTL_MS) {
        deniedTokens.delete(key);
        return false;
      }
      return true;
    },
    async deny(): Promise<void> {
      const key = await keyPromise;
      deniedTokens.set(key, Date.now());
    },
  };
}

// Hash so raw tokens never sit in the cache, and keys stay a fixed length.
async function hashToken(token: string): Promise<string> {
  const data = new TextEncoder().encode(token);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return toHex(digest);
}

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

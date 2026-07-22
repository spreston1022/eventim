import { createRemoteJWKSet, JWTVerifyGetKey } from "jose";

// One resolver per issuer (realm), reused for as long as this isolate stays
// warm. `jose` handles its own internal cache/cooldown and will transparently
// refetch on an unrecognized `kid` (e.g. after key rotation) - no need to
// reimplement that ourselves.
//
// Entries are evicted after REALM_IDLE_TTL_MS of inactivity. The cache key is
// the resolved JWKS URI, itself derived from the token's (unverified at this
// point) `iss` claim, so without a cap this map grows without bound - both
// from legitimate realm churn and from anyone crafting distinct fake realm
// paths under an otherwise-trusted host.
const REALM_IDLE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const REALM_SWEEP_INTERVAL_MS = 60 * 1000; // rate-limit the full-map sweep to once/minute

interface CachedJwks {
  jwks: JWTVerifyGetKey;
  lastUsedAt: number;
}

const jwksByUri = new Map<string, CachedJwks>();
let lastRealmSweepAt = 0;

// Throttled rather than run on every request - an unthrottled full-map sweep
// is negligible at expected cardinality, but scales linearly with map size
// and so works against you specifically under the attack this eviction
// exists to defend against (many fake realm names inflating the map).
function evictIdleJwks(now: number): void {
  if (now - lastRealmSweepAt < REALM_SWEEP_INTERVAL_MS) {
    return;
  }
  lastRealmSweepAt = now;
  for (const [key, entry] of jwksByUri) {
    if (now - entry.lastUsedAt > REALM_IDLE_TTL_MS) {
      jwksByUri.delete(key);
    }
  }
}

// Cheap surrogate key - issuer + jwksTemplate + realm together fully
// determine the resolved JWKS URI, so this is just as specific as the real
// jwksUri.href without needing a string .replace() + URL parse just to
// check whether the cache already has an entry.
function buildKey(jwksTemplate: string, issuer: string, realm: string): string {
  return `${issuer}|${jwksTemplate}|${realm}`;
}

export default function getJwks(
  jwksTemplate: string,
  issuer: string,
  realm: string,
): JWTVerifyGetKey {
  const now = Date.now();
  evictIdleJwks(now);

  // Keyed by issuer + jwksTemplate + realm, not just the issuer - two
  // configs sharing an issuer but using different templates would otherwise
  // silently share whichever resolver was created first.
  const key = buildKey(jwksTemplate, issuer, realm);
  const cached = jwksByUri.get(key);
  if (cached) {
    cached.lastUsedAt = now;
    return cached.jwks;
  }

  // Only build the real URL (string replace + URL parse) on an actual cache
  // miss - the common case (same realm hit repeatedly) skips this entirely.
  const jwksUri = new URL(jwksTemplate.replace("${realm}", realm), issuer);
  const jwks = createRemoteJWKSet(jwksUri);
  jwksByUri.set(key, { jwks, lastUsedAt: now });
  return jwks;
}

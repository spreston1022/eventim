import {
  HttpProblems,
  InboundPolicyHandler,
  MemoryZoneReadThroughCache,
  ZuploContext,
  ZuploRequest,
} from "@zuplo/runtime";
import {
  createLocalJWKSet,
  createRemoteJWKSet,
  decodeJwt,
  errors,
  jwtVerify,
  JWTVerifyGetKey,
} from "jose";
import { createTokenDenyList } from "./token-deny-list.js";

export interface DynamicJwksAuthPolicyOptions {
  /**
   * Only tokens whose `iss` claim resolves to one of these trusted
   * host+path prefixes are accepted. `iss` is unverified when we read it, so
   * this allowlist is what stops a forged token from pointing the gateway at
   * an attacker-controlled JWKS endpoint.
   *
   * Compared via parsed URL (protocol + exact host + path prefix), not raw
   * string prefix matching - so a crafted issuer like
   * "https://keycloak.eventim.com.attacker.com/realms/evil" can't slip past
   * by merely sharing a string prefix with a trusted entry.
   *
   * Example: ["https://keycloak.eventim.com/realms/"]
   */
  issuerPrefixes: string[];
  /**
   * Path appended to `iss` to build the realm's JWKS URL.
   * Defaults to Keycloak's well-known layout.
   */
  jwksPath?: string;
  /**
   * Expected `aud` claim. Omit to skip audience validation at the gateway
   * (e.g. audience isn't consistent across realms) and enforce it downstream
   * instead.
   */
  audience?: string;
}

// Parses both sides as URLs and compares protocol + exact host + path
// prefix, rather than doing a raw string startsWith on `iss`. Raw prefix
// matching is bypassable: "https://keycloak.eventim.com.attacker.com/realms/evil"
// shares a string prefix with "https://keycloak.eventim.com" but resolves to
// a completely different host. Comparing the parsed `.host` closes that off
// regardless of whether a trusted prefix happens to end in a path segment.
function isTrustedIssuer(issuer: string, trustedPrefixes: string[]): boolean {
  let issuerUrl: URL;
  try {
    issuerUrl = new URL(issuer);
  } catch {
    return false;
  }

  return trustedPrefixes.some((prefix) => {
    let prefixUrl: URL;
    try {
      prefixUrl = new URL(prefix);
    } catch {
      return false;
    }
    return (
      issuerUrl.protocol === prefixUrl.protocol &&
      issuerUrl.host === prefixUrl.host &&
      issuerUrl.pathname.startsWith(prefixUrl.pathname)
    );
  });
}

// One resolver per issuer (realm), reused for as long as this isolate stays
// warm. `jose` handles its own internal cache/cooldown and will transparently
// refetch on an unrecognized `kid` (e.g. after key rotation) for the remote
// (real IdP) path. The same-origin path caches the fetched keyset for the
// isolate's lifetime.
//
// Entries are evicted after REALM_IDLE_TTL_MS of inactivity. The realm/issuer
// cache key is derived from the token's (unverified at this point) `iss`
// claim, so without a cap this map grows without bound - both from
// legitimate realm churn over the life of a long-running isolate, and from
// anyone crafting distinct fake realm paths under an otherwise-trusted host.
const REALM_IDLE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

interface CachedJwks {
  jwks: Promise<JWTVerifyGetKey>;
  lastUsedAt: number;
}

const jwksByIssuer = new Map<string, CachedJwks>();

function evictIdleJwks(now: number): void {
  for (const [issuer, entry] of jwksByIssuer) {
    if (now - entry.lastUsedAt > REALM_IDLE_TTL_MS) {
      jwksByIssuer.delete(issuer);
    }
  }
}

function getJwks(
  issuer: string,
  jwksPath: string,
  request: ZuploRequest,
  context: ZuploContext,
): Promise<JWTVerifyGetKey> {
  const now = Date.now();
  evictIdleJwks(now);

  const cached = jwksByIssuer.get(issuer);
  if (cached) {
    cached.lastUsedAt = now;
    return cached.jwks;
  }

  const jwksUrl = new URL(`${issuer}${jwksPath}`);
  const gatewayOrigin = new URL(request.url).origin;

  const jwks =
    jwksUrl.origin === gatewayOrigin
      ? // Same gateway (e.g. an IdP mocked as routes on this project) - the
        // platform doesn't allow a Worker to fetch() back out to its own
        // deployed URL, so invoke the route in-process instead. A real,
        // separately-hosted Keycloak never hits this path.
        context
          .invokeRoute(jwksUrl.pathname)
          .then((res) => {
            if (!res.ok) {
              throw new Error(`JWKS fetch failed with status ${res.status}`);
            }
            return res.json();
          })
          .then((keySet) => createLocalJWKSet(keySet))
      : Promise.resolve(createRemoteJWKSet(jwksUrl));

  jwksByIssuer.set(issuer, { jwks, lastUsedAt: now });

  // A rejected promise would otherwise sit in the cache and be served to
  // every subsequent request for this issuer forever (each hit also
  // refreshes lastUsedAt, so idle-eviction never kicks in either). Evict it
  // so the next request gets a fresh attempt instead of the same failure.
  jwks.catch(() => {
    if (jwksByIssuer.get(issuer)?.jwks === jwks) {
      jwksByIssuer.delete(issuer);
    }
  });

  return jwks;
}

export const dynamicJwksAuthPolicy: InboundPolicyHandler<
  DynamicJwksAuthPolicyOptions
> = async (
  request: ZuploRequest,
  context: ZuploContext,
  options: DynamicJwksAuthPolicyOptions,
  policyName: string,
) => {
  const authHeader = request.headers.get("authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return HttpProblems.unauthorized(request, context, {
      detail: "Missing bearer token",
    });
  }
  const token = authHeader.slice("Bearer ".length);

  const denyCache = new MemoryZoneReadThroughCache<number>(
    "denied-token-cache",
    context,
  );
  const denyList = createTokenDenyList(token, denyCache, context);

  if (await denyList.isDenied()) {
    context.log.warn(`[${policyName}] rejected denied token`);
    return HttpProblems.unauthorized(request, context, {
      detail: "Token denied",
    });
  }

  let issuer: string | undefined;
  try {
    issuer = decodeJwt(token).iss;
  } catch {
    await denyList.deny();
    return HttpProblems.unauthorized(request, context, {
      detail: "Malformed token",
    });
  }

  if (!issuer || !isTrustedIssuer(issuer, options.issuerPrefixes)) {
    context.log.warn(
      `[${policyName}] rejected token with untrusted issuer: ${issuer}`,
    );
    await denyList.deny();
    return HttpProblems.unauthorized(request, context, {
      detail: "Untrusted issuer",
    });
  }

  try {
    const jwks = await getJwks(
      issuer,
      options.jwksPath ?? "/protocol/openid-connect/certs",
      request,
      context,
    );
    const { payload } = await jwtVerify(token, jwks, {
      issuer,
      audience: options.audience,
    });

    request.user = {
      sub: typeof payload.sub === "string" ? payload.sub : "unknown",
      data: payload,
    };
  } catch (err) {
    context.log.warn(
      `[${policyName}] token verification failed: ${(err as Error)?.message ?? err}`,
    );
    // Only deny-list on errors that mean the token itself is bad - a
    // transient JWKS-fetch failure or network blip shouldn't lock out a
    // token that would otherwise verify fine once the IdP is reachable
    // again.
    if (isDefinitivelyInvalidToken(err)) {
      await denyList.deny();
    }
    return HttpProblems.unauthorized(request, context, {
      detail: "Invalid token",
    });
  }

  return request;
};

function isDefinitivelyInvalidToken(err: unknown): boolean {
  return (
    err instanceof errors.JWTClaimValidationFailed ||
    err instanceof errors.JWTExpired ||
    err instanceof errors.JWSSignatureVerificationFailed ||
    err instanceof errors.JWTInvalid ||
    err instanceof errors.JWSInvalid ||
    err instanceof errors.JWKSNoMatchingKey
  );
}

export default dynamicJwksAuthPolicy;

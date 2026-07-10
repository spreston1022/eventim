import {
  HttpProblems,
  InboundPolicyHandler,
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
   * Expected `aud` claim, used when the route itself doesn't declare its own
   * `x-eventim-auth.audience` (see {@link getEffectiveAudience}). Omit both
   * to skip audience validation at the gateway (e.g. audience isn't
   * consistent across realms) and enforce it downstream instead.
   */
  audience?: string;
}

interface RouteEventimAuthExtension {
  "x-eventim-auth"?: { audience?: string };
}

// Audience can be pinned per-route via an `x-eventim-auth.audience` OAS
// extension (e.g. several routes sharing one policy instance but expecting
// different audiences), falling back to the policy-level `options.audience`
// default when a route doesn't declare its own.
function getEffectiveAudience(
  context: ZuploContext,
  options: DynamicJwksAuthPolicyOptions,
): string | undefined {
  const routeData = context.route.raw<RouteEventimAuthExtension>();
  // || rather than ?? - an explicit-but-empty route audience ("") is
  // misconfiguration, not a deliberate "no audience" signal, so it should
  // fall back to the policy default the same way an absent one does.
  return routeData?.["x-eventim-auth"]?.audience || options.audience;
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

  // A query string or fragment isn't part of any legitimate Keycloak realm
  // issuer, and would otherwise get carried into the JWKS URL we build from
  // this same issuer string later, silently breaking the JWKS path
  // (`?a=b/protocol/openid-connect/certs` ends up inside the query, not
  // appended to the path). Reject outright rather than let a weird-but-
  // still-host-trusted variant pollute the JWKS cache with garbage keys.
  if (issuerUrl.search || issuerUrl.hash) {
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
const REALM_SWEEP_INTERVAL_MS = 60 * 1000; // rate-limit the full-map sweep to once/minute

interface CachedJwks {
  jwks: Promise<JWTVerifyGetKey>;
  lastUsedAt: number;
}

const jwksByIssuer = new Map<string, CachedJwks>();
let lastRealmSweepAt = 0;

// Throttled rather than run on every request - same pattern as
// token-deny-list.ts's sweepExpired. An unthrottled full-map sweep is
// negligible at expected cardinality, but scales linearly with map size and
// so works against you specifically under the attack this eviction exists
// to defend against (many fake realm names inflating the map).
function evictIdleJwks(now: number): void {
  if (now - lastRealmSweepAt < REALM_SWEEP_INTERVAL_MS) {
    return;
  }
  lastRealmSweepAt = now;
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
  const authHeader = request.headers.get("authorization") ?? "";
  // Auth-scheme names are case-insensitive (RFC 7235) - a client sending
  // "bearer <token>" is just as valid as "Bearer <token>". \S+ (not .+)
  // so trailing whitespace doesn't get folded into the token - a JWT's
  // compact serialization never contains whitespace, and a naive .+ would
  // otherwise capture a whitespace-only "token" as a non-empty match.
  const bearerMatch = /^Bearer\s+(\S+)\s*$/i.exec(authHeader);
  if (!bearerMatch) {
    return HttpProblems.unauthorized(request, context, {
      detail: "Missing bearer token",
    });
  }
  const token = bearerMatch[1];

  const effectiveAudience = getEffectiveAudience(context, options);
  const denyList = createTokenDenyList(token, effectiveAudience);

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
      audience: effectiveAudience,
    });

    if (typeof payload.sub !== "string" || payload.sub.length === 0) {
      await denyList.deny();
      return HttpProblems.unauthorized(request, context, {
        detail: "No valid sub claim in token",
      });
    }

    request.user = {
      sub: payload.sub,
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

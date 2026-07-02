import {
  HttpProblems,
  InboundPolicyHandler,
  ZuploContext,
  ZuploRequest,
} from "@zuplo/runtime";
import { createRemoteJWKSet, decodeJwt, jwtVerify } from "jose";

export interface DynamicJwksAuthPolicyOptions {
  /**
   * Only tokens whose `iss` claim starts with one of these values are
   * trusted. `iss` is unverified when we read it, so this allowlist is what
   * stops a forged token from pointing the gateway at an attacker-controlled
   * JWKS endpoint.
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

// One resolver per issuer (realm), reused for as long as this isolate stays
// warm. `jose` handles its own internal cache/cooldown and will transparently
// refetch on an unrecognized `kid` (e.g. after key rotation).
const jwksByIssuer = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function getJwks(issuer: string, jwksPath: string) {
  let jwks = jwksByIssuer.get(issuer);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(`${issuer}${jwksPath}`));
    jwksByIssuer.set(issuer, jwks);
  }
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

  let issuer: string | undefined;
  try {
    issuer = decodeJwt(token).iss;
  } catch {
    return HttpProblems.unauthorized(request, context, {
      detail: "Malformed token",
    });
  }

  if (!issuer || !options.issuerPrefixes.some((prefix) => issuer.startsWith(prefix))) {
    context.log.warn(
      `[${policyName}] rejected token with untrusted issuer: ${issuer}`,
    );
    return HttpProblems.unauthorized(request, context, {
      detail: "Untrusted issuer",
    });
  }

  const jwks = getJwks(issuer, options.jwksPath ?? "/protocol/openid-connect/certs");

  try {
    const { payload } = await jwtVerify(token, jwks, {
      issuer,
      audience: options.audience,
    });

    request.user = {
      sub: typeof payload.sub === "string" ? payload.sub : "unknown",
      data: payload,
    };
  } catch (err) {
    const message = (err as Error)?.message ?? String(err);
    const name = (err as Error)?.name ?? "Error";
    context.log.warn(`[${policyName}] token verification failed: ${message}`);
    // TEMPORARY: surfacing the real error for debugging a prod-only failure.
    // Revert to a generic "Invalid token" detail once diagnosed.
    return HttpProblems.unauthorized(request, context, {
      detail: `Invalid token: [${name}] ${message}`,
    });
  }

  return request;
};

export default dynamicJwksAuthPolicy;

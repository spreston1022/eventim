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
  jwtVerify,
  JWTVerifyGetKey,
} from "jose";

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
// refetch on an unrecognized `kid` (e.g. after key rotation) for the remote
// (real IdP) path. The same-origin path caches the fetched keyset for the
// isolate's lifetime.
const jwksByIssuer = new Map<string, Promise<JWTVerifyGetKey>>();

function getJwks(
  issuer: string,
  jwksPath: string,
  request: ZuploRequest,
  context: ZuploContext,
): Promise<JWTVerifyGetKey> {
  let jwks = jwksByIssuer.get(issuer);
  if (!jwks) {
    const jwksUrl = new URL(`${issuer}${jwksPath}`);
    const gatewayOrigin = new URL(request.url).origin;

    jwks =
      jwksUrl.origin === gatewayOrigin
        ? // Same gateway (e.g. an IdP mocked as routes on this project) - the
          // platform doesn't allow a Worker to fetch() back out to its own
          // deployed URL, so invoke the route in-process instead. A real,
          // separately-hosted Keycloak never hits this path.
          context
            .invokeRoute(jwksUrl.pathname)
            .then((res) => res.json())
            .then((keySet) => createLocalJWKSet(keySet))
        : Promise.resolve(createRemoteJWKSet(jwksUrl));

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
    return HttpProblems.unauthorized(request, context, {
      detail: "Invalid token",
    });
  }

  return request;
};

export default dynamicJwksAuthPolicy;

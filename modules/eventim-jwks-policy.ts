import {HttpProblems, InboundPolicyHandler, ZuploContext, ZuploRequest} from "@zuplo/runtime";
import {decodeJwt, JWTPayload, jwtVerify} from "jose";
import {createTokenDenyList} from "./eventim-token-deny.js";
import getJwks from "./eventim-jwks-resolver-cache.js";

export interface JwksPolicyOptions {
    issuerPrefixes: string[];
    jwksTemplate: string;
}

const DEFAULTS: Required<JwksPolicyOptions> = {
    issuerPrefixes: ['https://api.eventim.com'],
    jwksTemplate: '/identity/auth/realms/${realm}/protocol/openid-connect/certs'
}

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

function getRealmFromIssuer(iss: string) {
    if (typeof iss !== "string") {
        throw new Error("Missing issuer claim");
    }
    const url = new URL(iss);
    const parts = url.pathname.split("/").filter(Boolean);

    const idx = parts.indexOf("realms");

    if (idx === -1 || idx + 1 >= parts.length) {
        throw new Error(`Issuer does not contain a realm: ${iss}`);
    }

    return parts[idx + 1];
}

export const eventimJwksAuthPolicy: InboundPolicyHandler<
    JwksPolicyOptions
> = async (
    request: ZuploRequest,
    context: ZuploContext,
    options: JwksPolicyOptions,
    policyName: string,
) => {
    const config = {...DEFAULTS, ...options};
    const authHeader = request.headers.get("authorization") ?? "";
    // "bearer <token>" is just as valid as "Bearer <token>" per RFC 7235.
    const bearerMatch = /^Bearer\s+(\S+)\s*$/i.exec(authHeader);
    if (!bearerMatch) {
        return HttpProblems.unauthorized(request, context, {
            detail: "Missing bearer token",
        });
    }
    const token = bearerMatch[1];
    const denyList = createTokenDenyList(token, policyName);

    if (await denyList.isDenied()) {
        return HttpProblems.unauthorized(request, context, {
            detail: "Token denied",
        });
    }

    let jwt: JWTPayload | undefined;
    try {
        jwt = decodeJwt(token);
    } catch {
        context.waitUntil(denyList.deny());
        return HttpProblems.unauthorized(request, context, {
            detail: "Malformed token",
        });
    }

    const issuer = jwt.iss;
    if (!issuer || !isTrustedIssuer(issuer, config.issuerPrefixes)) {
        context.waitUntil(denyList.deny());
        context.log.warn(
            `[${policyName}] rejected token with untrusted issuer: ${issuer}`,
        );
        return HttpProblems.unauthorized(request, context, {
            detail: "Untrusted issuer",
        });
    }

    // The path-prefix check in isTrustedIssuer doesn't guarantee a `realms`
    // segment (e.g. a prefix with pathname "/"), so a trusted-host issuer
    // can still fail here - wrapped so a crafted issuer yields a clean 401
    // instead of an uncaught exception (which would otherwise surface as a
    // 500, before the token's signature has even been checked).
    let realm: string;
    try {
        realm = getRealmFromIssuer(issuer);
    } catch {
        context.waitUntil(denyList.deny());
        return HttpProblems.unauthorized(request, context, {
            detail: "Untrusted issuer",
        });
    }

    const routeData = context.route.raw<{ "x-eventim-auth"?: { audience?: string } }>();
    const audience = routeData?.["x-eventim-auth"]?.audience;

    const jwks = getJwks(config.jwksTemplate, issuer, realm);

    let payload: JWTPayload;
    try {
        // No `issuer` option here - jwt.iss was already validated against
        // the trusted-issuer allowlist above. Passing it back to jwtVerify
        // would just compare the token's claimed issuer to itself, which
        // always passes and validates nothing.
        ({ payload } = await jwtVerify(token, jwks, { audience }));
    } catch (err) {
        context.log.warn(
            `[${policyName}] token verification failed: ${(err as Error)?.message}`,
        );
        return HttpProblems.unauthorized(request, context, {
            detail: "Could not verify token"
        });
    }

    if (!payload.sub) {
        context.waitUntil(denyList.deny());
        return HttpProblems.unauthorized(request, context, {
            detail: "No valid sub claim in token",
        });
    }

    request.user = { sub: payload.sub, data: payload };

    return request;
}

export default eventimJwksAuthPolicy;

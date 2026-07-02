import { ZuploContext, ZuploRequest } from "@zuplo/runtime";
import { exportJWK, generateKeyPair, KeyLike, SignJWT } from "jose";

/**
 * Stands in for Keycloak so the dynamic-JWKS policy can be exercised without
 * a real IdP. Each "realm" gets its own signing key, generated on first use
 * and cached for the life of this isolate - restarting the dev server mints
 * new keys, which invalidates any previously issued dummy tokens.
 */

interface RealmKeys {
  privateKey: KeyLike;
  publicJwk: JsonWebKey & { kid: string; alg: string; use: string };
}

const realmKeys = new Map<string, Promise<RealmKeys>>();

function getRealmKeys(realm: string): Promise<RealmKeys> {
  let keys = realmKeys.get(realm);
  if (!keys) {
    keys = (async () => {
      const { privateKey, publicKey } = await generateKeyPair("RS256", {
        extractable: true,
      });
      const publicJwk = await exportJWK(publicKey);
      return {
        privateKey,
        publicJwk: { ...publicJwk, kid: `${realm}-key-1`, alg: "RS256", use: "sig" },
      };
    })();
    realmKeys.set(realm, keys);
  }
  return keys;
}

/** GET /mock-idp/realms/{realm}/protocol/openid-connect/certs */
export async function jwksHandler(request: ZuploRequest, context: ZuploContext) {
  const realm = request.params.realm;
  const { publicJwk } = await getRealmKeys(realm);
  return new Response(JSON.stringify({ keys: [publicJwk] }), {
    headers: { "content-type": "application/json" },
  });
}

/**
 * POST /mock-idp/realms/{realm}/token
 * Mints a dummy signed JWT for testing, standing in for Keycloak's token
 * endpoint. Body (optional, all fields optional): { "aud": "...", "sub": "..." }
 */
export async function tokenHandler(request: ZuploRequest, context: ZuploContext) {
  const realm = request.params.realm;
  const { privateKey, publicJwk } = await getRealmKeys(realm);

  let body: { aud?: string; sub?: string } = {};
  try {
    body = await request.json();
  } catch {
    // no/invalid body - fall back to defaults below
  }

  const issuer = `${new URL(request.url).origin}/mock-idp/realms/${realm}`;
  const audience = body.aud ?? "https://api.eventim-dummy.com";
  const subject = body.sub ?? "demo-user";

  const accessToken = await new SignJWT({ realm })
    .setProtectedHeader({ alg: "RS256", kid: publicJwk.kid })
    .setIssuer(issuer)
    .setAudience(audience)
    .setSubject(subject)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey);

  return new Response(
    JSON.stringify({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 300,
      issuer,
      audience,
    }),
    { headers: { "content-type": "application/json" } },
  );
}

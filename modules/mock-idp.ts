import { ZuploContext, ZuploRequest } from "@zuplo/runtime";
import { importJWK, KeyLike, SignJWT } from "jose";

/**
 * Stands in for Keycloak so the dynamic-JWKS policy can be exercised without
 * a real IdP.
 *
 * The signing key is fixed (baked into source, not generated at runtime).
 * On a real edge deployment, requests for the same realm can land on
 * different isolates - a key generated on first use per isolate would mean
 * the isolate that signs a token and the isolate that later serves the
 * certs endpoint could disagree on the key, breaking verification. A static
 * key sidesteps that entirely. Only `kid` varies per realm, which is enough
 * to demonstrate that each realm resolves its own JWKS URL.
 *
 * This is a mock for demo purposes only - never bake a real signing key
 * into source for anything that isn't throwaway dummy data.
 */

const STATIC_PUBLIC_JWK = {
  kty: "RSA",
  n: "k3UHT6sr7u5_gQuRVdbt4ShH-EjGSGqZ9dFR5t-Q5dRwdkEqFe686Gh8asJ0KDE8SWnEpZcly0QlPlEN7rwFvGOri57i0q25RnaZ7QqgBMFk9UVVYpKc91IoR4PywD2n3O6udhHcZM_X4ltgBNavhYwZLvUzq7bLjQZYLFM5bDcvBjh3Y8z6rkG_zn6Z5aUAZpBleKqZf5NCtSz4xbGywTqPkYaP4hFq1d3ifTrUHr2M0VOEG9KQlzATAE4P5y30Etatx6di-TgxMtM6SOEQTnJqRQhwLVHi5OA37FxMB2ar3C7V4iOpkZYBNTQWdTC1HkfDHc2TsHqima5ydVgOVw",
  e: "AQAB",
};

const STATIC_PRIVATE_JWK = {
  ...STATIC_PUBLIC_JWK,
  d: "C2vBCTakzHjEf2Y594ASJKJOELjyQqGfEx8HTO579pEhtMcPT2uSTh3ppQsym_pURQtgI8M1Ni0tBUqZ3afKefDuVH4V62NxOjftbCKqijPAcg7QsjXQ2ocOf5uErccYvU_vS03O2DAQ9INHSJioN5vGR5DOU7pwwZeANM6tX-g4IDtN9LifG4I82qIzlTJ2QxkIHaEGO-fZUBvY8m7hXZU0kXM9LD1jvQY7nh5zVXnzSVna3E77gsmAlZ3HSd_xi_XKV2VpFxNVZ-UW5zcHR4s_k76ZIwL-vXU92YNKDslzzbYsuQzz15AGFW3HB3jkwmIRAPaUAC3gOMGUnY9rYQ",
  p: "ztcfXLoKARbogcueJ83N8r-2yh1rpICy5XHER2fI71Ish7iWob82WD_FllkafkzCzIqN0EaT33sn0h5CkyKNPFrV16BZW-Bj4Z7olmeh8LhnIp2tOLHXknx99Q7bRM0T8rJ_rQcbkmSLaixgscLkKzppc9RJ0ugVY4fFAtW4heM",
  q: "toDUM-DoGkP2-so8ulgXB7kKqvUcd6wPgi7GCtJReSwmvEPdpFPzFHtd3PfXo0ol4jP0Fy22h93Y4LNTQkhmCtZ_nGXa0DNv0r5bRKVvnYo3TVpi1pGpbnF2eC-NWwtYChmlwc8LeZiSebW37zl25Bn-A0hTSdKW2kWqoLAp3_0",
  dp: "Q201OBEdecVx_f3WjLs2S8_bUn_Mu0-JAerYRT677egnxAaUdB3VJWeEjcJ2NH3pcqwoFqErS0rmbESZB0XYLLifxS7sclrvtHkM8RrPW52BYXNtKHIxB_u1Q9GYARGpUxCFNm5-unY0TGQzET-rCbx869lkR3CIqG1197qb8Gk",
  dq: "RP0yOmI8myEyDd_BURfXrN2wQKvjlQF_41BXIOQcVFfyVJy6_lGVxBpWgx9Vbq6q33WQQerP41BjmZ1wTdAccuBe4PpH2wh2rw2yZqK7LKyA90bBsibiC5PsmsYvA0mogDjtxfPEfLTGOigNXes1HEkPEqKWiYOH7v8C3zd4vOk",
  qi: "pLHwS2SIZsaqJyu8nfsKeqdMIyM1Wt4vrsf0XSxvyB55Fk674vjkxxVLhEXz2SGCuHhSLJ_dk6qCFEP1HPm2_dsy-lZmfe4Iwi89A8bZ0QnBuPB3LNJTlq-zs01Tsn67EVL9cjaDFgxB6DN3AOLwZGk_E-005N7tR3SzLBrGNB4",
};

let privateKeyPromise: Promise<KeyLike> | undefined;

function getPrivateKey(): Promise<KeyLike> {
  if (!privateKeyPromise) {
    privateKeyPromise = importJWK(STATIC_PRIVATE_JWK, "RS256") as Promise<KeyLike>;
  }
  return privateKeyPromise;
}

function publicJwkForRealm(realm: string) {
  return { ...STATIC_PUBLIC_JWK, kid: `${realm}-key-1`, alg: "RS256", use: "sig" };
}

/** GET /mock-idp/realms/{realm}/protocol/openid-connect/certs */
export async function jwksHandler(request: ZuploRequest, context: ZuploContext) {
  const realm = request.params.realm;
  return new Response(JSON.stringify({ keys: [publicJwkForRealm(realm)] }), {
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
  const privateKey = await getPrivateKey();
  const kid = publicJwkForRealm(realm).kid;

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
    .setProtectedHeader({ alg: "RS256", kid })
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

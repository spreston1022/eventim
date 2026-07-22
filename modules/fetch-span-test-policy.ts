import { InboundPolicyHandler, ZuploContext, ZuploRequest } from "@zuplo/runtime";

// Diagnostic only - not a real auth policy. Makes a single outbound fetch()
// from inside a custom-code-inbound policy, the same shape jose's
// createRemoteJWKSet does internally when resolving a JWKS. Exists to
// answer: does this fetch surface as its own child span nested under this
// policy's "policy:fetch-span-test" span (the way handler:urlForwardHandler's
// outbound call shows up as a child "SVC POST" span), or does it just add
// silent, untraced time to the parent span?
export const fetchSpanTestPolicy: InboundPolicyHandler = async (
  request: ZuploRequest,
  context: ZuploContext,
) => {
  await fetch(
    "https://eventim-poc-main-9473b72.d2.zuplo.dev/mock-idp/realms/test-realm/protocol/openid-connect/certs",
  );
  return request;
};

export default fetchSpanTestPolicy;

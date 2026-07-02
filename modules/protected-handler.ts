import { ZuploContext, ZuploRequest } from "@zuplo/runtime";

export default async function (request: ZuploRequest, context: ZuploContext) {
  return {
    message: "Authenticated via dynamically resolved JWKS",
    sub: request.user?.sub,
    claims: request.user?.data,
  };
}

import { ZuploContext, ZuploRequest } from "@zuplo/runtime";

/** GET /health - liveness check, no auth. */
export default async function (request: ZuploRequest, context: ZuploContext) {
  return "hello world";
}

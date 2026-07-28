import { ZuploContext, ZuploRequest } from "@zuplo/runtime";
import { originDurations } from "./timing-context.js";

// Test-only: hardcoded rather than configurable via route options, since
// custom handlers (unlike policies) aren't passed their route's `options`
// block - only (request, context).
const ORIGIN_BASE_URL = "https://echo.zuplo.io";

// Forwards to ORIGIN_BASE_URL, same as the built-in urlForwardHandler, but
// measures the origin call's own duration explicitly (not inferred/assumed)
// and stores it for the response-sending hook in zuplo.runtime.ts to report
// alongside total elapsed time - giving a real, measured gateway-vs-origin
// split rather than an approximation from an isolated benchmark.
export default async function timedForwardHandler(
  request: ZuploRequest,
  context: ZuploContext,
): Promise<Response> {
  const url = new URL(request.url);
  const originUrl = new URL(url.pathname + url.search, ORIGIN_BASE_URL);

  const start = Date.now();
  const response = await fetch(originUrl, {
    method: request.method,
    headers: request.headers,
    body: ["GET", "HEAD"].includes(request.method) ? undefined : request.body,
  });
  originDurations.set(context, Date.now() - start);

  return response;
}

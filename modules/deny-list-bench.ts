import { MemoryZoneReadThroughCache, ZuploContext, ZuploRequest } from "@zuplo/runtime";
import { createTokenDenyList } from "./token-deny-list.js";

// TEMP: benchmark route, not part of the real auth path. Measures the real
// cost of MemoryZoneReadThroughCache-backed isDenied() checks for N distinct
// never-denied tokens (the legitimate-traffic case - always a miss).
export default async function (request: ZuploRequest, context: ZuploContext) {
  const url = new URL(request.url);
  const n = Number(url.searchParams.get("n") ?? "200");

  const denyCache = new MemoryZoneReadThroughCache<number>(
    "denied-token-cache",
    context,
  );

  const start = Date.now();
  for (let i = 0; i < n; i++) {
    const denyList = createTokenDenyList(
      `bench-token-${Date.now()}-${i}`,
      denyCache,
      context,
    );
    await denyList.isDenied();
  }
  const totalMs = Date.now() - start;

  return new Response(
    JSON.stringify({
      n,
      totalMs,
      microsecondsPerCheck: (totalMs * 1000) / n,
    }),
    { headers: { "content-type": "application/json" } },
  );
}

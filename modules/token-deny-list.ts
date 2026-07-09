import { MemoryZoneReadThroughCache, ZuploContext } from "@zuplo/runtime";

// TTL is just cache hygiene -- a denied token never becomes valid later.
const DENY_TTL_SECONDS = 60 * 60; // 1 hour

export function createTokenDenyList(
  token: string,
  denyCache: MemoryZoneReadThroughCache<number>,
  context: ZuploContext,
) {
  const keyPromise = hashToken(token);

  return {
    async isDenied(): Promise<boolean> {
      try {
        const key = await keyPromise;
        const deniedAt = await denyCache.get(key);
        return deniedAt !== undefined;
      } catch (err) {
        // Fail open -- this is a perf optimization, not the security boundary.
        context.log.error("Error reading token deny cache", err);
        return false;
      }
    },
    async deny(): Promise<void> {
      const key = await keyPromise;
      try {
        // put() is synchronous (in-memory tier first, zone tier in the background).
        denyCache.put(key, Date.now(), DENY_TTL_SECONDS);
      } catch (err) {
        context.log.error("Error writing token deny cache", err);
      }
    },
  };
}

// Hash so raw tokens never sit in the cache, and keys stay a fixed length.
async function hashToken(token: string): Promise<string> {
  const data = new TextEncoder().encode(token);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return toHex(digest);
}

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

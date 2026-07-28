import { ZuploContext } from "@zuplo/runtime";

// Bridges timing data between runtime hooks (which bracket the whole
// pipeline: before all policies, after everything including the handler)
// and an individual handler (which is the only thing that can measure its
// own origin-call duration in isolation, since Zuplo doesn't expose a hook
// specifically between "policies finished" and "handler started").
export const requestStartTimes = new WeakMap<ZuploContext, number>();
export const originDurations = new WeakMap<ZuploContext, number>();

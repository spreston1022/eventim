import { RuntimeExtensions, ZuploContext, ZuploRequest } from "@zuplo/runtime";
import { McpGatewayPlugin } from "@zuplo/runtime/mcp-gateway";
import { originDurations, requestStartTimes } from "./timing-context.js";

/**
 * `runtimeInit` runs once when your gateway boots. Use it to register plugins
 * and lifecycle hooks. Docs:
 * https://zuplo.com/docs/programmable-api/runtime-extensions
 */
export function runtimeInit(runtime: RuntimeExtensions) {
  // --- MCP Gateway ---------------------------------------------------------
  // Registers the MCP Gateway, which adds the OAuth and upstream-connection
  // routes used to expose and secure MCP servers through your gateway. It is a
  // no-op until you add an MCP route/policy, so it is safe to leave enabled.
  // Docs: https://zuplo.com/docs/mcp-server/introduction
  //
  // Remove this plugin if you are not using the MCP Gateway features.
  runtime.addPlugin(new McpGatewayPlugin());

  // --- OpenTelemetry tracing - DISABLED ------------------------------------
  // Removed for performance - do not re-add without confirming the
  // overhead is acceptable at production traffic levels.

  // --- Logging (optional) --------------------------------------------------
  // Ship request logs to Datadog. Other log integrations (New Relic, Splunk,
  // Loki, Dynatrace, and others) follow the same pattern — see the logging
  // overview at https://zuplo.com/docs/articles/logging.
  // Docs: https://zuplo.com/docs/articles/log-plugin-datadog
  //
  // To enable, import the plugin and `environment` from "@zuplo/runtime":
  // runtime.addPlugin(
  //   new DataDogLoggingPlugin({
  //     apiKey: environment.DATADOG_API_KEY,
  //     source: "my-api",
  //   }),
  // );

  // --- Gateway vs. origin timing log ----------------------------------------
  // Logs total elapsed time (request start -> response ready) and, when the
  // route's handler is timed-forward-handler.ts, the origin call's own
  // measured duration - so gateway time (policies + overhead) = total -
  // origin, computed from real measurements, not an assumption that policy
  // time is negligible.
  runtime.addRequestHook((request: ZuploRequest, context: ZuploContext) => {
    requestStartTimes.set(context, Date.now());
    return request;
  });

  runtime.addResponseSendingHook(
    (response: Response, request: ZuploRequest, context: ZuploContext) => {
      const start = requestStartTimes.get(context);
      if (start !== undefined) {
        const totalMs = Date.now() - start;
        const originMs = originDurations.get(context);
        const path = new URL(request.url).pathname;
        if (originMs !== undefined) {
          const gatewayMs = totalMs - originMs;
          context.log.info(
            `[timing] ${request.method} ${path} - total=${totalMs}ms origin=${originMs}ms gateway=${gatewayMs}ms`,
          );
          originDurations.delete(context);
        } else {
          context.log.info(
            `[timing] ${request.method} ${path} - total=${totalMs}ms (no origin call measured)`,
          );
        }
        requestStartTimes.delete(context);
      }
      return response;
    },
  );
}

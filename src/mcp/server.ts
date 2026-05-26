// JSON-RPC 2.0 + MCP envelope handler for catdef.org/mcp.
//
// Speaks MCP over HTTP (streamable-http transport). Each POST to /mcp carries
// a JSON-RPC request envelope; the server returns a JSON-RPC response.
//
// Supported methods (the subset catdef.org/mcp needs):
//   initialize          → handshake; returns capabilities
//   tools/list          → list tools the caller's tier can invoke
//   tools/call          → invoke a tool
//   resources/list      → list available catdef://spec/* resources
//   resources/read      → fetch a resource by URI
//   ping                → liveness check (returns {})
//
// Anything else returns RPC_METHOD_NOT_FOUND. Notifications (no id) are
// processed but no response is sent.

import {
  JsonRpcRequest,
  JsonRpcResponse,
  JsonRpcError,
  RPC_PARSE_ERROR,
  RPC_INVALID_REQUEST,
  RPC_METHOD_NOT_FOUND,
  RPC_INVALID_PARAMS,
  RPC_INTERNAL_ERROR,
  RPC_UNAUTHORIZED,
  RPC_FORBIDDEN,
  InitializeResult,
} from "./types";
import { resolveAuth, tierAtLeast } from "./auth";
import { listResources, readResource } from "./resources";
import { findTool, toolsForTier, RpcError } from "./tools";

export interface ServerEnv {
  DB: D1Database;
  GITHUB_TOKEN?: string;
}

const PROTOCOL_VERSION = "2025-03-26";
const SERVER_NAME = "catdef-org-mcp";
const SERVER_VERSION = "0.1.0";

const INITIALIZE_INSTRUCTIONS = `catdef.org/mcp is the canonical AI-peer surface for catdef substrate work.

What you can do here:
- Read the catdef spec: resources/read catdef://spec/CATDEF_SPEC.md (and CATIO_SPEC.md, MCP_REFERENCE.md, etc.)
- Ground yourself: tools/call catdef_lookup({term: "subcat"}) or catdef_list_decisions
- File feedback (standard tier): tools/call catdef_report_feedback({category, severity, body})
- Triage queue (elevated tier; Director-issued keys only): catdef_list_feedback, catdef_set_feedback_status, catdef_attach_decision

Authentication: HTTP Authorization: Bearer <key>. Without a key, you have anonymous tier (read spec + grounding tools).

Standard keys (cdfk_<random>) are self-serve; ask the Director or check catdef.org/mcp/issue-key.
Elevated keys (cdfk_dir_<random>) are issued by the Director to the strategist/maintainer seats.

All feedback is private at submission and becomes public only via explicit curation (catdef_attach_decision with make_public:true). See https://github.com/catdef/catdef-spec/blob/main/proposals/catdef-org-mcp-canonical-surface.md for the full surface description.`;

export async function handleMcpRequest(request: Request, env: ServerEnv): Promise<Response> {
  if (request.method !== "POST") {
    return jsonResponse(rpcError(null, RPC_INVALID_REQUEST, "Only POST is supported on /mcp"), 405);
  }

  let rpc: JsonRpcRequest;
  try {
    rpc = await request.json() as JsonRpcRequest;
  } catch {
    return jsonResponse(rpcError(null, RPC_PARSE_ERROR, "Invalid JSON"), 400);
  }

  if (!rpc || typeof rpc !== "object" || rpc.jsonrpc !== "2.0" || typeof rpc.method !== "string") {
    return jsonResponse(rpcError((rpc as any)?.id ?? null, RPC_INVALID_REQUEST, "Not a valid JSON-RPC 2.0 request"), 400);
  }

  // Resolve auth once; null means present-but-invalid (vs anonymous which is fine)
  const auth = await resolveAuth(request, env);
  if (auth === null) {
    return jsonResponse(rpcError(rpc.id ?? null, RPC_UNAUTHORIZED, "Authorization header present but did not validate"), 401);
  }

  const isNotification = rpc.id === undefined;

  try {
    let result: unknown;
    switch (rpc.method) {
      case "initialize":
        result = handleInitialize();
        break;
      case "ping":
        result = {};
        break;
      case "tools/list":
        result = { tools: toolsForTier(auth) };
        break;
      case "tools/call": {
        const params = (rpc.params ?? {}) as { name?: string; arguments?: Record<string, unknown> };
        if (typeof params.name !== "string") {
          throw new RpcError(RPC_INVALID_PARAMS, "tools/call requires 'name'");
        }
        const tool = findTool(params.name);
        if (!tool) {
          throw new RpcError(RPC_METHOD_NOT_FOUND, `Unknown tool: ${params.name}`);
        }
        if (!tierAtLeast(auth, tool.tier)) {
          throw new RpcError(RPC_FORBIDDEN, `Tool '${params.name}' requires ${tool.tier} tier (current: ${auth.tier})`);
        }
        const out = await tool.handler(params.arguments ?? {}, auth, env);
        // MCP tool-call result shape: { content: [...], isError? }
        result = {
          content: [{ type: "text", text: typeof out === "string" ? out : JSON.stringify(out, null, 2) }],
        };
        break;
      }
      case "resources/list":
        result = { resources: listResources() };
        break;
      case "resources/read": {
        const params = (rpc.params ?? {}) as { uri?: string };
        if (typeof params.uri !== "string") {
          throw new RpcError(RPC_INVALID_PARAMS, "resources/read requires 'uri'");
        }
        const contents = await readResource(params.uri);
        if (!contents) {
          throw new RpcError(-32004, `Unknown resource URI: ${params.uri}`);
        }
        result = { contents: [contents] };
        break;
      }
      case "notifications/initialized":
        // Client signaling it's ready post-initialize; no-op
        return new Response(null, { status: 204 });
      default:
        if (isNotification) {
          // Spec: unknown notifications are silently ignored
          return new Response(null, { status: 204 });
        }
        throw new RpcError(RPC_METHOD_NOT_FOUND, `Unknown method: ${rpc.method}`);
    }

    if (isNotification) {
      return new Response(null, { status: 204 });
    }
    return jsonResponse({ jsonrpc: "2.0", id: rpc.id!, result });
  } catch (e) {
    if (e instanceof RpcError) {
      return jsonResponse(rpcError(rpc.id ?? null, e.code, e.message), httpStatusForRpcCode(e.code));
    }
    const msg = e instanceof Error ? e.message : "Unknown error";
    return jsonResponse(rpcError(rpc.id ?? null, RPC_INTERNAL_ERROR, msg), 500);
  }
}

function handleInitialize(): InitializeResult {
  return {
    protocolVersion: PROTOCOL_VERSION,
    capabilities: {
      tools: { listChanged: false },
      resources: { listChanged: false, subscribe: false },
    },
    serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
    instructions: INITIALIZE_INSTRUCTIONS,
  };
}

function rpcError(id: any, code: number, message: string): JsonRpcResponse {
  return { jsonrpc: "2.0", id: id ?? null, error: { code, message } };
}

function httpStatusForRpcCode(code: number): number {
  switch (code) {
    case RPC_UNAUTHORIZED: return 401;
    case RPC_FORBIDDEN: return 403;
    case -32004: return 404;
    case RPC_PARSE_ERROR:
    case RPC_INVALID_REQUEST:
    case RPC_INVALID_PARAMS:
    case RPC_METHOD_NOT_FOUND:
      return 400;
    default:
      return 500;
  }
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    },
  });
}

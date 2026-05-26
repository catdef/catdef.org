// MCP JSON-RPC 2.0 message types
// Implements just what the catdef.org/mcp server needs — initialize,
// tools/list, tools/call, resources/list, resources/read.
// Full MCP spec at https://spec.modelcontextprotocol.io

export type JsonRpcId = string | number | null;

export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: JsonRpcId;
  method: string;
  params?: unknown;
}

export interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: JsonRpcId;
  result?: unknown;
  error?: JsonRpcError;
}

export interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

export const RPC_PARSE_ERROR = -32700;
export const RPC_INVALID_REQUEST = -32600;
export const RPC_METHOD_NOT_FOUND = -32601;
export const RPC_INVALID_PARAMS = -32602;
export const RPC_INTERNAL_ERROR = -32603;
// Server-defined errors (MCP convention)
export const RPC_UNAUTHORIZED = -32001;
export const RPC_FORBIDDEN = -32002;
export const RPC_NOT_FOUND = -32004;
export const RPC_RATE_LIMITED = -32005;

// ── MCP entity shapes ───────────────────────────────────────

export interface McpTool {
  name: string;
  description: string;
  inputSchema: {
    type: "object";
    properties: Record<string, unknown>;
    required?: string[];
    additionalProperties?: boolean;
  };
}

export interface McpResource {
  uri: string;
  name: string;
  description?: string;
  mimeType?: string;
}

export interface McpResourceContents {
  uri: string;
  mimeType?: string;
  text?: string;
  blob?: string;  // base64
}

export interface McpServerInfo {
  name: string;
  version: string;
}

export interface McpCapabilities {
  tools?: { listChanged?: boolean };
  resources?: { listChanged?: boolean; subscribe?: boolean };
  prompts?: { listChanged?: boolean };
}

export interface InitializeResult {
  protocolVersion: string;
  capabilities: McpCapabilities;
  serverInfo: McpServerInfo;
  instructions?: string;
}

// ── catdef-specific auth tiers ──────────────────────────────

export type AuthTier = "anonymous" | "standard" | "elevated";

export interface AuthContext {
  tier: AuthTier;
  keyHash?: string;  // Set for standard/elevated; absent for anonymous
}

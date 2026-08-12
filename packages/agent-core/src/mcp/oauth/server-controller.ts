import { randomUUID } from 'node:crypto';

import { ErrorCodes, KimiError } from '#/errors';
import type { Promisable } from '#/utils/types';

import { AlreadyAuthorizedError, type BeginAuthorizationResult } from './service';

const DEFAULT_MCP_OAUTH_COMPLETION_TIMEOUT_MS = 15 * 60 * 1000;

export interface McpOAuthServerIdentity {
  readonly serverName: string;
  readonly serverUrl: string;
}

export interface McpOAuthServerCompleteInput {
  readonly flowId: string;
  readonly timeoutMs?: number;
}

export interface McpOAuthServerCancelInput {
  readonly flowId: string;
}

export interface McpOAuthServerStatusInput extends McpOAuthServerIdentity {
  /** When true, connect to the MCP server with the stored credentials. */
  readonly verifyWithNetwork?: boolean;
}

export type McpOAuthServerBeginResult =
  | { readonly status: 'already-authorized' }
  | {
      readonly status: 'authorization-required';
      readonly flowId: string;
      readonly authorizationUrl: string;
    };

export type McpOAuthServerAuthStatus = 'oauth-required' | 'oauth-authorized';

export interface McpOAuthServerStatusResult {
  readonly authStatus: McpOAuthServerAuthStatus;
}

export interface McpOAuthServerProbeResult {
  readonly status: string;
  readonly error?: string;
}

export interface McpOAuthServerService {
  beginAuthorization(
    serverName: string,
    serverUrl: string | URL,
  ): Promise<BeginAuthorizationResult>;
  hasTokens(serverName: string, serverUrl: string | URL): Promisable<boolean>;
  invalidate(
    serverName: string,
    serverUrl: string | URL,
    scope?: 'all' | 'client' | 'tokens' | 'discovery',
  ): Promisable<void>;
}

export interface McpOAuthServerControllerOptions {
  readonly service: McpOAuthServerService;
  readonly isAlreadyAuthorizedError?: (error: unknown) => boolean;
  readonly createFlowId?: () => string;
  readonly verifyStatusWithNetwork?: (
    identity: McpOAuthServerIdentity,
  ) => Promisable<McpOAuthServerAuthStatus>;
}

/**
 * Owns the process-local MCP OAuth flow registry for server-addressed RPCs.
 * Persisted credentials remain owned by the injected OAuth service.
 */
export class McpOAuthServerController {
  private readonly service: McpOAuthServerService;
  private readonly isAlreadyAuthorizedError: (error: unknown) => boolean;
  private readonly createFlowId: () => string;
  private readonly verifyStatusWithNetwork:
    | ((identity: McpOAuthServerIdentity) => Promisable<McpOAuthServerAuthStatus>)
    | undefined;
  private readonly flows = new Map<string, BeginAuthorizationResult>();

  constructor(options: McpOAuthServerControllerOptions) {
    this.service = options.service;
    this.isAlreadyAuthorizedError =
      options.isAlreadyAuthorizedError ??
      ((error): boolean => error instanceof AlreadyAuthorizedError);
    this.createFlowId = options.createFlowId ?? randomUUID;
    this.verifyStatusWithNetwork = options.verifyStatusWithNetwork;
  }

  async begin(input: McpOAuthServerIdentity): Promise<McpOAuthServerBeginResult> {
    const identity = normalizeMcpOAuthServerIdentity(input);
    try {
      const flow = await this.service.beginAuthorization(
        identity.serverName,
        identity.serverUrl,
      );
      const flowId = this.createFlowId();
      this.flows.set(flowId, flow);
      return {
        status: 'authorization-required',
        flowId,
        authorizationUrl: flow.authorizationUrl.toString(),
      };
    } catch (error) {
      if (this.isAlreadyAuthorizedError(error)) {
        return { status: 'already-authorized' };
      }
      throw error;
    }
  }

  async complete(
    input: McpOAuthServerCompleteInput,
    options: { readonly signal?: AbortSignal } = {},
  ): Promise<void> {
    const flow = this.flows.get(input.flowId);
    if (flow === undefined) {
      throw new KimiError(
        ErrorCodes.REQUEST_INVALID,
        `Unknown MCP OAuth flow: ${input.flowId}`,
      );
    }
    try {
      await flow.complete({
        signal: options.signal,
        timeoutMs: input.timeoutMs ?? DEFAULT_MCP_OAUTH_COMPLETION_TIMEOUT_MS,
      });
    } finally {
      this.flows.delete(input.flowId);
    }
  }

  async cancel(input: McpOAuthServerCancelInput): Promise<void> {
    const flow = this.flows.get(input.flowId);
    if (flow === undefined) return;
    this.flows.delete(input.flowId);
    await flow.cancel();
  }

  async reset(input: McpOAuthServerIdentity): Promise<void> {
    const identity = normalizeMcpOAuthServerIdentity(input);
    await this.service.invalidate(identity.serverName, identity.serverUrl, 'all');
  }

  async status(input: McpOAuthServerStatusInput): Promise<McpOAuthServerStatusResult> {
    const identity = normalizeMcpOAuthServerIdentity(input);
    const authorized = await this.service.hasTokens(identity.serverName, identity.serverUrl);
    if (!authorized) return { authStatus: 'oauth-required' };
    if (input.verifyWithNetwork !== true) return { authStatus: 'oauth-authorized' };

    const verify = this.verifyStatusWithNetwork;
    if (verify === undefined) {
      throw new KimiError(
        ErrorCodes.REQUEST_INVALID,
        'MCP OAuth network status verification is not available',
      );
    }
    return { authStatus: await verify(identity) };
  }
}

export function mcpOAuthServerAuthStatusFromProbe(
  serverName: string,
  result: McpOAuthServerProbeResult | undefined,
): McpOAuthServerAuthStatus {
  if (result?.status === 'connected') return 'oauth-authorized';
  if (result?.status === 'needs-auth') return 'oauth-required';
  const message =
    result?.error ??
    `MCP server "${serverName}" finished with status ${result?.status ?? 'unknown'}`;
  throw new KimiError(
    ErrorCodes.MCP_STARTUP_FAILED,
    message === '' ? `MCP server "${serverName}" failed network verification` : message,
  );
}

function normalizeMcpOAuthServerIdentity(
  input: McpOAuthServerIdentity,
): McpOAuthServerIdentity {
  const serverName = input.serverName.trim();
  if (serverName === '') {
    throw new KimiError(ErrorCodes.REQUEST_INVALID, 'MCP OAuth serverName must not be empty');
  }

  let url: URL;
  try {
    url = new URL(input.serverUrl.trim());
  } catch {
    throw new KimiError(
      ErrorCodes.REQUEST_INVALID,
      'MCP OAuth serverUrl must be an absolute HTTP(S) URL',
    );
  }
  if (
    (url.protocol !== 'http:' && url.protocol !== 'https:') ||
    url.username !== '' ||
    url.password !== '' ||
    url.hash !== ''
  ) {
    throw new KimiError(
      ErrorCodes.REQUEST_INVALID,
      'MCP OAuth serverUrl must be an absolute HTTP(S) URL without credentials or a fragment',
    );
  }
  return { serverName, serverUrl: url.toString() };
}

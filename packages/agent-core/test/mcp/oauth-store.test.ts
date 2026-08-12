import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'pathe';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import type { OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';
import {
  AlreadyAuthorizedError,
  McpOAuthClientProvider,
  mcpOAuthServerAuthStatusFromProbe,
  McpOAuthServerController,
  McpOAuthService,
  type BeginAuthorizationResult,
  type McpOAuthServerService,
} from '../../src/mcp/oauth';
import { JsonFileStore, sanitizeStoreKey } from '../../src/mcp/oauth/store';

describe('sanitizeStoreKey', () => {
  it('strips path traversal segments', () => {
    expect(sanitizeStoreKey('../../etc/passwd')).toBe('passwd');
    expect(sanitizeStoreKey('a/b/c')).toBe('c');
  });

  it('replaces unsafe characters with underscores and collapses runs', () => {
    expect(sanitizeStoreKey('My Server!Name')).toBe('My_Server_Name');
  });

  it('rejects names that collapse to empty', () => {
    expect(() => sanitizeStoreKey('')).toThrow(/Invalid/);
  });

  it('rewrites a leading dot into a safe underscore-prefixed name', () => {
    expect(sanitizeStoreKey('.dot')).toBe('_dot');
  });
});

describe('JsonFileStore', () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'kimi-mcp-oauth-store-'));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('round-trips JSON data via the named file', () => {
    const store = new JsonFileStore(dir);
    store.write('foo.json', { hello: 'world' });
    expect(store.read('foo.json')).toEqual({ hello: 'world' });
  });

  it('returns undefined when a file is missing or unreadable JSON', () => {
    const store = new JsonFileStore(dir);
    expect(store.read('missing.json')).toBeUndefined();
  });

  it('writes files with 0600 permissions on POSIX', async () => {
    if (process.platform === 'win32') return; // file modes unreliable on Windows
    const store = new JsonFileStore(dir);
    store.write('secret.json', { token: 'abc' });
    const info = await stat(join(dir, 'secret.json'));
    expect(info.mode & 0o777).toBe(0o600);
  });

  it('removes existing files without throwing on already-missing files', () => {
    const store = new JsonFileStore(dir);
    store.write('keep.json', { a: 1 });
    expect(store.read('keep.json')).toEqual({ a: 1 });
    store.remove('keep.json');
    expect(store.read('keep.json')).toBeUndefined();
    store.remove('keep.json'); // no throw
  });
});

describe('MCP OAuth credential identity', () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'kimi-mcp-oauth-identity-'));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('isolates tokens for the same server name on different URLs', () => {
    const store = new JsonFileStore(dir);
    const first = new McpOAuthClientProvider({
      serverName: 'linear',
      serverUrl: 'https://first.example.com/mcp',
      store,
    });
    const second = new McpOAuthClientProvider({
      serverName: 'linear',
      serverUrl: 'https://second.example.com/mcp',
      store,
    });

    first.saveTokens(token('first-token'));
    second.saveTokens(token('second-token'));

    expect(first.storeKey).not.toBe(second.storeKey);
    expect(first.tokens()?.access_token).toBe('first-token');
    expect(second.tokens()?.access_token).toBe('second-token');
  });

  it('isolates tokens when distinct server names sanitize to the same prefix', () => {
    const store = new JsonFileStore(dir);
    const first = new McpOAuthClientProvider({
      serverName: 'team mcp',
      serverUrl: 'https://same.example.com/mcp',
      store,
    });
    const second = new McpOAuthClientProvider({
      serverName: 'team!mcp',
      serverUrl: 'https://same.example.com/mcp',
      store,
    });

    first.saveTokens(token('space-token'));
    second.saveTokens(token('bang-token'));

    expect(first.storeKey).not.toBe(second.storeKey);
    expect(first.tokens()?.access_token).toBe('space-token');
    expect(second.tokens()?.access_token).toBe('bang-token');
  });

  it('scopes hasTokens to the server URL, not just the configured name', () => {
    const service = new McpOAuthService({ store: new JsonFileStore(dir) });
    service
      .getProvider('linear', 'https://first.example.com/mcp')
      .saveTokens(token('first-token'));

    expect(service.hasTokens('linear', 'https://first.example.com/mcp')).toBe(true);
    expect(service.hasTokens('linear', 'https://second.example.com/mcp')).toBe(false);
  });

  it('removes stored credentials when a server authorization is reset', () => {
    const service = new McpOAuthService({ store: new JsonFileStore(dir) });
    service
      .getProvider('linear', 'https://mcp.example.com/mcp')
      .saveTokens(token('access-token'));

    service.invalidate('linear', 'https://mcp.example.com/mcp');

    expect(service.hasTokens('linear', 'https://mcp.example.com/mcp')).toBe(false);
  });

  it('uses stored client redirect URI when no active OAuth callback is running', () => {
    const provider = new McpOAuthClientProvider({
      serverName: 'notion',
      serverUrl: 'https://mcp.notion.com/mcp',
      store: new JsonFileStore(dir),
    });
    provider.saveClientInformation({
      client_id: 'cached-client',
      redirect_uris: ['http://127.0.0.1:45678/callback'],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
    });

    expect(provider.redirectUrl).toBe('http://127.0.0.1:45678/callback');
    expect(provider.clientMetadata.redirect_uris).toEqual(['http://127.0.0.1:45678/callback']);
  });
});

describe('McpOAuthServerController', () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'kimi-mcp-oauth-controller-'));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('begins authorization for the normalized server identity', async () => {
    const calls: Array<{ serverName: string; serverUrl: string }> = [];
    const controller = new McpOAuthServerController({
      service: fakeOAuthService(async (serverName, serverUrl) => {
        calls.push({ serverName, serverUrl: serverUrl.toString() });
        return oauthFlow();
      }),
      createFlowId: () => 'flow_test',
    });

    await expect(
      controller.begin({
        serverName: '  docs  ',
        serverUrl: ' HTTPS://MCP.EXAMPLE.TEST:443/mcp ',
      }),
    ).resolves.toEqual({
      status: 'authorization-required',
      flowId: 'flow_test',
      authorizationUrl: 'https://auth.example.test/authorize',
    });
    expect(calls).toEqual([
      { serverName: 'docs', serverUrl: 'https://mcp.example.test/mcp' },
    ]);
  });

  it('reports an already-authorized result without registering a flow', async () => {
    const controller = new McpOAuthServerController({
      service: fakeOAuthService(async () => {
        throw new AlreadyAuthorizedError('docs');
      }),
    });

    await expect(
      controller.begin({ serverName: 'docs', serverUrl: 'https://mcp.example.test/mcp' }),
    ).resolves.toEqual({ status: 'already-authorized' });
  });

  it('completes a registered flow once with the default timeout', async () => {
    const completionOptions: Array<{
      readonly signal?: AbortSignal;
      readonly timeoutMs?: number;
    }> = [];
    const controller = new McpOAuthServerController({
      service: fakeOAuthService(async () =>
        oauthFlow({
          complete: async (options) => {
            completionOptions.push(options ?? {});
          },
        }),
      ),
      createFlowId: () => 'flow_test',
    });
    const started = await controller.begin({
      serverName: 'docs',
      serverUrl: 'https://mcp.example.test/mcp',
    });
    expect(started.status).toBe('authorization-required');

    await controller.complete({ flowId: 'flow_test' });

    expect(completionOptions).toEqual([{ signal: undefined, timeoutMs: 15 * 60 * 1000 }]);
    await expect(controller.complete({ flowId: 'flow_test' })).rejects.toMatchObject({
      code: 'request.invalid',
    });
  });

  it('cancels a registered flow and treats repeated cancellation as a no-op', async () => {
    let cancelCount = 0;
    const controller = new McpOAuthServerController({
      service: fakeOAuthService(async () =>
        oauthFlow({
          cancel: async () => {
            cancelCount += 1;
          },
        }),
      ),
      createFlowId: () => 'flow_test',
    });
    await controller.begin({
      serverName: 'docs',
      serverUrl: 'https://mcp.example.test/mcp',
    });

    await controller.cancel({ flowId: 'flow_test' });
    await controller.cancel({ flowId: 'flow_test' });

    expect(cancelCount).toBe(1);
  });

  it('reads authorization status for the exact server name and URL', async () => {
    const service = new McpOAuthService({ store: new JsonFileStore(dir) });
    const controller = new McpOAuthServerController({ service });
    service
      .getProvider('docs', 'https://first.example.test/mcp')
      .saveTokens(token('first-token'));

    await expect(
      controller.status({
        serverName: 'docs',
        serverUrl: 'https://first.example.test/mcp',
      }),
    ).resolves.toEqual({ authStatus: 'oauth-authorized' });
    await expect(
      controller.status({
        serverName: 'docs',
        serverUrl: 'https://second.example.test/mcp',
      }),
    ).resolves.toEqual({ authStatus: 'oauth-required' });
  });

  it('keeps status local when network verification is not requested', async () => {
    const service = new McpOAuthService({ store: new JsonFileStore(dir) });
    service
      .getProvider('docs', 'https://mcp.example.test/mcp')
      .saveTokens(token('access-token'));
    const controller = new McpOAuthServerController({
      service,
      verifyStatusWithNetwork: () => {
        throw new Error('network verification must not run');
      },
    });

    await expect(
      controller.status({
        serverName: 'docs',
        serverUrl: 'https://mcp.example.test/mcp',
      }),
    ).resolves.toEqual({ authStatus: 'oauth-authorized' });
  });

  it('returns the network verification result when requested', async () => {
    const service = new McpOAuthService({ store: new JsonFileStore(dir) });
    service
      .getProvider('docs', 'https://mcp.example.test/mcp')
      .saveTokens(token('access-token'));
    const controller = new McpOAuthServerController({
      service,
      verifyStatusWithNetwork: () => 'oauth-required',
    });

    await expect(
      controller.status({
        serverName: 'docs',
        serverUrl: 'https://mcp.example.test/mcp',
        verifyWithNetwork: true,
      }),
    ).resolves.toEqual({ authStatus: 'oauth-required' });
  });

  it('does not contact the network when no stored token exists', async () => {
    const controller = new McpOAuthServerController({
      service: fakeOAuthService(async () => oauthFlow()),
      verifyStatusWithNetwork: () => {
        throw new Error('network verification must not run');
      },
    });

    await expect(
      controller.status({
        serverName: 'docs',
        serverUrl: 'https://mcp.example.test/mcp',
        verifyWithNetwork: true,
      }),
    ).resolves.toEqual({ authStatus: 'oauth-required' });
  });

  it('resets only the credentials for the exact server name and URL', async () => {
    const firstUrl = 'https://first.example.test/mcp';
    const secondUrl = 'https://second.example.test/mcp';
    const service = new McpOAuthService({ store: new JsonFileStore(dir) });
    const controller = new McpOAuthServerController({ service });
    service.getProvider('docs', firstUrl).saveTokens(token('reset-token'));
    service.getProvider('docs', secondUrl).saveTokens(token('same-name-token'));
    service.getProvider('other', firstUrl).saveTokens(token('same-url-token'));

    await controller.reset({ serverName: 'docs', serverUrl: firstUrl });

    expect(service.hasTokens('docs', firstUrl)).toBe(false);
    expect(service.hasTokens('docs', secondUrl)).toBe(true);
    expect(service.hasTokens('other', firstUrl)).toBe(true);
  });

  it.each([
    [{ serverName: '   ', serverUrl: 'https://mcp.example.test' }, 'serverName'],
    [{ serverName: 'docs', serverUrl: 'relative/path' }, 'serverUrl'],
    [{ serverName: 'docs', serverUrl: 'ftp://mcp.example.test' }, 'serverUrl'],
    [{ serverName: 'docs', serverUrl: 'https://user@mcp.example.test' }, 'serverUrl'],
    [{ serverName: 'docs', serverUrl: 'https://mcp.example.test/#fragment' }, 'serverUrl'],
  ])('rejects an invalid server identity (%s)', async (input, field) => {
    const controller = new McpOAuthServerController({
      service: fakeOAuthService(async () => oauthFlow()),
    });

    await expect(controller.status(input)).rejects.toMatchObject({
      code: 'request.invalid',
      message: expect.stringContaining(field),
    });
  });
});

describe('MCP OAuth network status classification', () => {
  it('reports authorization when the MCP connection succeeds', () => {
    expect(
      mcpOAuthServerAuthStatusFromProbe('docs', {
        status: 'connected',
      }),
    ).toBe('oauth-authorized');
  });

  it('reports reauthentication when the MCP server rejects authorization', () => {
    expect(
      mcpOAuthServerAuthStatusFromProbe('docs', {
        status: 'needs-auth',
      }),
    ).toBe('oauth-required');
  });

  it('preserves connection failures instead of reporting reauthentication', () => {
    expect(() =>
      mcpOAuthServerAuthStatusFromProbe('docs', {
        status: 'failed',
        error: 'connection refused',
      }),
    ).toThrow(expect.objectContaining({ code: 'mcp.startup_failed' }));
  });
});

function token(accessToken: string): OAuthTokens {
  return {
    access_token: accessToken,
    token_type: 'Bearer',
  };
}

function fakeOAuthService(
  beginAuthorization: McpOAuthServerService['beginAuthorization'],
): McpOAuthServerService {
  return {
    beginAuthorization,
    hasTokens: () => false,
    invalidate: () => undefined,
  };
}

function oauthFlow(
  overrides: Partial<BeginAuthorizationResult> = {},
): BeginAuthorizationResult {
  return {
    authorizationUrl: new URL('https://auth.example.test/authorize'),
    complete: async () => undefined,
    cancel: async () => undefined,
    ...overrides,
  };
}

describe('McpOAuthClientProvider.invalidateStaleRegistration', () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'kimi-mcp-oauth-stale-'));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  function makeProvider() {
    return new McpOAuthClientProvider({
      serverName: 'srv',
      serverUrl: 'https://mcp.example.com/mcp',
      store: new JsonFileStore(dir),
    });
  }

  it('drops a registration whose redirect_uris miss the current callback', () => {
    const provider = makeProvider();
    provider.saveClientInformation({
      client_id: 'c1',
      redirect_uris: ['http://127.0.0.1:11111/callback'],
    });
    expect(provider.invalidateStaleRegistration('http://127.0.0.1:22222/callback')).toBe(true);
    expect(provider.clientInformation()).toBeUndefined();
  });

  it('keeps a registration that still covers the callback URI', () => {
    const provider = makeProvider();
    provider.saveClientInformation({
      client_id: 'c1',
      redirect_uris: ['http://127.0.0.1:11111/callback'],
    });
    expect(provider.invalidateStaleRegistration('http://127.0.0.1:11111/callback')).toBe(false);
    expect(provider.clientInformation()).toMatchObject({ client_id: 'c1' });
  });

  it('is a no-op without a stored registration', () => {
    const provider = makeProvider();
    expect(provider.invalidateStaleRegistration('http://127.0.0.1:11111/callback')).toBe(false);
  });
});

import type {
  AuthConfig,
  AuthorizeOptions,
  StorageAdapter,
  HttpClient,
  HttpRequestConfig,
  TokenResponse,
  CallbackResult,
  IDTokenClaims,
  ConnectionsResponse,
  CreateChallengeRequest,
  CreateChallengeResponse,
  VerifyChallengeRequest,
  VerifyChallengeResponse,
  LoginRequest,
  PKCEParams,
  AuthEventType,
  AuthEventListener,
} from '@/types';
import { EventBus } from '@core/event-bus';
import { TokenManager } from '@core/token-manager';
import { OAuthFlow } from '@core/oauth-flow';
import { API } from '@core/api';
import { BrowserStorageAdapter } from '@core/storage';

export class Auth {
  private events: EventBus;
  private tokens: TokenManager;
  private flow: OAuthFlow;
  private api: API;

  constructor(config: AuthConfig) {
    const storage = config.storage ?? defaultStorage();
    const http = config.httpClient ?? defaultHttpClient();

    this.events = new EventBus();

    this.tokens = new TokenManager({
      storage,
      events: this.events,
      http,
      endpoint: config.endpoint,
      clientId: config.clientId,
    });

    this.flow = new OAuthFlow({
      endpoint: config.endpoint,
      clientId: config.clientId,
      redirectUri: config.redirectUri,
      storage,
      http,
      tokens: this.tokens,
      events: this.events,
    });

    this.api = new API(http, config.endpoint);
  }

  // ==================== OAuth Flow ====================

  async authorize(
    options: AuthorizeOptions
  ): Promise<{ url: string; pkce: PKCEParams; state: string }> {
    return this.flow.authorize(options);
  }

  async handleCallback(code: string, state?: string): Promise<CallbackResult> {
    return this.flow.handleCallback(code, state);
  }

  // ==================== Token ====================

  async getAccessToken(audience?: string): Promise<string | null> {
    return this.tokens.getAccessToken(audience);
  }

  async isAuthenticated(audience?: string): Promise<boolean> {
    return this.tokens.isAuthenticated(audience);
  }

  async refreshToken(refreshToken?: string, audience?: string): Promise<TokenResponse> {
    return this.tokens.refreshToken(refreshToken, audience);
  }

  // ==================== User ====================

  async getUser(): Promise<IDTokenClaims | null> {
    return this.tokens.getUser();
  }

  async saveReturnTo(path: string): Promise<void> {
    return this.flow.saveReturnTo(path);
  }

  // ==================== Session ====================

  async logout(): Promise<void> {
    await this.tokens.purgeAll();
    this.tokens.invalidateKeys();
    this.events.emit('logout');
  }

  // ==================== Challenge / Login ====================

  async getConnections(): Promise<ConnectionsResponse> {
    return this.api.getConnections();
  }

  async createChallenge(req: CreateChallengeRequest): Promise<CreateChallengeResponse> {
    return this.api.createChallenge(req);
  }

  async verifyChallenge(challengeId: string, req: VerifyChallengeRequest): Promise<VerifyChallengeResponse> {
    return this.api.verifyChallenge(challengeId, req);
  }

  async login(req: LoginRequest): Promise<void> {
    return this.api.login(req);
  }

  // ==================== Events ====================

  on(event: AuthEventType, listener: AuthEventListener): () => void {
    return this.events.on(event, listener);
  }

  off(event: AuthEventType, listener: AuthEventListener): void {
    this.events.off(event, listener);
  }
}

function defaultStorage(): StorageAdapter {
  if (typeof window !== 'undefined' && window.localStorage) return new BrowserStorageAdapter();
  throw new Error('No default storage available. Provide a custom StorageAdapter.');
}

function defaultHttpClient(): HttpClient {
  return {
    async request<T = unknown>(config: HttpRequestConfig) {
      const response = await fetch(config.url, {
        method: config.method,
        headers: config.headers,
        body: config.body,
        credentials: 'omit',
      });
      const text = await response.text();
      let data: unknown;
      let rawText: string | undefined;
      try {
        data = JSON.parse(text);
      } catch {
        data = {};
        rawText = text.slice(0, 500);
      }
      return { status: response.status, data: data as T, rawText };
    },
  };
}

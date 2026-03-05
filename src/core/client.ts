/**
 * Aegis Auth 核心类
 */

import type {
  AuthConfig,
  AuthorizeOptions,
  AudienceScope,
  StorageAdapter,
  HttpClient,
  TokenResponse,
  MultiAudienceTokenResponse,
  AuthEvent,
  AuthEventListener,
  AuthEventType,
  PKCEParams,
  IDTokenClaims,
  ConnectionsResponse,
  CreateChallengeRequest,
  CreateChallengeResponse,
  VerifyChallengeRequest,
  VerifyChallengeResponse,
  LoginRequest,
} from '@/types';
import { AuthError, ErrorCodes } from '@/types';
import { TokenStorage, FlowState, BrowserStorageAdapter, StorageKeys } from '@utils/storage';
import { generatePKCE } from '@utils/pkce';
import { verify as verifyToken, invalidateKeys } from '@utils/paseto';

export class Auth {
  private config: AuthConfig;
  private storage: StorageAdapter;
  private tokens: TokenStorage;
  private flow: FlowState;
  private http: HttpClient;
  private listeners: Map<AuthEventType, Set<AuthEventListener>> = new Map();
  private pendingAudience: string | null = null;
  private pendingRedirectUri: string | null = null;
  private pendingAudiences: Record<string, AudienceScope> | null = null;

  constructor(config: AuthConfig) {
    this.config = config;
    this.storage = config.storage ?? this.defaultStorage();
    this.tokens = new TokenStorage(this.storage);
    this.flow = new FlowState(this.storage);
    this.http = config.httpClient ?? this.defaultHttpClient();
  }

  // ==================== 公开 API ====================

  async authorize(
    options: AuthorizeOptions
  ): Promise<{ url: string; pkce: PKCEParams; state: string }> {
    const { scopes, state: customState, redirectUri } = options;
    const audiences = options.audiences ?? null;
    const audience = audiences ? null : (options.audience ?? null);

    this.pendingAudience = audience;
    this.pendingRedirectUri = redirectUri ?? this.config.redirectUri ?? null;
    this.pendingAudiences = audiences;

    const pkce = await generatePKCE();
    const state = customState ?? this.nonce();

    await this.flow.stashCodeVerifier(pkce.codeVerifier);
    await this.flow.stashState(state);
    if (audience) {
      await this.flow.stashAudience(audience);
    }
    if (this.pendingRedirectUri) {
      await this.flow.stashRedirectUri(this.pendingRedirectUri);
    }
    if (audiences) {
      await this.flow.stashAudiences(audiences);
    }

    const url = this.buildAuthorizeUrl(pkce, state, scopes, this.pendingRedirectUri, audience, audiences);
    return { url, pkce, state };
  }

  async handleCallback(code: string, state?: string): Promise<TokenResponse> {
    const savedState = this.flow.popState();
    if (state && savedState && state !== savedState) {
      throw new AuthError(ErrorCodes.INVALID_REQUEST, 'State mismatch');
    }

    const codeVerifier = this.flow.popCodeVerifier();
    if (!codeVerifier) {
      throw new AuthError(ErrorCodes.INVALID_REQUEST, 'Code verifier not found');
    }

    const redirectUri = this.flow.popRedirectUri();
    const storedAudiences = this.flow.popAudiences() as Record<string, AudienceScope> | null;
    const multiAudience =
      (this.pendingAudiences && Object.keys(this.pendingAudiences).length > 0) ||
      (storedAudiences && Object.keys(storedAudiences).length > 0);

    return multiAudience
      ? this.redeemMultiAudience(code, codeVerifier, redirectUri)
      : this.redeemCode(code, codeVerifier, redirectUri);
  }

  async getAccessToken(audience?: string): Promise<string | null> {
    if (audience) return this.resolveToken(audience);

    const store = await this.tokens.load();
    if (!store.accessToken) return null;

    if (await this.tokens.expired()) {
      if (store.refreshToken) {
        try {
          return (await this.refreshToken(store.refreshToken)).access_token;
        } catch {
          this.emit('token_expired');
          await this.tokens.purge();
          return null;
        }
      }
      this.emit('token_expired');
      await this.tokens.purge();
      return null;
    }

    return store.accessToken;
  }

  audiences(): string[] {
    return this.tokens.audiences();
  }

  async isAuthenticated(): Promise<boolean> {
    const store = await this.tokens.load();
    if (!store.accessToken) return false;

    if (await this.tokens.expired(60_000)) {
      return !!store.refreshToken;
    }
    return true;
  }

  // ---- User ----

  async getUser(): Promise<IDTokenClaims | null> {
    const raw = await Promise.resolve(this.storage.getItem(StorageKeys.ID_TOKEN));
    if (!raw) return null;
    try {
      const claims: IDTokenClaims = JSON.parse(raw);
      if (new Date(claims.exp) <= new Date()) {
        await Promise.resolve(this.storage.removeItem(StorageKeys.ID_TOKEN));
        return null;
      }
      return claims;
    } catch {
      return null;
    }
  }

  // ---- ReturnTo ----

  async saveReturnTo(path: string): Promise<void> {
    await this.flow.stashReturnTo(path);
  }

  consumeReturnTo(): string | null {
    return this.flow.popReturnTo();
  }

  // ---- Session ----

  async refreshToken(refreshToken?: string, audience?: string): Promise<TokenResponse> {
    let rt: string | null | undefined = refreshToken;

    if (!rt) {
      const store = audience
        ? await this.tokens.loadScoped(audience)
        : await this.tokens.load();
      rt = store.refreshToken;
    }

    if (!rt) {
      throw new AuthError(ErrorCodes.NOT_AUTHENTICATED, 'No refresh token available');
    }

    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: rt,
      client_id: this.config.clientId,
    });

    const res = await this.http.request<TokenResponse>({
      method: 'POST',
      url: `${this.config.endpoint}/api/token`,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    if (res.status !== 200) {
      throw new AuthError(ErrorCodes.INVALID_GRANT, 'Token refresh failed');
    }

    if (audience) {
      await this.tokens.persistScoped(audience, res.data.access_token, res.data.refresh_token ?? null);
    } else {
      await this.tokens.persist(res.data.access_token, res.data.refresh_token ?? null);
    }

    this.emit('token_refreshed', res.data);
    return res.data;
  }

  async logout(): Promise<void> {
    const token = await this.getAccessToken();
    if (token) {
      try {
        await this.http.request({
          method: 'POST',
          url: `${this.config.endpoint}/api/logout`,
          headers: { Authorization: `Bearer ${token}` },
        });
      } catch {
        // logout API failed, still clear local state
      }
    }

    await this.tokens.purgeAll();
    await Promise.resolve(this.storage.removeItem(StorageKeys.ID_TOKEN));
    invalidateKeys();
    this.emit('logout');
  }

  // ---- Challenge / Login ----

  async getConnections(): Promise<ConnectionsResponse> {
    const res = await this.http.request<ConnectionsResponse>({
      method: 'GET',
      url: `${this.config.endpoint}/api/connections`,
      headers: { 'Content-Type': 'application/json' },
    });
    if (res.status !== 200) throw new AuthError(ErrorCodes.SERVER_ERROR, 'Failed to get connections');
    return res.data;
  }

  async createChallenge(req: CreateChallengeRequest): Promise<CreateChallengeResponse> {
    const res = await this.http.request<CreateChallengeResponse>({
      method: 'POST',
      url: `${this.config.endpoint}/api/challenge`,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req),
    });
    if (res.status !== 200) {
      const err = res.data as unknown as { error?: string; error_description?: string };
      throw new AuthError(err?.error ?? ErrorCodes.SERVER_ERROR, err?.error_description ?? 'Failed to create challenge');
    }
    return res.data;
  }

  async verifyChallenge(challengeId: string, req: VerifyChallengeRequest): Promise<VerifyChallengeResponse> {
    const res = await this.http.request<VerifyChallengeResponse>({
      method: 'PUT',
      url: `${this.config.endpoint}/api/challenge?challenge_id=${encodeURIComponent(challengeId)}`,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req),
    });
    if (res.status !== 200) {
      const err = res.data as unknown as { error?: string; error_description?: string };
      throw new AuthError(err?.error ?? ErrorCodes.SERVER_ERROR, err?.error_description ?? 'Failed to verify challenge');
    }
    return res.data;
  }

  async login(req: LoginRequest): Promise<void> {
    const res = await this.http.request({
      method: 'POST',
      url: `${this.config.endpoint}/api/login`,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req),
    });
    if (res.status !== 200) {
      const err = res.data as unknown as { error?: string; error_description?: string };
      throw new AuthError(err?.error ?? ErrorCodes.ACCESS_DENIED, err?.error_description ?? 'Login failed');
    }
  }

  // ---- Events ----

  on(event: AuthEventType, listener: AuthEventListener): () => void {
    if (!this.listeners.has(event)) this.listeners.set(event, new Set());
    this.listeners.get(event)!.add(listener);
    return () => this.off(event, listener);
  }

  off(event: AuthEventType, listener: AuthEventListener): void {
    this.listeners.get(event)?.delete(listener);
  }

  // ==================== Internals ====================

  // --- Token Exchange ---

  private async redeemCode(code: string, verifier: string, redirectUri: string | null): Promise<TokenResponse> {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: this.config.clientId,
      code_verifier: verifier,
    });
    if (redirectUri) body.set('redirect_uri', redirectUri);

    const { data } = await this.post<TokenResponse>(
      '/api/token', body.toString(), 'application/x-www-form-urlencoded',
    );

    await this.tokens.persist(data.access_token, data.refresh_token ?? null);
    await this.settle(data);
    return data;
  }

  private async redeemMultiAudience(code: string, verifier: string, redirectUri: string | null): Promise<TokenResponse> {
    const payload: Record<string, unknown> = {
      grant_type: 'authorization_code',
      code,
      client_id: this.config.clientId,
      code_verifier: verifier,
    };
    if (redirectUri) payload.redirect_uri = redirectUri;

    const { data } = await this.post<MultiAudienceTokenResponse>(
      '/api/token', JSON.stringify(payload), 'application/json',
    );

    const entries = Object.entries(data);
    if (entries.length === 0) {
      throw new AuthError(ErrorCodes.INVALID_GRANT, 'Empty token response');
    }

    await this.tokens.registerAudiences(entries.map(([aud]) => aud));

    const [, primary] = entries[0];
    await this.tokens.persist(primary.access_token, primary.refresh_token ?? null);

    for (const [aud, resp] of entries) {
      await this.tokens.persistScoped(aud, resp.access_token, resp.refresh_token ?? null);
    }

    await this.settle(primary);
    return primary;
  }

  // --- Token Resolution ---

  private async resolveToken(audience: string): Promise<string | null> {
    const store = await this.tokens.loadScoped(audience);
    if (!store.accessToken) return null;

    if (await this.tokens.expiredScoped(audience)) {
      if (store.refreshToken) {
        try {
          return (await this.refreshToken(store.refreshToken, audience)).access_token;
        } catch {
          await this.tokens.purgeScoped(audience);
          return null;
        }
      }
      await this.tokens.purgeScoped(audience);
      return null;
    }

    return store.accessToken;
  }

  private async requireToken(audience?: string): Promise<string> {
    const token = await this.getAccessToken(audience);
    if (!token) {
      throw new AuthError(
        ErrorCodes.NOT_AUTHENTICATED,
        audience ? `Not authenticated for ${audience}` : 'Not authenticated',
      );
    }
    return token;
  }

  // --- Settle & Cleanup ---

  private async settle(resp: TokenResponse): Promise<void> {
    if (resp.id_token) {
      try {
        const claims = await verifyToken(resp.id_token, this.config.endpoint, this.config.clientId, this.http);
        await Promise.resolve(this.storage.setItem(StorageKeys.ID_TOKEN, JSON.stringify(claims)));
      } catch {
        // id_token 验签失败不阻塞登录，用户信息不可用但 access_token 仍有效
      }
    }
    this.resetFlow();
    this.emit('login', resp);
  }

  private resetFlow(): void {
    this.flow.popAudience();
    this.pendingAudience = null;
    this.pendingRedirectUri = null;
    this.pendingAudiences = null;
  }

  // --- HTTP ---

  private async post<T>(path: string, body: string, contentType: string): Promise<{ data: T }> {
    const res = await this.http.request<T>({
      method: 'POST',
      url: `${this.config.endpoint}${path}`,
      headers: { 'Content-Type': contentType },
      body,
    });
    if (res.status !== 200) {
      const err = res.data as unknown as { error?: string; error_description?: string };
      throw new AuthError(err?.error ?? ErrorCodes.INVALID_GRANT, err?.error_description ?? `POST ${path} failed`);
    }
    return res;
  }

  // --- Events ---

  private emit(type: AuthEventType, data?: unknown): void {
    const event: AuthEvent = { type, data };
    this.listeners.get(type)?.forEach((fn) => fn(event));
  }

  // --- URL & Crypto ---

  private buildAuthorizeUrl(
    pkce: PKCEParams, state: string, scopes: string[],
    redirectUri?: string | null, audience?: string | null,
    audiences?: Record<string, AudienceScope> | null,
  ): string {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      code_challenge: pkce.codeChallenge,
      code_challenge_method: pkce.codeChallengeMethod,
      state,
      scope: scopes.join(' '),
    });
    if (audience) params.set('audience', audience);
    if (audiences) params.set('audiences', JSON.stringify(audiences));
    if (redirectUri) params.set('redirect_uri', redirectUri);
    return `${this.config.endpoint}/authorize?${params}`;
  }

  private nonce(): string {
    const buf = new Uint8Array(16);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(buf);
    } else {
      for (let i = 0; i < 16; i++) buf[i] = Math.floor(Math.random() * 256);
    }
    return Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join('');
  }

  // --- Defaults ---

  private defaultStorage(): StorageAdapter {
    if (typeof window !== 'undefined' && window.localStorage) return new BrowserStorageAdapter();
    throw new Error('No default storage available. Provide a custom StorageAdapter.');
  }

  private defaultHttpClient(): HttpClient {
    return {
      async request(config) {
        const response = await fetch(config.url, {
          method: config.method,
          headers: config.headers,
          body: config.body,
          credentials: 'omit',
        });
        const text = await response.text();
        let data;
        try { data = JSON.parse(text); } catch { data = {}; }
        return { status: response.status, data };
      },
    };
  }
}

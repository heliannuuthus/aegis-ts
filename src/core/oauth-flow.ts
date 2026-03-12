import type {
  StorageAdapter,
  HttpClient,
  AuthorizeOptions,
  AudienceScope,
  TokenResponse,
  CallbackResult,
  MultiAudienceTokenResponse,
  PKCEParams,
} from '@/types';
import { AuthError, ErrorCodes } from '@/types';
import { generatePKCE } from '@utils/pkce';
import { TokenManager, extractAudience } from '@core/token-manager';
import { EventBus } from '@core/event-bus';

function metaKeys(clientId: string) {
  return {
    CODE_VERIFIER: `###aegis@${clientId}@pkce-verifier###`,
    STATE: `###aegis@${clientId}@state###`,
    REDIRECT_URI: `###aegis@${clientId}@redirect-uri###`,
    RETURN_TO: `###aegis@${clientId}@return-to###`,
  } as const;
}

type MetaKeys = ReturnType<typeof metaKeys>;

export interface OAuthFlowConfig {
  endpoint: string;
  clientId: string;
  redirectUri?: string;
  storage: StorageAdapter;
  http: HttpClient;
  tokens: TokenManager;
  events: EventBus;
}

export class OAuthFlow {
  private endpoint: string;
  private clientId: string;
  private redirectUri: string | undefined;
  private s: StorageAdapter;
  private http: HttpClient;
  private tokens: TokenManager;
  private events: EventBus;
  private keys: MetaKeys;

  constructor(config: OAuthFlowConfig) {
    this.endpoint = config.endpoint;
    this.clientId = config.clientId;
    this.redirectUri = config.redirectUri;
    this.s = config.storage;
    this.http = config.http;
    this.tokens = config.tokens;
    this.events = config.events;
    this.keys = metaKeys(config.clientId);
  }

  async authorize(
    options: AuthorizeOptions
  ): Promise<{ url: string; pkce: PKCEParams; state: string }> {
    const { scopes, state: customState, redirectUri } = options;
    const audiences = options.audiences ?? null;
    const audience = audiences ? null : (options.audience ?? null);
    const effectiveRedirectUri = redirectUri ?? this.redirectUri ?? null;

    const pkce = await generatePKCE();
    const state = customState ?? this.nonce();

    await this.s.setItem(this.keys.CODE_VERIFIER, pkce.codeVerifier);
    await this.s.setItem(this.keys.STATE, state);
    if (effectiveRedirectUri) await this.s.setItem(this.keys.REDIRECT_URI, effectiveRedirectUri);

    const url = this.buildUrl(pkce, state, scopes, effectiveRedirectUri, audience, audiences);
    return { url, pkce, state };
  }

  async handleCallback(code: string, state?: string): Promise<CallbackResult> {
    try {
      const savedState = await this.pop(this.keys.STATE);
      if (state && savedState && state !== savedState) {
        throw new AuthError(ErrorCodes.INVALID_REQUEST, 'State mismatch');
      }

      const codeVerifier = await this.pop(this.keys.CODE_VERIFIER);
      if (!codeVerifier) {
        throw new AuthError(ErrorCodes.INVALID_REQUEST, 'Code verifier not found');
      }

      const redirectUri = await this.pop(this.keys.REDIRECT_URI);

      const tokens = await this.redeemCode(code, codeVerifier, redirectUri);

      const returnTo = await this.pop(this.keys.RETURN_TO);
      return { ...tokens, returnTo: returnTo ?? null };
    } catch (e) {
      await this.s.removeItem(this.keys.RETURN_TO);
      throw e;
    } finally {
      await this.purgeFlow();
    }
  }

  private async purgeFlow(): Promise<void> {
    await Promise.all([
      this.s.removeItem(this.keys.STATE),
      this.s.removeItem(this.keys.CODE_VERIFIER),
      this.s.removeItem(this.keys.REDIRECT_URI),
    ]);
  }

  async saveReturnTo(path: string): Promise<void> {
    await this.s.setItem(this.keys.RETURN_TO, path);
  }

  // ==================== Internals ====================

  /** authorization_code 统一用 form，按响应结构解析：扁平或 keyed；单 audience 时从 access_token 解析 aud */
  private async redeemCode(
    code: string, verifier: string, redirectUri: string | null,
  ): Promise<TokenResponse> {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: this.clientId,
      code_verifier: verifier,
    });
    if (redirectUri) body.set('redirect_uri', redirectUri);

    const { data } = await this.post<TokenResponse | MultiAudienceTokenResponse>(
      '/api/token', body.toString(), 'application/x-www-form-urlencoded',
    );

    if (this.isKeyedResponse(data)) {
      const entries = Object.entries(data);
      if (entries.length === 0) {
        throw new AuthError(ErrorCodes.INVALID_GRANT, 'Empty token response');
      }
      for (const [aud, resp] of entries) {
        await this.tokens.persistScoped(aud, resp.access_token, resp.refresh_token ?? null);
      }
      const [, primary] = entries[0];
      await this.settle(primary);
      return primary;
    }

    const aud = extractAudience(data.access_token) ?? this.clientId;
    await this.tokens.persistScoped(aud, data.access_token, data.refresh_token ?? null);
    await this.settle(data);
    return data;
  }

  private isKeyedResponse(data: TokenResponse | MultiAudienceTokenResponse): data is MultiAudienceTokenResponse {
    return typeof data === 'object' && data !== null && !('access_token' in data);
  }

  private async settle(resp: TokenResponse): Promise<void> {
    if (resp.id_token) {
      console.log('[aegis] settle: id_token received, persisting claims');
      await this.tokens.settleIdToken(resp.id_token);
    } else {
      console.log('[aegis] settle: no id_token in token response (scope may not include openid)');
    }
    this.events.emit('login', resp);
  }

  private async post<T>(path: string, body: string, contentType: string): Promise<{ data: T }> {
    const res = await this.http.request<T>({
      method: 'POST',
      url: `${this.endpoint}${path}`,
      headers: { 'Content-Type': contentType },
      body,
    });
    if (res.status !== 200) {
      const err = res.data as unknown as { error?: string; error_description?: string };
      const code = err?.error ?? ErrorCodes.INVALID_GRANT;
      const desc = err?.error_description ?? (res.rawText ? `HTTP ${res.status}: ${res.rawText}` : `POST ${path} failed (${res.status})`);
      console.error('[aegis] token exchange failed:', { path, status: res.status, code, description: desc });
      throw new AuthError(code, desc, undefined, res.status);
    }
    return res;
  }

  private buildUrl(
    pkce: PKCEParams, state: string, scopes: string[],
    redirectUri?: string | null, audience?: string | null,
    audiences?: Record<string, AudienceScope> | null,
  ): string {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.clientId,
      code_challenge: pkce.codeChallenge,
      code_challenge_method: pkce.codeChallengeMethod,
      state,
      scope: scopes.join(' '),
    });
    if (audience) params.set('audience', audience);
    if (audiences) params.set('audiences', JSON.stringify(audiences));
    if (redirectUri) params.set('redirect_uri', redirectUri);
    return `${this.endpoint}/authorize?${params}`;
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

  private async pop(key: string): Promise<string | null> {
    const v = await this.s.getItem(key);
    if (v) await this.s.removeItem(key);
    return v;
  }

  private async popJson<T>(key: string): Promise<T | null> {
    const raw = await this.pop(key);
    if (!raw) return null;
    try { return JSON.parse(raw); } catch { return null; }
  }
}

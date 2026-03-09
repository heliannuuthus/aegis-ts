import type {
  StorageAdapter,
  HttpClient,
  AuthorizeOptions,
  AudienceScope,
  TokenResponse,
  MultiAudienceTokenResponse,
  PKCEParams,
} from '@/types';
import { AuthError, ErrorCodes } from '@/types';
import { generatePKCE } from '@utils/pkce';
import { TokenManager } from '@core/token-manager';
import { EventBus } from '@core/event-bus';

function metaKeys(clientId: string) {
  return {
    CODE_VERIFIER: `###aegis@${clientId}@pkce-verifier###`,
    STATE: `###aegis@${clientId}@flow-state###`,
    AUDIENCE: `###aegis@${clientId}@flow-audience###`,
    REDIRECT_URI: `###aegis@${clientId}@flow-redirect-uri###`,
    AUDIENCES: `###aegis@${clientId}@flow-audiences###`,
    RETURN_TO: `###aegis@${clientId}@flow-return-to###`,
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
    if (audience) await this.s.setItem(this.keys.AUDIENCE, audience);
    if (effectiveRedirectUri) await this.s.setItem(this.keys.REDIRECT_URI, effectiveRedirectUri);
    if (audiences) await this.s.setItem(this.keys.AUDIENCES, JSON.stringify(audiences));

    const url = this.buildUrl(pkce, state, scopes, effectiveRedirectUri, audience, audiences);
    return { url, pkce, state };
  }

  async handleCallback(code: string, state?: string): Promise<TokenResponse> {
    const savedState = await this.pop(this.keys.STATE);
    if (state && savedState && state !== savedState) {
      throw new AuthError(ErrorCodes.INVALID_REQUEST, 'State mismatch');
    }

    const codeVerifier = await this.pop(this.keys.CODE_VERIFIER);
    if (!codeVerifier) {
      throw new AuthError(ErrorCodes.INVALID_REQUEST, 'Code verifier not found');
    }

    const redirectUri = await this.pop(this.keys.REDIRECT_URI);
    const storedAudiences = await this.popJson<Record<string, AudienceScope>>(this.keys.AUDIENCES);
    await this.pop(this.keys.AUDIENCE);

    const multiAudience = storedAudiences && Object.keys(storedAudiences).length > 0;

    return multiAudience
      ? this.redeemMultiAudience(code, codeVerifier, redirectUri)
      : this.redeemCode(code, codeVerifier, redirectUri);
  }

  async saveReturnTo(path: string): Promise<void> {
    await this.s.setItem(this.keys.RETURN_TO, path);
  }

  async consumeReturnTo(): Promise<string | null> {
    return this.pop(this.keys.RETURN_TO);
  }

  // ==================== Internals ====================

  private async redeemCode(code: string, verifier: string, redirectUri: string | null): Promise<TokenResponse> {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: this.clientId,
      code_verifier: verifier,
    });
    if (redirectUri) body.set('redirect_uri', redirectUri);

    const { data } = await this.post<TokenResponse>(
      '/api/token', body.toString(), 'application/x-www-form-urlencoded',
    );

    await this.tokens.persistScoped(this.clientId, data.access_token, data.refresh_token ?? null);
    await this.settle(data);
    return data;
  }

  private async redeemMultiAudience(code: string, verifier: string, redirectUri: string | null): Promise<TokenResponse> {
    const payload: Record<string, unknown> = {
      grant_type: 'authorization_code',
      code,
      client_id: this.clientId,
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

    for (const [aud, resp] of entries) {
      await this.tokens.persistScoped(aud, resp.access_token, resp.refresh_token ?? null);
    }

    const [, primary] = entries[0];
    await this.settle(primary);
    return primary;
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
      throw new AuthError(err?.error ?? ErrorCodes.INVALID_GRANT, err?.error_description ?? `POST ${path} failed`);
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

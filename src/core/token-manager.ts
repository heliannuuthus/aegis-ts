import { verify as pasetoVerify } from 'paseto-ts/v4';
import type {
  StorageAdapter,
  HttpClient,
  TokenResponse,
  TokenStore,
  MultiAudienceTokenStore,
  IDTokenClaims,
  PublicKeysResponse,
} from '@/types';
import { AuthError, ErrorCodes } from '@/types';
import { EventBus } from '@core/event-bus';

const Keys = {
  ACCESS_TOKEN: '###aegis@access-token###',
  REFRESH_TOKEN: '###aegis@refresh-token###',
  ID_TOKEN: '###aegis@id-token###',
  AUDIENCES: '###aegis@audiences###',
} as const;

function scopedKey(base: string, audience: string): string {
  return base.replace(/###$/, `@${audience}###`);
}

function extractExp(token: string): Date | null {
  try {
    const parts = token.split('.');
    if (parts.length < 3 || parts[0] !== 'v4' || parts[1] !== 'public') return null;
    const decoded = atob(parts[2].replace(/-/g, '+').replace(/_/g, '/'));
    if (decoded.length < 64) return null;
    const { exp } = JSON.parse(decoded.slice(0, -64));
    return exp ? new Date(exp) : null;
  } catch {
    return null;
  }
}

function toUrlSafe(b64: string): string {
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export interface TokenManagerConfig {
  storage: StorageAdapter;
  events: EventBus;
  http: HttpClient;
  endpoint: string;
  clientId: string;
}

export class TokenManager {
  private s: StorageAdapter;
  private events: EventBus;
  private http: HttpClient;
  private endpoint: string;
  private clientId: string;

  private keyCache: { keys: string[]; ts: number } | null = null;
  private readonly keyTTL = 5 * 60 * 1000;

  constructor(config: TokenManagerConfig) {
    this.s = config.storage;
    this.events = config.events;
    this.http = config.http;
    this.endpoint = config.endpoint;
    this.clientId = config.clientId;
  }

  // ==================== Access Token ====================

  async persist(accessToken: string, refreshToken: string | null): Promise<void> {
    await this.s.setItem(Keys.ACCESS_TOKEN, accessToken);
    if (refreshToken) {
      await this.s.setItem(Keys.REFRESH_TOKEN, refreshToken);
    }
  }

  async load(): Promise<TokenStore> {
    const [accessToken, refreshToken] = await Promise.all([
      this.s.getItem(Keys.ACCESS_TOKEN),
      this.s.getItem(Keys.REFRESH_TOKEN),
    ]);
    return { accessToken, refreshToken };
  }

  async purge(): Promise<void> {
    await Promise.all([
      this.s.removeItem(Keys.ACCESS_TOKEN),
      this.s.removeItem(Keys.REFRESH_TOKEN),
    ]);
  }

  async expired(bufferMs = 5 * 60 * 1000): Promise<boolean> {
    const token = await this.s.getItem(Keys.ACCESS_TOKEN);
    if (!token) return true;
    const exp = extractExp(token);
    return !exp || Date.now() + bufferMs >= exp.getTime();
  }

  // ==================== Scoped Token (per-audience) ====================

  async persistScoped(audience: string, accessToken: string, refreshToken: string | null): Promise<void> {
    await this.s.setItem(scopedKey(Keys.ACCESS_TOKEN, audience), accessToken);
    if (refreshToken) {
      await this.s.setItem(scopedKey(Keys.REFRESH_TOKEN, audience), refreshToken);
    }
  }

  async loadScoped(audience: string): Promise<TokenStore> {
    const [accessToken, refreshToken] = await Promise.all([
      this.s.getItem(scopedKey(Keys.ACCESS_TOKEN, audience)),
      this.s.getItem(scopedKey(Keys.REFRESH_TOKEN, audience)),
    ]);
    return { accessToken, refreshToken };
  }

  async expiredScoped(audience: string, bufferMs = 5 * 60 * 1000): Promise<boolean> {
    const token = await this.s.getItem(scopedKey(Keys.ACCESS_TOKEN, audience));
    if (!token) return true;
    const exp = extractExp(token);
    return !exp || Date.now() + bufferMs >= exp.getTime();
  }

  async purgeScoped(audience: string): Promise<void> {
    await Promise.all([
      this.s.removeItem(scopedKey(Keys.ACCESS_TOKEN, audience)),
      this.s.removeItem(scopedKey(Keys.REFRESH_TOKEN, audience)),
    ]);
  }

  // ==================== Audience Registry ====================

  async registerAudiences(audiences: string[]): Promise<void> {
    await this.s.setItem(Keys.AUDIENCES, JSON.stringify(audiences));
  }

  async audiences(): Promise<string[]> {
    const raw = await this.s.getItem(Keys.AUDIENCES);
    if (!raw) return [];
    try { return JSON.parse(raw); } catch { return []; }
  }

  async snapshot(): Promise<MultiAudienceTokenStore> {
    const result: MultiAudienceTokenStore = {};
    for (const aud of await this.audiences()) {
      result[aud] = await this.loadScoped(aud);
    }
    return result;
  }

  async purgeAll(): Promise<void> {
    for (const aud of await this.audiences()) {
      await this.purgeScoped(aud);
    }
    await this.s.removeItem(Keys.AUDIENCES);
    await this.purge();
    await this.s.removeItem(Keys.ID_TOKEN);
  }

  // ==================== Token Resolution ====================

  async getAccessToken(audience?: string): Promise<string | null> {
    if (audience) return this.resolveScoped(audience);

    const store = await this.load();
    if (!store.accessToken) return null;

    if (await this.expired()) {
      if (store.refreshToken) {
        try {
          return (await this.refreshToken(store.refreshToken)).access_token;
        } catch {
          this.events.emit('token_expired');
          await this.purge();
          return null;
        }
      }
      this.events.emit('token_expired');
      await this.purge();
      return null;
    }

    return store.accessToken;
  }

  async isAuthenticated(): Promise<boolean> {
    const store = await this.load();
    if (!store.accessToken) return false;
    if (await this.expired(60_000)) return !!store.refreshToken;
    return true;
  }

  async refreshToken(refreshToken?: string, audience?: string): Promise<TokenResponse> {
    let rt: string | null | undefined = refreshToken;

    if (!rt) {
      const store = audience
        ? await this.loadScoped(audience)
        : await this.load();
      rt = store.refreshToken;
    }

    if (!rt) {
      throw new AuthError(ErrorCodes.NOT_AUTHENTICATED, 'No refresh token available');
    }

    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: rt,
      client_id: this.clientId,
    });

    const res = await this.http.request<TokenResponse>({
      method: 'POST',
      url: `${this.endpoint}/api/token`,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    if (res.status !== 200) {
      throw new AuthError(ErrorCodes.INVALID_GRANT, 'Token refresh failed');
    }

    if (audience) {
      await this.persistScoped(audience, res.data.access_token, res.data.refresh_token ?? null);
    } else {
      await this.persist(res.data.access_token, res.data.refresh_token ?? null);
    }

    this.events.emit('token_refreshed', res.data);
    return res.data;
  }

  private async resolveScoped(audience: string): Promise<string | null> {
    const store = await this.loadScoped(audience);
    if (!store.accessToken) return null;

    if (await this.expiredScoped(audience)) {
      if (store.refreshToken) {
        try {
          return (await this.refreshToken(store.refreshToken, audience)).access_token;
        } catch {
          await this.purgeScoped(audience);
          return null;
        }
      }
      await this.purgeScoped(audience);
      return null;
    }

    return store.accessToken;
  }

  // ==================== ID Token ====================

  async settleIdToken(idToken: string): Promise<void> {
    try {
      const claims = await this.verifyIdToken(idToken);
      await this.s.setItem(Keys.ID_TOKEN, JSON.stringify(claims));
    } catch {
      // id_token 验签失败不阻塞登录
    }
  }

  async getUser(): Promise<IDTokenClaims | null> {
    const raw = await this.s.getItem(Keys.ID_TOKEN);
    if (!raw) return null;
    try {
      const claims: IDTokenClaims = JSON.parse(raw);
      if (new Date(claims.exp) <= new Date()) {
        await this.s.removeItem(Keys.ID_TOKEN);
        return null;
      }
      return claims;
    } catch {
      return null;
    }
  }

  invalidateKeys(): void {
    this.keyCache = null;
  }

  // ==================== PASETO Verification (private) ====================

  private async verifyIdToken(token: string): Promise<IDTokenClaims> {
    const keys = await this.resolveKeys();

    for (const key of keys) {
      try {
        const { payload } = await pasetoVerify<IDTokenClaims>(key, token, {
          validatePayload: true,
        });
        return payload;
      } catch {
        continue;
      }
    }

    throw new AuthError(ErrorCodes.INVALID_TOKEN, 'No matching key for token verification');
  }

  private async resolveKeys(): Promise<string[]> {
    if (this.keyCache && Date.now() - this.keyCache.ts < this.keyTTL) {
      return this.keyCache.keys;
    }

    const res = await this.http.request<PublicKeysResponse>({
      method: 'GET',
      url: `${this.endpoint}/pubkeys?client_id=${encodeURIComponent(this.clientId)}`,
      headers: {},
    });

    if (res.status !== 200 || !res.data?.keys) {
      throw new AuthError(ErrorCodes.SERVER_ERROR, 'Failed to fetch public keys');
    }

    const keys = res.data.keys.map((k) => `k4.public.${toUrlSafe(k.public_key)}`);
    this.keyCache = { keys, ts: Date.now() };
    return keys;
  }
}

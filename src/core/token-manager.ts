import { verify as pasetoVerify } from 'paseto-ts/v4';
import type {
  StorageAdapter,
  HttpClient,
  TokenResponse,
  TokenStore,
  IDTokenClaims,
  PublicKeysResponse,
} from '@/types';
import { AuthError, ErrorCodes } from '@/types';
import { EventBus } from '@core/event-bus';

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

  private idTokenKey: string;
  private keyCache: { keys: string[]; ts: number } | null = null;
  private readonly keyTTL = 5 * 60 * 1000;

  constructor(config: TokenManagerConfig) {
    this.s = config.storage;
    this.events = config.events;
    this.http = config.http;
    this.endpoint = config.endpoint;
    this.clientId = config.clientId;
    this.idTokenKey = `###aegis@${config.clientId}@id-token###`;
  }

  private scopedKey(kind: 'at' | 'rt', audience: string): string {
    return `###aegis@${this.clientId}@${kind}@${audience}###`;
  }

  // ==================== Scoped Token ====================

  async persistScoped(audience: string, accessToken: string, refreshToken: string | null): Promise<void> {
    await this.s.setItem(this.scopedKey('at', audience), accessToken);
    if (refreshToken) {
      await this.s.setItem(this.scopedKey('rt', audience), refreshToken);
    }
  }

  async loadScoped(audience: string): Promise<TokenStore> {
    const [accessToken, refreshToken] = await Promise.all([
      this.s.getItem(this.scopedKey('at', audience)),
      this.s.getItem(this.scopedKey('rt', audience)),
    ]);
    return { accessToken, refreshToken };
  }

  async expiredScoped(audience: string, bufferMs = 5 * 60 * 1000): Promise<boolean> {
    const token = await this.s.getItem(this.scopedKey('at', audience));
    if (!token) return true;
    const exp = extractExp(token);
    return !exp || Date.now() + bufferMs >= exp.getTime();
  }

  async purgeScoped(audience: string): Promise<void> {
    await Promise.all([
      this.s.removeItem(this.scopedKey('at', audience)),
      this.s.removeItem(this.scopedKey('rt', audience)),
    ]);
  }

  // ==================== Token Resolution ====================

  async getAccessToken(audience?: string): Promise<string | null> {
    const aud = audience ?? this.clientId;
    return this.resolveScoped(aud);
  }

  async isAuthenticated(audience?: string): Promise<boolean> {
    const aud = audience ?? this.clientId;
    const store = await this.loadScoped(aud);
    if (!store.accessToken) return false;
    if (await this.expiredScoped(aud, 60_000)) return !!store.refreshToken;
    return true;
  }

  async refreshToken(refreshToken?: string, audience?: string): Promise<TokenResponse> {
    const aud = audience ?? this.clientId;
    let rt: string | null | undefined = refreshToken;

    if (!rt) {
      const store = await this.loadScoped(aud);
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

    await this.persistScoped(aud, res.data.access_token, res.data.refresh_token ?? null);
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
          this.events.emit('token_expired');
          await this.purgeScoped(audience);
          return null;
        }
      }
      this.events.emit('token_expired');
      await this.purgeScoped(audience);
      return null;
    }

    return store.accessToken;
  }

  // ==================== Purge All ====================

  async purgeAll(audiences?: string[]): Promise<void> {
    if (audiences) {
      for (const aud of audiences) {
        await this.purgeScoped(aud);
      }
    }
    await this.purgeScoped(this.clientId);
    await this.s.removeItem(this.idTokenKey);
  }

  // ==================== ID Token ====================

  async settleIdToken(idToken: string): Promise<void> {
    try {
      const claims = await this.verifyIdToken(idToken);
      await this.s.setItem(this.idTokenKey, JSON.stringify(claims));
      console.log('[aegis] settleIdToken: claims persisted, sub=%s', claims.sub);
    } catch (e) {
      console.log('[aegis] settleIdToken: verification failed, skipping', e);
    }
  }

  async getUser(): Promise<IDTokenClaims | null> {
    const raw = await this.s.getItem(this.idTokenKey);
    if (!raw) {
      console.log('[aegis] getUser: no id_token in storage');
      return null;
    }
    try {
      const claims: IDTokenClaims = JSON.parse(raw);
      if (new Date(claims.exp) <= new Date()) {
        console.log('[aegis] getUser: id_token expired, removing');
        await this.s.removeItem(this.idTokenKey);
        return null;
      }
      console.log('[aegis] getUser: returning claims, sub=%s', claims.sub);
      return claims;
    } catch {
      console.log('[aegis] getUser: failed to parse stored id_token');
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
      url: `${this.endpoint}/api/pubkeys?client_id=${encodeURIComponent(this.clientId)}`,
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

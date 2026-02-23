/**
 * 存储工具
 */

import type { StorageAdapter, TokenStore, MultiAudienceTokenStore } from '@/types';

/** 存储 Key 前缀 */
const STORAGE_PREFIX = 'aegis_';

/** 存储 Key */
export const StorageKeys = {
  // Token 相关
  ACCESS_TOKEN: `${STORAGE_PREFIX}access_token`,
  REFRESH_TOKEN: `${STORAGE_PREFIX}refresh_token`,
  EXPIRES_AT: `${STORAGE_PREFIX}expires_at`,
  SCOPE: `${STORAGE_PREFIX}scope`,
  AUDIENCES: `${STORAGE_PREFIX}audiences`,
  // OAuth 流程状态
  CODE_VERIFIER: `${STORAGE_PREFIX}code_verifier`,
  STATE: `${STORAGE_PREFIX}state`,
  AUDIENCE: `${STORAGE_PREFIX}audience`,
  REDIRECT_URI: `${STORAGE_PREFIX}redirect_uri`,
  MULTI_AUDIENCES: `${STORAGE_PREFIX}multi_audiences`,
  RETURN_TO: `${STORAGE_PREFIX}return_to`,
} as const;

/** 生成带 audience 后缀的 storage key */
function audienceKey(baseKey: string, audience: string): string {
  return `${baseKey}:${audience}`;
}

/**
 * 浏览器 localStorage 适配器
 */
export class BrowserStorageAdapter implements StorageAdapter {
  getItem(key: string): string | null {
    try {
      return localStorage.getItem(key);
    } catch {
      return null;
    }
  }

  setItem(key: string, value: string): void {
    try {
      localStorage.setItem(key, value);
    } catch {
      console.warn('[Aegis SDK] Failed to save to localStorage');
    }
  }

  removeItem(key: string): void {
    try {
      localStorage.removeItem(key);
    } catch {
      // ignore
    }
  }
}

/**
 * 内存存储适配器（用于测试或无持久化场景）
 */
export class MemoryStorageAdapter implements StorageAdapter {
  private store = new Map<string, string>();

  getItem(key: string): string | null {
    return this.store.get(key) ?? null;
  }

  setItem(key: string, value: string): void {
    this.store.set(key, value);
  }

  removeItem(key: string): void {
    this.store.delete(key);
  }

  clear(): void {
    this.store.clear();
  }
}

/**
 * Token 存储管理器
 * 只负责 Token 的持久化（单 audience / 多 audience）
 */
export class TokenStorageManager {
  constructor(private storage: StorageAdapter) {}

  // ==================== 单 Audience ====================

  async save(
    accessToken: string,
    refreshToken: string | null,
    expiresIn: number,
    scope?: string
  ): Promise<void> {
    const expiresAt = Date.now() + expiresIn * 1000;

    await Promise.resolve(this.storage.setItem(StorageKeys.ACCESS_TOKEN, accessToken));
    await Promise.resolve(this.storage.setItem(StorageKeys.EXPIRES_AT, String(expiresAt)));

    if (refreshToken) {
      await Promise.resolve(this.storage.setItem(StorageKeys.REFRESH_TOKEN, refreshToken));
    }

    if (scope) {
      await Promise.resolve(this.storage.setItem(StorageKeys.SCOPE, scope));
    }
  }

  async get(): Promise<TokenStore> {
    const [accessToken, refreshToken, expiresAtStr, scope] = await Promise.all([
      Promise.resolve(this.storage.getItem(StorageKeys.ACCESS_TOKEN)),
      Promise.resolve(this.storage.getItem(StorageKeys.REFRESH_TOKEN)),
      Promise.resolve(this.storage.getItem(StorageKeys.EXPIRES_AT)),
      Promise.resolve(this.storage.getItem(StorageKeys.SCOPE)),
    ]);

    return {
      accessToken,
      refreshToken,
      expiresAt: expiresAtStr ? parseInt(expiresAtStr, 10) : null,
      scope,
    };
  }

  async clear(): Promise<void> {
    await Promise.all([
      Promise.resolve(this.storage.removeItem(StorageKeys.ACCESS_TOKEN)),
      Promise.resolve(this.storage.removeItem(StorageKeys.REFRESH_TOKEN)),
      Promise.resolve(this.storage.removeItem(StorageKeys.EXPIRES_AT)),
      Promise.resolve(this.storage.removeItem(StorageKeys.SCOPE)),
    ]);
  }

  async isExpired(bufferMs: number = 5 * 60 * 1000): Promise<boolean> {
    const expiresAtStr = await Promise.resolve(
      this.storage.getItem(StorageKeys.EXPIRES_AT)
    );
    if (!expiresAtStr) return true;
    const expiresAt = parseInt(expiresAtStr, 10);
    return Date.now() + bufferMs >= expiresAt;
  }

  // ==================== 多 Audience ====================

  async saveAudiences(audiences: string[]): Promise<void> {
    await Promise.resolve(
      this.storage.setItem(StorageKeys.AUDIENCES, JSON.stringify(audiences))
    );
  }

  getAudiences(): string[] {
    const raw = this.storage.getItem(StorageKeys.AUDIENCES) as string | null;
    if (!raw) return [];
    try {
      return JSON.parse(raw);
    } catch {
      return [];
    }
  }

  async saveForAudience(
    audience: string,
    accessToken: string,
    refreshToken: string | null,
    expiresIn: number,
    scope?: string
  ): Promise<void> {
    const expiresAt = Date.now() + expiresIn * 1000;

    await Promise.resolve(
      this.storage.setItem(audienceKey(StorageKeys.ACCESS_TOKEN, audience), accessToken)
    );
    await Promise.resolve(
      this.storage.setItem(audienceKey(StorageKeys.EXPIRES_AT, audience), String(expiresAt))
    );

    if (refreshToken) {
      await Promise.resolve(
        this.storage.setItem(audienceKey(StorageKeys.REFRESH_TOKEN, audience), refreshToken)
      );
    }

    if (scope) {
      await Promise.resolve(
        this.storage.setItem(audienceKey(StorageKeys.SCOPE, audience), scope)
      );
    }
  }

  async getForAudience(audience: string): Promise<TokenStore> {
    const [accessToken, refreshToken, expiresAtStr, scope] = await Promise.all([
      Promise.resolve(this.storage.getItem(audienceKey(StorageKeys.ACCESS_TOKEN, audience))),
      Promise.resolve(this.storage.getItem(audienceKey(StorageKeys.REFRESH_TOKEN, audience))),
      Promise.resolve(this.storage.getItem(audienceKey(StorageKeys.EXPIRES_AT, audience))),
      Promise.resolve(this.storage.getItem(audienceKey(StorageKeys.SCOPE, audience))),
    ]);

    return {
      accessToken,
      refreshToken,
      expiresAt: expiresAtStr ? parseInt(expiresAtStr, 10) : null,
      scope,
    };
  }

  async isExpiredForAudience(audience: string, bufferMs: number = 5 * 60 * 1000): Promise<boolean> {
    const expiresAtStr = await Promise.resolve(
      this.storage.getItem(audienceKey(StorageKeys.EXPIRES_AT, audience))
    );
    if (!expiresAtStr) return true;
    const expiresAt = parseInt(expiresAtStr, 10);
    return Date.now() + bufferMs >= expiresAt;
  }

  async clearForAudience(audience: string): Promise<void> {
    await Promise.all([
      Promise.resolve(this.storage.removeItem(audienceKey(StorageKeys.ACCESS_TOKEN, audience))),
      Promise.resolve(this.storage.removeItem(audienceKey(StorageKeys.REFRESH_TOKEN, audience))),
      Promise.resolve(this.storage.removeItem(audienceKey(StorageKeys.EXPIRES_AT, audience))),
      Promise.resolve(this.storage.removeItem(audienceKey(StorageKeys.SCOPE, audience))),
    ]);
  }

  async getAllAudiences(): Promise<MultiAudienceTokenStore> {
    const audiences = this.getAudiences();
    const result: MultiAudienceTokenStore = {};
    for (const aud of audiences) {
      result[aud] = await this.getForAudience(aud);
    }
    return result;
  }

  async clearAll(): Promise<void> {
    const audiences = this.getAudiences();
    for (const aud of audiences) {
      await this.clearForAudience(aud);
    }
    await Promise.resolve(this.storage.removeItem(StorageKeys.AUDIENCES));
    await this.clear();
  }
}

/**
 * OAuth 流程状态管理器
 * 管理授权流程中的一次性状态（PKCE、state、audience、redirectUri、returnTo 等）
 * 这些数据在 authorize → callback 之间跨页面传递，回调后即消费销毁
 */
export class FlowStateManager {
  constructor(private storage: StorageAdapter) {}

  // ==================== PKCE ====================

  async saveCodeVerifier(verifier: string): Promise<void> {
    await Promise.resolve(this.storage.setItem(StorageKeys.CODE_VERIFIER, verifier));
  }

  consumeCodeVerifier(): string | null {
    const verifier = this.storage.getItem(StorageKeys.CODE_VERIFIER) as string | null;
    if (verifier) {
      this.storage.removeItem(StorageKeys.CODE_VERIFIER);
    }
    return verifier;
  }

  // ==================== State ====================

  async saveState(state: string): Promise<void> {
    await Promise.resolve(this.storage.setItem(StorageKeys.STATE, state));
  }

  consumeState(): string | null {
    const state = this.storage.getItem(StorageKeys.STATE) as string | null;
    if (state) {
      this.storage.removeItem(StorageKeys.STATE);
    }
    return state;
  }

  // ==================== Audience ====================

  async saveAudience(audience: string): Promise<void> {
    await Promise.resolve(this.storage.setItem(StorageKeys.AUDIENCE, audience));
  }

  consumeAudience(): string | null {
    const audience = this.storage.getItem(StorageKeys.AUDIENCE) as string | null;
    if (audience) {
      this.storage.removeItem(StorageKeys.AUDIENCE);
    }
    return audience;
  }

  // ==================== Redirect URI ====================

  async saveRedirectUri(redirectUri: string): Promise<void> {
    await Promise.resolve(this.storage.setItem(StorageKeys.REDIRECT_URI, redirectUri));
  }

  consumeRedirectUri(): string | null {
    const redirectUri = this.storage.getItem(StorageKeys.REDIRECT_URI) as string | null;
    if (redirectUri) {
      this.storage.removeItem(StorageKeys.REDIRECT_URI);
    }
    return redirectUri;
  }

  // ==================== Multi-Audiences 配置 ====================

  async saveMultiAudiences(audiences: Record<string, unknown>): Promise<void> {
    await Promise.resolve(
      this.storage.setItem(StorageKeys.MULTI_AUDIENCES, JSON.stringify(audiences))
    );
  }

  consumeMultiAudiences(): Record<string, unknown> | null {
    const raw = this.storage.getItem(StorageKeys.MULTI_AUDIENCES) as string | null;
    if (raw) {
      this.storage.removeItem(StorageKeys.MULTI_AUDIENCES);
      try {
        return JSON.parse(raw);
      } catch {
        return null;
      }
    }
    return null;
  }

  // ==================== Return To ====================

  async saveReturnTo(path: string): Promise<void> {
    await Promise.resolve(this.storage.setItem(StorageKeys.RETURN_TO, path));
  }

  consumeReturnTo(): string | null {
    const path = this.storage.getItem(StorageKeys.RETURN_TO) as string | null;
    if (path) {
      this.storage.removeItem(StorageKeys.RETURN_TO);
    }
    return path;
  }
}

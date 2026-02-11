/**
 * 存储工具
 */

import type { StorageAdapter, TokenStore } from '@/types';

/** 存储 Key 前缀 */
const STORAGE_PREFIX = 'aegis_';

/** 存储 Key */
export const StorageKeys = {
  ACCESS_TOKEN: `${STORAGE_PREFIX}access_token`,
  REFRESH_TOKEN: `${STORAGE_PREFIX}refresh_token`,
  EXPIRES_AT: `${STORAGE_PREFIX}expires_at`,
  SCOPE: `${STORAGE_PREFIX}scope`,
  CODE_VERIFIER: `${STORAGE_PREFIX}code_verifier`,
  STATE: `${STORAGE_PREFIX}state`,
  AUDIENCE: `${STORAGE_PREFIX}audience`,
  REDIRECT_URI: `${STORAGE_PREFIX}redirect_uri`,
} as const;

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
 */
export class TokenStorageManager {
  constructor(private storage: StorageAdapter) {}

  /**
   * 保存 Token
   */
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

  /**
   * 获取 Token
   */
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

  /**
   * 清除 Token
   */
  async clear(): Promise<void> {
    await Promise.all([
      Promise.resolve(this.storage.removeItem(StorageKeys.ACCESS_TOKEN)),
      Promise.resolve(this.storage.removeItem(StorageKeys.REFRESH_TOKEN)),
      Promise.resolve(this.storage.removeItem(StorageKeys.EXPIRES_AT)),
      Promise.resolve(this.storage.removeItem(StorageKeys.SCOPE)),
    ]);
  }

  /**
   * 检查 Token 是否过期（提前 5 分钟）
   */
  async isExpired(bufferMs: number = 5 * 60 * 1000): Promise<boolean> {
    const expiresAtStr = await Promise.resolve(
      this.storage.getItem(StorageKeys.EXPIRES_AT)
    );
    if (!expiresAtStr) {
      return true;
    }
    const expiresAt = parseInt(expiresAtStr, 10);
    return Date.now() + bufferMs >= expiresAt;
  }

  /**
   * 保存 PKCE code_verifier
   */
  async saveCodeVerifier(verifier: string): Promise<void> {
    await Promise.resolve(this.storage.setItem(StorageKeys.CODE_VERIFIER, verifier));
  }

  /**
   * 获取并清除 code_verifier
   */
  async consumeCodeVerifier(): Promise<string | null> {
    const verifier = await Promise.resolve(
      this.storage.getItem(StorageKeys.CODE_VERIFIER)
    );
    if (verifier) {
      await Promise.resolve(this.storage.removeItem(StorageKeys.CODE_VERIFIER));
    }
    return verifier;
  }

  /**
   * 保存 state
   */
  async saveState(state: string): Promise<void> {
    await Promise.resolve(this.storage.setItem(StorageKeys.STATE, state));
  }

  /**
   * 获取并清除 state
   */
  async consumeState(): Promise<string | null> {
    const state = await Promise.resolve(this.storage.getItem(StorageKeys.STATE));
    if (state) {
      await Promise.resolve(this.storage.removeItem(StorageKeys.STATE));
    }
    return state;
  }

  /**
   * 保存 audience
   */
  async saveAudience(audience: string): Promise<void> {
    await Promise.resolve(this.storage.setItem(StorageKeys.AUDIENCE, audience));
  }

  /**
   * 获取并清除 audience
   */
  async consumeAudience(): Promise<string | null> {
    const audience = await Promise.resolve(this.storage.getItem(StorageKeys.AUDIENCE));
    if (audience) {
      await Promise.resolve(this.storage.removeItem(StorageKeys.AUDIENCE));
    }
    return audience;
  }

  /**
   * 保存 redirectUri
   */
  async saveRedirectUri(redirectUri: string): Promise<void> {
    await Promise.resolve(this.storage.setItem(StorageKeys.REDIRECT_URI, redirectUri));
  }

  /**
   * 获取并清除 redirectUri
   */
  async consumeRedirectUri(): Promise<string | null> {
    const redirectUri = await Promise.resolve(this.storage.getItem(StorageKeys.REDIRECT_URI));
    if (redirectUri) {
      await Promise.resolve(this.storage.removeItem(StorageKeys.REDIRECT_URI));
    }
    return redirectUri;
  }
}

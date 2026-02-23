/**
 * 小程序 Auth
 * 专门为小程序场景设计，不需要 PKCE 和重定向
 */

import type {
  AuthConfig,
  StorageAdapter,
  HttpClient,
  TokenResponse,
  AuthEvent,
  AuthEventListener,
  AuthEventType,
  IDPType,
} from '@/types';
import { AuthError, ErrorCodes } from '@/types';
import { TokenStorageManager } from '@utils/storage';
import { isJWTExpired, parseJWT } from '@utils/jwt';

/** 小程序登录参数 */
export interface MPLoginParams {
  /** 平台登录码 */
  code: string;
  /** 用户昵称（可选） */
  nickname?: string;
  /** 用户头像（可选） */
  avatar?: string;
}

/** 小程序配置 */
export interface MPAuthConfig {
  /** 认证服务器地址 */
  issuer: string;
  /** IDP 类型 */
  idp: IDPType;
  /** 存储适配器 */
  storage: StorageAdapter;
  /** HTTP 客户端 */
  httpClient: HttpClient;
  /** 启用调试日志 */
  debug?: boolean;
}

/**
 * 小程序 Auth
 */
export class MiniProgramAuth {
  private config: MPAuthConfig;
  private tokenManager: TokenStorageManager;
  private listeners: Map<AuthEventType, Set<AuthEventListener>> = new Map();
  private debug: boolean;

  constructor(config: MPAuthConfig) {
    this.config = config;
    this.debug = config.debug ?? false;
    this.tokenManager = new TokenStorageManager(config.storage);
  }

  // ==================== 公开方法 ====================

  /**
   * 小程序登录
   * 使用平台 login API 获取的 code 换取 Token
   */
  async login(params: MPLoginParams): Promise<TokenResponse> {
    // 组合 code: idp:actual_code
    const combinedCode = `${this.config.idp}:${params.code}`;

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: combinedCode,
    });

    if (params.nickname) {
      body.append('nickname', params.nickname);
    }
    if (params.avatar) {
      body.append('avatar', params.avatar);
    }

    this.log('Login request - IDP:', this.config.idp);

    const response = await this.config.httpClient.request<TokenResponse>({
      method: 'POST',
      url: `${this.config.issuer}/api/token`,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: body.toString(),
    });

    if (response.status !== 200) {
      const error = response.data as unknown as {
        error?: string;
        error_description?: string;
      };
      throw new AuthError(
        error?.error ?? ErrorCodes.INVALID_GRANT,
        error?.error_description ?? 'Login failed'
      );
    }

    // 保存 Token
    await this.tokenManager.save(
      response.data.access_token,
      response.data.refresh_token ?? null,
      response.data.expires_in,
      response.data.scope
    );

    this.emit('login', response.data);
    this.log('Login successful');

    return response.data;
  }

  /**
   * 获取 Access Token（自动刷新）
   */
  async getAccessToken(): Promise<string | null> {
    const store = await this.tokenManager.get();

    if (!store.accessToken) {
      return null;
    }

    // 检查是否过期
    const isExpired = await this.tokenManager.isExpired();
    if (isExpired) {
      // 尝试刷新
      if (store.refreshToken) {
        try {
          const tokens = await this.refreshToken(store.refreshToken);
          return tokens.access_token;
        } catch (error) {
          this.log('Token refresh failed:', error);
          this.emit('token_expired');
          await this.tokenManager.clear();
          return null;
        }
      } else {
        this.emit('token_expired');
        await this.tokenManager.clear();
        return null;
      }
    }

    return store.accessToken;
  }

  /**
   * 确保 Token 有效（用于请求前检查）
   */
  async ensureValidToken(): Promise<string | null> {
    return this.getAccessToken();
  }

  /**
   * 刷新 Token
   */
  async refreshToken(refreshToken?: string): Promise<TokenResponse> {
    const token = refreshToken ?? (await this.tokenManager.get()).refreshToken;

    if (!token) {
      throw new AuthError(
        ErrorCodes.NOT_AUTHENTICATED,
        'No refresh token available'
      );
    }

    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: token,
    });

    const response = await this.config.httpClient.request<TokenResponse>({
      method: 'POST',
      url: `${this.config.issuer}/api/token`,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: body.toString(),
    });

    if (response.status !== 200) {
      throw new AuthError(ErrorCodes.INVALID_GRANT, 'Token refresh failed');
    }

    // 保存新 Token
    await this.tokenManager.save(
      response.data.access_token,
      response.data.refresh_token ?? null,
      response.data.expires_in,
      response.data.scope
    );

    this.emit('token_refreshed', response.data);
    this.log('Token refreshed');

    return response.data;
  }

  /**
   * 登出
   */
  async logout(): Promise<void> {
    await this.tokenManager.clear();
    this.emit('logout');
    this.log('Logged out');
  }

  /**
   * 检查是否已登录
   */
  async isAuthenticated(): Promise<boolean> {
    const store = await this.tokenManager.get();
    if (!store.accessToken) {
      return false;
    }

    // 检查 Token 是否过期
    if (isJWTExpired(store.accessToken)) {
      return !!store.refreshToken;
    }

    return true;
  }

  /**
   * 获取当前用户的 Claims
   */
  async getClaims(): Promise<Record<string, unknown> | null> {
    const store = await this.tokenManager.get();
    if (!store.accessToken) {
      return null;
    }
    return parseJWT(store.accessToken);
  }

  // ==================== 事件系统 ====================

  on(event: AuthEventType, listener: AuthEventListener): () => void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(listener);
    return () => this.off(event, listener);
  }

  off(event: AuthEventType, listener: AuthEventListener): void {
    this.listeners.get(event)?.delete(listener);
  }

  private emit(type: AuthEventType, data?: unknown): void {
    const event: AuthEvent = { type, data };
    this.listeners.get(type)?.forEach((listener) => listener(event));
  }

  private log(...args: unknown[]): void {
    if (this.debug) {
      console.log('[Aegis SDK]', ...args);
    }
  }
}

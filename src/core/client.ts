/**
 * Aegis Auth 核心类
 */

import type {
  AuthConfig,
  AuthorizeOptions,
  StorageAdapter,
  HttpClient,
  TokenResponse,
  UserInfo,
  AuthEvent,
  AuthEventListener,
  AuthEventType,
  PKCEParams,
  ConnectionsResponse,
  CreateChallengeRequest,
  CreateChallengeResponse,
  VerifyChallengeRequest,
  VerifyChallengeResponse,
  LoginRequest,
} from '@/types';
import { AuthError, ErrorCodes } from '@/types';
import { TokenStorageManager, BrowserStorageAdapter } from '@utils/storage';
import { generatePKCE } from '@utils/pkce';
import { isJWTExpired, parseJWT } from '@utils/jwt';

/**
 * Aegis Auth
 * 
 * @example
 * ```typescript
 * const auth = new Auth({
 *   endpoint: 'https://aegis.example.com',
 *   clientId: 'my-app',
 * })
 * 
 * // 发起授权（指定目标服务）
 * await auth.authorize({ audience: 'api.example.com' })
 * ```
 */
export class Auth {
  private config: AuthConfig;
  private tokenManager: TokenStorageManager;
  private httpClient: HttpClient;
  private listeners: Map<AuthEventType, Set<AuthEventListener>> = new Map();
  private debug: boolean;
  /** 当前授权的 audience（用于 token 交换） */
  private currentAudience: string | null = null;
  /** 当前授权的 redirectUri */
  private currentRedirectUri: string | null = null;

  constructor(config: AuthConfig) {
    this.config = config;
    this.debug = config.debug ?? false;

    // 初始化存储
    const storage = config.storage ?? this.getDefaultStorage();
    this.tokenManager = new TokenStorageManager(storage);

    // 初始化 HTTP 客户端
    this.httpClient = config.httpClient ?? this.getDefaultHttpClient();
  }

  // ==================== 公开方法 ====================

  /**
   * 开始授权流程（生成授权 URL）
   * 
   * @param options - 授权选项
   * @param options.audience - 目标服务 ID（必填）
   * @param options.scopes - 请求的 scope 列表（必填）
   * @param options.state - 自定义 state
   * @param options.redirectUri - 重定向 URI（可选，覆盖默认配置）
   * 
   * @example
   * ```typescript
   * // 基本用法
   * const { url } = await auth.authorize({ 
   *   audience: 'api.example.com',
   *   scopes: ['openid', 'profile']
   * })
   * window.location.href = url
   * 
   * // 需要后端换取凭证时指定 redirectUri
   * const { url } = await auth.authorize({
   *   audience: 'api.example.com',
   *   scopes: ['openid', 'profile', 'email'],
   *   redirectUri: 'https://my-app.com/auth/callback'
   * })
   * ```
   */
  async authorize(options: AuthorizeOptions): Promise<{ url: string; pkce: PKCEParams; state: string }> {
    const { audience, scopes, state: customState, redirectUri } = options;

    // 保存当前授权的 audience 和 redirectUri（用于 token 交换）
    this.currentAudience = audience;
    this.currentRedirectUri = redirectUri ?? this.config.redirectUri ?? null;

    // 生成 PKCE
    const pkce = await generatePKCE();

    // 生成 state（如果未提供）
    const state = customState ?? this.generateState();

    // 保存到存储
    await this.tokenManager.saveCodeVerifier(pkce.codeVerifier);
    await this.tokenManager.saveState(state);
    // 同时保存 audience 和 redirectUri 用于回调处理
    await this.tokenManager.saveAudience(audience);
    if (this.currentRedirectUri) {
      await this.tokenManager.saveRedirectUri(this.currentRedirectUri);
    }

    // 构建授权 URL
    const url = this.buildAuthorizeUrl(pkce, state, audience, scopes, this.currentRedirectUri);

    this.log('Authorize URL generated:', url);

    return { url, pkce, state };
  }

  /**
   * 处理授权回调（交换 Token）
   */
  async handleCallback(
    code: string,
    state?: string
  ): Promise<TokenResponse> {
    // 验证 state
    const savedState = await this.tokenManager.consumeState();
    if (state && savedState && state !== savedState) {
      throw new AuthError(
        ErrorCodes.INVALID_REQUEST,
        'State mismatch'
      );
    }

    // 获取 code_verifier
    const codeVerifier = await this.tokenManager.consumeCodeVerifier();
    if (!codeVerifier) {
      throw new AuthError(
        ErrorCodes.INVALID_REQUEST,
        'Code verifier not found'
      );
    }

    // 获取保存的 redirectUri
    const redirectUri = await this.tokenManager.consumeRedirectUri();

    // 交换 Token
    const tokens = await this.exchangeToken(code, codeVerifier, redirectUri);

    // 保存 Token
    await this.tokenManager.save(
      tokens.access_token,
      tokens.refresh_token ?? null,
      tokens.expires_in,
      tokens.scope
    );

    // 清理 audience
    await this.tokenManager.consumeAudience();

    this.emit('login', tokens);
    this.log('Login successful');

    return tokens;
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
      client_id: this.config.clientId,
    });

    const response = await this.httpClient.request<TokenResponse>({
      method: 'POST',
      url: `${this.config.endpoint}/api/token`,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: body.toString(),
    });

    if (response.status !== 200) {
      throw new AuthError(
        ErrorCodes.INVALID_GRANT,
        'Token refresh failed'
      );
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
   * 获取用户信息
   */
  async getUserInfo(): Promise<UserInfo> {
    const token = await this.getAccessToken();
    if (!token) {
      throw new AuthError(
        ErrorCodes.NOT_AUTHENTICATED,
        'Not authenticated'
      );
    }

    const response = await this.httpClient.request<UserInfo>({
      method: 'GET',
      url: `${this.config.endpoint}/api/userinfo`,
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (response.status !== 200) {
      throw new AuthError(ErrorCodes.SERVER_ERROR, 'Failed to get user info');
    }

    return response.data;
  }

  /**
   * 登出
   */
  async logout(): Promise<void> {
    const token = await this.getAccessToken();

    if (token) {
      try {
        await this.httpClient.request({
          method: 'POST',
          url: `${this.config.endpoint}/api/logout`,
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
      } catch {
        // 忽略登出 API 错误
        this.log('Logout API failed, clearing local tokens');
      }
    }

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
      // 如果有 refresh_token，仍然认为已登录（可以刷新）
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

  // ==================== Challenge API ====================

  /**
   * 获取可用的 Connections 配置
   * 需要先调用 authorize() 创建认证会话
   */
  async getConnections(): Promise<ConnectionsResponse> {
    const response = await this.httpClient.request<ConnectionsResponse>({
      method: 'GET',
      url: `${this.config.endpoint}/api/connections`,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    if (response.status !== 200) {
      throw new AuthError(ErrorCodes.SERVER_ERROR, 'Failed to get connections');
    }

    return response.data;
  }

  /**
   * 创建 Challenge（MFA/Captcha）
   * 
   * @example
   * ```typescript
   * // 创建邮箱 OTP Challenge
   * const challenge = await auth.createChallenge({
   *   type: 'email',
   *   email: 'user@example.com',
   *   captcha_token: turnstileToken, // 如果需要 captcha 前置
   * });
   * ```
   */
  async createChallenge(req: CreateChallengeRequest): Promise<CreateChallengeResponse> {
    const response = await this.httpClient.request<CreateChallengeResponse>({
      method: 'POST',
      url: `${this.config.endpoint}/api/challenge`,
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(req),
    });

    if (response.status !== 200) {
      const error = response.data as unknown as { error?: string; error_description?: string };
      throw new AuthError(
        error?.error ?? ErrorCodes.SERVER_ERROR,
        error?.error_description ?? 'Failed to create challenge'
      );
    }

    this.log('Challenge created:', response.data);
    return response.data;
  }

  /**
   * 验证 Challenge
   * 
   * @example
   * ```typescript
   * // 验证邮箱 OTP
   * const result = await auth.verifyChallenge(challengeId, { code: '123456' });
   * if (result.verified) {
   *   // 继续登录流程
   * }
   * ```
   */
  async verifyChallenge(challengeId: string, req: VerifyChallengeRequest): Promise<VerifyChallengeResponse> {
    const response = await this.httpClient.request<VerifyChallengeResponse>({
      method: 'PUT',
      url: `${this.config.endpoint}/api/challenge?challenge_id=${encodeURIComponent(challengeId)}`,
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(req),
    });

    if (response.status !== 200) {
      const error = response.data as unknown as { error?: string; error_description?: string };
      throw new AuthError(
        error?.error ?? ErrorCodes.SERVER_ERROR,
        error?.error_description ?? 'Failed to verify challenge'
      );
    }

    this.log('Challenge verified:', response.data);
    return response.data;
  }

  /**
   * 执行登录
   * 
   * @example
   * ```typescript
   * // 邮箱 OTP 登录
   * await auth.login({
   *   connection: 'email',
   *   data: { email: 'user@example.com', code: '123456' }
   * });
   * 
   * // oper 登录（运营后台）
   * await auth.login({
   *   connection: 'oper',
   *   data: { email: 'admin@example.com', challenge_id: '...' }
   * });
   * ```
   */
  async login(req: LoginRequest): Promise<void> {
    const response = await this.httpClient.request({
      method: 'POST',
      url: `${this.config.endpoint}/api/login`,
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(req),
    });

    if (response.status !== 200) {
      const error = response.data as unknown as { error?: string; error_description?: string };
      throw new AuthError(
        error?.error ?? ErrorCodes.ACCESS_DENIED,
        error?.error_description ?? 'Login failed'
      );
    }

    this.log('Login successful');
  }

  // ==================== 事件系统 ====================

  /**
   * 添加事件监听器
   */
  on(event: AuthEventType, listener: AuthEventListener): () => void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(listener);

    // 返回取消订阅函数
    return () => this.off(event, listener);
  }

  /**
   * 移除事件监听器
   */
  off(event: AuthEventType, listener: AuthEventListener): void {
    this.listeners.get(event)?.delete(listener);
  }

  /**
   * 触发事件
   */
  private emit(type: AuthEventType, data?: unknown): void {
    const event: AuthEvent = { type, data };
    this.listeners.get(type)?.forEach((listener) => listener(event));
  }

  // ==================== 内部方法 ====================

  /**
   * 构建授权 URL
   */
  private buildAuthorizeUrl(
    pkce: PKCEParams,
    state: string,
    audience: string,
    scopes: string[],
    redirectUri?: string | null
  ): string {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      audience,
      code_challenge: pkce.codeChallenge,
      code_challenge_method: pkce.codeChallengeMethod,
      state,
      scope: scopes.join(' '),
    });

    // 只有在指定了 redirectUri 时才添加（否则由 aegis-ui 处理）
    if (redirectUri) {
      params.set('redirect_uri', redirectUri);
    }

    // 跳转到 aegis-ui 的 /authorize 页面，由 UI 发起真正的 API 请求
    return `${this.config.endpoint}/authorize?${params.toString()}`;
  }

  /**
   * 交换 Token
   */
  private async exchangeToken(
    code: string,
    codeVerifier: string,
    redirectUri?: string | null
  ): Promise<TokenResponse> {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: this.config.clientId,
      code_verifier: codeVerifier,
    });

    // 只有在指定了 redirectUri 时才添加
    if (redirectUri) {
      body.set('redirect_uri', redirectUri);
    }

    const response = await this.httpClient.request<TokenResponse>({
      method: 'POST',
      url: `${this.config.endpoint}/api/token`,
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
        error?.error_description ?? 'Token exchange failed'
      );
    }

    return response.data;
  }

  /**
   * 生成 state
   */
  private generateState(): string {
    const array = new Uint8Array(16);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(array);
    } else {
      for (let i = 0; i < 16; i++) {
        array[i] = Math.floor(Math.random() * 256);
      }
    }
    return Array.from(array, (b) => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * 获取默认存储适配器
   */
  private getDefaultStorage(): StorageAdapter {
    if (typeof window !== 'undefined' && window.localStorage) {
      return new BrowserStorageAdapter();
    }
    // 其他环境需要传入自定义适配器
    throw new Error(
      'No default storage available. Please provide a custom storage adapter.'
    );
  }

  /**
   * 获取默认 HTTP 客户端
   */
  private getDefaultHttpClient(): HttpClient {
    return {
      async request(config) {
        const response = await fetch(config.url, {
          method: config.method,
          headers: config.headers,
          body: config.body,
        });

        const data = await response.json();

        return {
          status: response.status,
          data,
        };
      },
    };
  }

  /**
   * 调试日志
   */
  private log(...args: unknown[]): void {
    if (this.debug) {
      console.log('[Aegis SDK]', ...args);
    }
  }
}

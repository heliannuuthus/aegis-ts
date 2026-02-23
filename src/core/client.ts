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
  ProfileResponse,
  UpdateProfileRequest,
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
import { TokenStorageManager, FlowStateManager, BrowserStorageAdapter } from '@utils/storage';
import { generatePKCE } from '@utils/pkce';
import { parseJWT } from '@utils/jwt';

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
 * // 发起授权（指定目标服务，可选多 audience）
 * await auth.authorize({
 *   audience: 'hermes',
 *   scopes: ['openid', 'profile', 'email'],
 *   audiences: {
 *     hermes: { scope: 'openid profile email' },
 *     iris: { scope: 'openid profile email' },
 *   },
 * })
 * ```
 */
export class Auth {
  private config: AuthConfig;
  private tokenManager: TokenStorageManager;
  private flowState: FlowStateManager;
  private httpClient: HttpClient;
  private listeners: Map<AuthEventType, Set<AuthEventListener>> = new Map();
  private debug: boolean;
  /** 当前授权的 audience（用于 token 交换） */
  private currentAudience: string | null = null;
  /** 当前授权的 redirectUri */
  private currentRedirectUri: string | null = null;
  /** 当前授权的多 audience 配置 */
  private currentAudiences: Record<string, AudienceScope> | null = null;

  constructor(config: AuthConfig) {
    this.config = config;
    this.debug = config.debug ?? false;

    // 初始化存储（两个 Manager 共享同一个 StorageAdapter）
    const storage = config.storage ?? this.getDefaultStorage();
    this.tokenManager = new TokenStorageManager(storage);
    this.flowState = new FlowStateManager(storage);

    // 初始化 HTTP 客户端
    this.httpClient = config.httpClient ?? this.getDefaultHttpClient();
  }

  // ==================== 公开方法 ====================

  /**
   * 开始授权流程（生成授权 URL）
   *
   * @param options - 授权选项
   * @param options.audience - 目标服务 ID（必填，授权阶段只能指定一个）
   * @param options.scopes - 请求的 scope 列表（必填）
   * @param options.state - 自定义 state
   * @param options.redirectUri - 重定向 URI（可选，覆盖默认配置）
   * @param options.audiences - 多 audience 配置（可选，token 交换时使用）
   */
  async authorize(
    options: AuthorizeOptions
  ): Promise<{ url: string; pkce: PKCEParams; state: string }> {
    const { audience, scopes, state: customState, redirectUri, audiences } = options;

    // 保存当前授权的 audience 和 redirectUri（用于 token 交换）
    this.currentAudience = audience;
    this.currentRedirectUri = redirectUri ?? this.config.redirectUri ?? null;
    this.currentAudiences = audiences ?? null;

    // 生成 PKCE
    const pkce = await generatePKCE();

    // 生成 state（如果未提供）
    const state = customState ?? this.generateState();

    // 保存流程状态到存储（跨页面传递）
    await this.flowState.saveCodeVerifier(pkce.codeVerifier);
    await this.flowState.saveState(state);
    await this.flowState.saveAudience(audience);
    if (this.currentRedirectUri) {
      await this.flowState.saveRedirectUri(this.currentRedirectUri);
    }
    if (audiences) {
      await this.flowState.saveMultiAudiences(audiences);
    }

    // 构建授权 URL
    const url = this.buildAuthorizeUrl(
      pkce,
      state,
      audience,
      scopes,
      this.currentRedirectUri
    );

    // 校验授权 URL 是否在白名单域名内（防止恶意配置篡改）
    if (!this.isAllowedUrl(url)) {
      throw new AuthError(
        ErrorCodes.INVALID_REQUEST,
        `Authorization URL host is not in allowed list: ${url}`
      );
    }

    this.log('Authorize URL generated:', url);

    return { url, pkce, state };
  }

  /**
   * 处理授权回调（交换 Token）
   * 自动检测是否有多 audience 配置，有则用 JSON 模式换取多 token
   */
  async handleCallback(
    code: string,
    state?: string
  ): Promise<TokenResponse> {
    this.log('handleCallback start', {
      code: code.substring(0, 8) + '...',
      state: state?.substring(0, 8),
    });

    // 消费一次性流程状态（读+删原子操作，防止并发竞态）
    const savedState = this.flowState.consumeState();
    this.log('handleCallback state check', {
      savedState: savedState?.substring(0, 8),
      receivedState: state?.substring(0, 8),
    });
    if (state && savedState && state !== savedState) {
      throw new AuthError(ErrorCodes.INVALID_REQUEST, 'State mismatch');
    }

    const codeVerifier = this.flowState.consumeCodeVerifier();
    this.log('handleCallback codeVerifier', { found: !!codeVerifier });
    if (!codeVerifier) {
      throw new AuthError(
        ErrorCodes.INVALID_REQUEST,
        'Code verifier not found'
      );
    }

    const redirectUri = this.flowState.consumeRedirectUri();
    this.log('handleCallback redirectUri', { redirectUri });

    // 恢复多 audience 配置（从存储中读取，因为跨页面了）
    let audiences = this.flowState.consumeMultiAudiences() as Record<string, AudienceScope> | null;
    // 也用内存中的配置（如果同页面）
    if (!audiences && this.currentAudiences) {
      audiences = this.currentAudiences;
    }

    // 根据是否有多 audience 选择换取方式
    if (audiences && Object.keys(audiences).length > 0) {
      return this.handleMultiAudienceCallback(
        code,
        codeVerifier,
        redirectUri,
        audiences
      );
    }

    // 单 audience 模式
    return this.handleSingleAudienceCallback(code, codeVerifier, redirectUri);
  }

  /**
   * 获取 Access Token（自动刷新）
   * @param audience 指定 audience，不传则返回默认（主 audience）token
   */
  async getAccessToken(audience?: string): Promise<string | null> {
    if (audience) {
      return this.getAccessTokenForAudience(audience);
    }

    const store = await this.tokenManager.get();
    this.log('getAccessToken', {
      hasAccessToken: !!store.accessToken,
      hasRefreshToken: !!store.refreshToken,
      expiresAt: store.expiresAt,
      now: Date.now(),
      diff: store.expiresAt ? store.expiresAt - Date.now() : null,
    });

    if (!store.accessToken) {
      this.log('getAccessToken: no access token');
      return null;
    }

    // 检查是否过期
    const isExpired = await this.tokenManager.isExpired();
    this.log('getAccessToken isExpired (5min buffer):', isExpired);
    if (isExpired) {
      // 尝试刷新
      if (store.refreshToken) {
        try {
          const tokens = await this.refreshToken(store.refreshToken);
          return tokens.access_token;
        } catch (error) {
          this.log('Token refresh failed:', error);
          this.emit('token_expired');
          this.log('getAccessToken: CLEARING all tokens (refresh failed)');
          await this.tokenManager.clear();
          return null;
        }
      } else {
        this.emit('token_expired');
        this.log(
          'getAccessToken: CLEARING all tokens (no refresh token, expired)'
        );
        await this.tokenManager.clear();
        return null;
      }
    }

    return store.accessToken;
  }

  /**
   * 获取所有已存储的 audience 列表
   */
  getAudiences(): string[] {
    return this.tokenManager.getAudiences();
  }

  // ==================== URL 白名单 ====================

  /**
   * 检查 URL 是否在允许的认证域名白名单中
   * 如果未配置 allowedAuthHosts，则从 endpoint 自动提取域名
   */
  isAllowedUrl(url: string): boolean {
    try {
      const parsed = new URL(url);
      const allowedHosts = this.config.allowedAuthHosts ?? [];

      // 如果未显式配置白名单，从 endpoint 自动提取
      if (allowedHosts.length === 0) {
        const endpointHost = new URL(this.config.endpoint).host;
        return parsed.host === endpointHost;
      }

      return allowedHosts.some(
        (host) => parsed.host === host || parsed.hostname === host
      );
    } catch {
      return false;
    }
  }

  // ==================== ReturnTo 路径管理 ====================

  /**
   * 保存登录前的路径（登录重定向前调用，回调后用 consumeReturnTo 恢复）
   */
  async saveReturnTo(path: string): Promise<void> {
    await this.flowState.saveReturnTo(path);
  }

  /**
   * 获取并清除 returnTo 路径（回调完成后调用）
   * 返回 null 表示没有保存的路径
   */
  consumeReturnTo(): string | null {
    return this.flowState.consumeReturnTo();
  }

  /**
   * 刷新 Token
   * @param refreshToken 指定 refresh token，不传则使用默认的
   * @param audience 指定 audience（刷新该 audience 的 token）
   */
  async refreshToken(
    refreshToken?: string,
    audience?: string
  ): Promise<TokenResponse> {
    let token: string | null | undefined = refreshToken;

    if (!token) {
      if (audience) {
        const store = await this.tokenManager.getForAudience(audience);
        token = store.refreshToken;
      } else {
        const store = await this.tokenManager.get();
        token = store.refreshToken;
      }
    }

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
      throw new AuthError(ErrorCodes.INVALID_GRANT, 'Token refresh failed');
    }

    // 保存新 Token
    if (audience) {
      await this.tokenManager.saveForAudience(
        audience,
        response.data.access_token,
        response.data.refresh_token ?? null,
        response.data.expires_in,
        response.data.scope
      );
    } else {
      await this.tokenManager.save(
        response.data.access_token,
        response.data.refresh_token ?? null,
        response.data.expires_in,
        response.data.scope
      );
    }

    this.emit('token_refreshed', response.data);
    this.log('Token refreshed', audience ? `for audience: ${audience}` : '');

    return response.data;
  }

  // ==================== Profile API（iris） ====================

  /**
   * 获取用户 Profile（从 iris /user/profile）
   * 需要 iris audience 的 token
   *
   * @param profileEndpoint iris 服务的 endpoint（如 'https://iris.example.com'）
   * @param audience iris 对应的 audience 名称（默认 'iris'）
   */
  async getProfile(
    profileEndpoint: string,
    audience: string = 'iris'
  ): Promise<ProfileResponse> {
    const token = await this.getAccessToken(audience);
    if (!token) {
      throw new AuthError(
        ErrorCodes.NOT_AUTHENTICATED,
        `Not authenticated for audience: ${audience}`
      );
    }

    const response = await this.httpClient.request<ProfileResponse>({
      method: 'GET',
      url: `${profileEndpoint}/user/profile`,
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    if (response.status !== 200) {
      throw new AuthError(
        ErrorCodes.SERVER_ERROR,
        'Failed to get user profile'
      );
    }

    return response.data;
  }

  /**
   * 更新用户 Profile（PATCH iris /user/profile）
   * 使用 JSON Merge Patch 语义
   *
   * @param profileEndpoint iris 服务的 endpoint
   * @param data 要更新的字段
   * @param audience iris 对应的 audience 名称（默认 'iris'）
   */
  async updateProfile(
    profileEndpoint: string,
    data: UpdateProfileRequest,
    audience: string = 'iris'
  ): Promise<ProfileResponse> {
    const token = await this.getAccessToken(audience);
    if (!token) {
      throw new AuthError(
        ErrorCodes.NOT_AUTHENTICATED,
        `Not authenticated for audience: ${audience}`
      );
    }

    const response = await this.httpClient.request<ProfileResponse>({
      method: 'PATCH',
      url: `${profileEndpoint}/user/profile`,
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(data),
    });

    if (response.status !== 200) {
      throw new AuthError(
        ErrorCodes.SERVER_ERROR,
        'Failed to update user profile'
      );
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

    await this.tokenManager.clearAll();
    this.emit('logout');
    this.log('Logged out');
  }

  /**
   * 检查是否已登录
   */
  async isAuthenticated(): Promise<boolean> {
    const store = await this.tokenManager.get();
    console.log('[Aegis SDK] isAuthenticated check', {
      hasAccessToken: !!store.accessToken,
      accessTokenPrefix: store.accessToken?.substring(0, 20),
      hasRefreshToken: !!store.refreshToken,
      expiresAt: store.expiresAt,
      now: Date.now(),
      debug: this.debug,
    });

    if (!store.accessToken) {
      console.log('[Aegis SDK] isAuthenticated: false (no access token)');
      return false;
    }

    // 基于 token exchange 时存储的 expires_at 判断过期，与 token 格式无关（兼容 JWT/PASETO）
    // 使用 60s buffer（仅判断是否仍可用，区别于 getAccessToken 的 5min 提前刷新）
    const isExpired = await this.tokenManager.isExpired(60 * 1000);
    if (isExpired) {
      // 如果有 refresh_token，仍然认为已登录（可以刷新）
      console.log('[Aegis SDK] isAuthenticated: token expired', {
        hasRefreshToken: !!store.refreshToken,
      });
      return !!store.refreshToken;
    }

    console.log('[Aegis SDK] isAuthenticated: true');
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
      throw new AuthError(
        ErrorCodes.SERVER_ERROR,
        'Failed to get connections'
      );
    }

    return response.data;
  }

  /**
   * 创建 Challenge（MFA/Captcha）
   */
  async createChallenge(
    req: CreateChallengeRequest
  ): Promise<CreateChallengeResponse> {
    const response = await this.httpClient.request<CreateChallengeResponse>({
      method: 'POST',
      url: `${this.config.endpoint}/api/challenge`,
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(req),
    });

    if (response.status !== 200) {
      const error = response.data as unknown as {
        error?: string;
        error_description?: string;
      };
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
   */
  async verifyChallenge(
    challengeId: string,
    req: VerifyChallengeRequest
  ): Promise<VerifyChallengeResponse> {
    const response = await this.httpClient.request<VerifyChallengeResponse>({
      method: 'PUT',
      url: `${this.config.endpoint}/api/challenge?challenge_id=${encodeURIComponent(challengeId)}`,
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(req),
    });

    if (response.status !== 200) {
      const error = response.data as unknown as {
        error?: string;
        error_description?: string;
      };
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
      const error = response.data as unknown as {
        error?: string;
        error_description?: string;
      };
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
   * 单 audience 回调处理
   */
  private async handleSingleAudienceCallback(
    code: string,
    codeVerifier: string,
    redirectUri: string | null
  ): Promise<TokenResponse> {
    const tokens = await this.exchangeToken(code, codeVerifier, redirectUri);
    this.log('handleCallback tokens received (single audience)', {
      hasAccessToken: !!tokens.access_token,
      hasRefreshToken: !!tokens.refresh_token,
      expiresIn: tokens.expires_in,
      scope: tokens.scope,
    });

    // 保存 Token
    await this.tokenManager.save(
      tokens.access_token,
      tokens.refresh_token ?? null,
      tokens.expires_in,
      tokens.scope
    );
    this.log('handleCallback tokens saved to storage');

    // 清理 audience
    this.flowState.consumeAudience();

    this.emit('login', tokens);
    this.log('Login successful');

    return tokens;
  }

  /**
   * 多 audience 回调处理
   */
  private async handleMultiAudienceCallback(
    code: string,
    codeVerifier: string,
    redirectUri: string | null,
    audiences: Record<string, AudienceScope>
  ): Promise<TokenResponse> {
    const multiTokens = await this.exchangeMultiAudienceToken(
      code,
      codeVerifier,
      redirectUri,
      audiences
    );
    this.log('handleCallback multi-audience tokens received', {
      audiences: Object.keys(multiTokens),
    });

    const audienceNames = Object.keys(multiTokens);

    // 保存 audiences 列表
    await this.tokenManager.saveAudiences(audienceNames);

    // 第一个 audience 作为默认（主）token
    let primaryTokens: TokenResponse | null = null;

    for (const [aud, tokenResp] of Object.entries(multiTokens)) {
      await this.tokenManager.saveForAudience(
        aud,
        tokenResp.access_token,
        tokenResp.refresh_token ?? null,
        tokenResp.expires_in,
        tokenResp.scope
      );

      if (!primaryTokens) {
        primaryTokens = tokenResp;
      }
    }

    // 清理 audience
    this.flowState.consumeAudience();

    this.emit('login', multiTokens);
    this.log('Login successful (multi-audience)');

    // 返回第一个 audience 的 token（向后兼容 TokenResponse 类型）
    return primaryTokens!;
  }

  /**
   * 获取指定 audience 的 access token（自动刷新）
   */
  private async getAccessTokenForAudience(
    audience: string
  ): Promise<string | null> {
    const store = await this.tokenManager.getForAudience(audience);
    this.log(`getAccessToken for audience: ${audience}`, {
      hasAccessToken: !!store.accessToken,
      hasRefreshToken: !!store.refreshToken,
    });

    if (!store.accessToken) {
      return null;
    }

    const isExpired = await this.tokenManager.isExpiredForAudience(audience);
    if (isExpired) {
      if (store.refreshToken) {
        try {
          const tokens = await this.refreshToken(
            store.refreshToken,
            audience
          );
          return tokens.access_token;
        } catch (error) {
          this.log(`Token refresh failed for audience ${audience}:`, error);
          await this.tokenManager.clearForAudience(audience);
          return null;
        }
      } else {
        await this.tokenManager.clearForAudience(audience);
        return null;
      }
    }

    return store.accessToken;
  }

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
   * 单 audience 交换 Token（form-encoded）
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

    const requestUrl = `${this.config.endpoint}/api/token`;
    this.log('exchangeToken request', {
      url: requestUrl,
      clientId: this.config.clientId,
      hasRedirectUri: !!redirectUri,
      redirectUri,
      codePrefix: code.substring(0, 8),
    });

    const response = await this.httpClient.request<TokenResponse>({
      method: 'POST',
      url: requestUrl,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: body.toString(),
    });

    this.log('exchangeToken response', {
      status: response.status,
      hasData: !!response.data,
      dataKeys: response.data ? Object.keys(response.data) : [],
    });

    if (response.status !== 200) {
      const error = response.data as unknown as {
        error?: string;
        error_description?: string;
      };
      this.log('exchangeToken failed', {
        error: error?.error,
        description: error?.error_description,
      });
      throw new AuthError(
        error?.error ?? ErrorCodes.INVALID_GRANT,
        error?.error_description ?? 'Token exchange failed'
      );
    }

    return response.data;
  }

  /**
   * 多 audience 交换 Token（JSON）
   */
  private async exchangeMultiAudienceToken(
    code: string,
    codeVerifier: string,
    redirectUri: string | null,
    audiences: Record<string, AudienceScope>
  ): Promise<MultiAudienceTokenResponse> {
    const requestBody: Record<string, unknown> = {
      grant_type: 'authorization_code',
      code,
      client_id: this.config.clientId,
      code_verifier: codeVerifier,
      audiences,
    };

    if (redirectUri) {
      requestBody.redirect_uri = redirectUri;
    }

    const requestUrl = `${this.config.endpoint}/api/token`;
    this.log('exchangeMultiAudienceToken request', {
      url: requestUrl,
      audiences: Object.keys(audiences),
      codePrefix: code.substring(0, 8),
    });

    const response =
      await this.httpClient.request<MultiAudienceTokenResponse>({
        method: 'POST',
        url: requestUrl,
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestBody),
      });

    this.log('exchangeMultiAudienceToken response', {
      status: response.status,
      audiences: response.data ? Object.keys(response.data) : [],
    });

    if (response.status !== 200) {
      const error = response.data as unknown as {
        error?: string;
        error_description?: string;
      };
      throw new AuthError(
        error?.error ?? ErrorCodes.INVALID_GRANT,
        error?.error_description ?? 'Multi-audience token exchange failed'
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
    const debug = this.debug;
    return {
      async request(config) {
        if (debug) {
          console.log('[Aegis SDK] HTTP request', {
            method: config.method,
            url: config.url,
            headers: config.headers,
          });
        }

        const response = await fetch(config.url, {
          method: config.method,
          headers: config.headers,
          body: config.body,
          credentials: 'omit',
        });

        const responseText = await response.text();
        if (debug) {
          console.log('[Aegis SDK] HTTP response', {
            status: response.status,
            statusText: response.statusText,
            contentType: response.headers.get('content-type'),
            bodyLength: responseText.length,
            bodyPreview: responseText.substring(0, 500),
          });
        }

        let data;
        try {
          data = JSON.parse(responseText);
        } catch {
          if (debug) {
            console.warn(
              '[Aegis SDK] Failed to parse response as JSON:',
              responseText.substring(0, 200)
            );
          }
          data = {};
        }

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

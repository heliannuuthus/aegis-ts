/**
 * Web 浏览器适配器
 * 为浏览器环境提供开箱即用的 Auth 支持
 */

import type {
  AuthConfig,
  AudienceScope,
  ProfileResponse,
  UpdateProfileRequest,
} from '@/types';
import { Auth } from '@core/client';
import { BrowserStorageAdapter } from '@utils/storage';

/** Web Auth 配置 */
export interface WebAuthConfig {
  /** 认证服务器地址（必填） */
  endpoint: string;
  /** 应用 Client ID（必填） */
  clientId: string;
  /** 重定向 URI（可选，不传则由 aegis-ui 处理） */
  redirectUri?: string;
  /** 默认目标服务 ID（用于 requireAuth 等便捷方法） */
  defaultAudience?: string;
  /** 默认 scope 列表（用于 requireAuth 等便捷方法） */
  defaultScopes?: string[];
  /**
   * 默认多 audience 配置（用于 token 交换）
   * 如果指定，authorize 时会自动传递，handleCallback 时用 JSON 模式换取多 token
   */
  defaultAudiences?: Record<string, AudienceScope>;
  /** Profile 服务 endpoint（iris 地址，用于 getProfile/updateProfile） */
  profileEndpoint?: string;
  /** Profile 对应的 audience 名称（默认 'iris'） */
  profileAudience?: string;
  /** 登录后的默认跳转路径 */
  defaultRedirectPath?: string;
  /** 启用调试日志 */
  debug?: boolean;
}

/**
 * 创建 Web Auth
 */
export function createWebAuth(config: WebAuthConfig): WebAuth {
  const authConfig: AuthConfig = {
    endpoint: config.endpoint,
    clientId: config.clientId,
    redirectUri: config.redirectUri,
    storage: new BrowserStorageAdapter(),
    debug: config.debug,
  };

  const auth = new Auth(authConfig);

  return new WebAuth(auth, config);
}

/**
 * Web Auth 封装
 * 提供浏览器特定的便捷 API
 */
export class WebAuth {
  private defaultRedirectPath: string;

  constructor(
    private auth: Auth,
    private config: WebAuthConfig
  ) {
    this.defaultRedirectPath = config.defaultRedirectPath ?? '/';
  }

  /**
   * 跳转到登录页面
   * 自动保存当前路径，登录回调后可通过 handleRedirectCallback 恢复
   */
  async loginWithRedirect(options: {
    audience: string;
    scopes: string[];
    state?: string;
    redirectUri?: string;
    /** 多 audience 配置（覆盖默认配置） */
    audiences?: Record<string, AudienceScope>;
    /** 登录完成后跳转的路径（不传则自动保存当前 pathname + search） */
    returnTo?: string;
  }): Promise<void> {
    // 自动保存 returnTo 路径
    const returnTo = options.returnTo ?? (window.location.pathname + window.location.search);
    await this.auth.saveReturnTo(returnTo);

    const { url } = await this.auth.authorize({
      audience: options.audience,
      scopes: options.scopes,
      state: options.state,
      redirectUri: options.redirectUri,
      audiences: options.audiences ?? this.config.defaultAudiences,
    });
    window.location.href = url;
  }

  /**
   * 处理登录回调
   * 应该在回调页面调用此方法
   */
  async handleRedirectCallback(): Promise<{
    success: boolean;
    error?: string;
    redirectTo?: string;
  }> {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const state = params.get('state');
    const error = params.get('error');
    const errorDescription = params.get('error_description');

    // 清除 URL 参数
    window.history.replaceState({}, '', window.location.pathname);

    if (error) {
      return {
        success: false,
        error: errorDescription || error,
      };
    }

    if (!code) {
      return {
        success: false,
        error: 'No authorization code found',
      };
    }

    try {
      await this.auth.handleCallback(code, state ?? undefined);

      // 从 SDK 存储中恢复 returnTo 路径（由 loginWithRedirect 保存）
      const savedPath = this.auth.consumeReturnTo();

      return {
        success: true,
        redirectTo: savedPath || this.defaultRedirectPath,
      };
    } catch (err) {
      const error = err as Error;
      return {
        success: false,
        error: error.message,
      };
    }
  }

  /**
   * 静默检查登录状态
   */
  async checkSession(): Promise<boolean> {
    return this.auth.isAuthenticated();
  }

  /**
   * 获取 Access Token（自动刷新）
   * @param audience 指定 audience，不传则返回默认 token
   */
  async getAccessToken(audience?: string): Promise<string | null> {
    return this.auth.getAccessToken(audience);
  }

  /**
   * 获取所有已存储的 audience 列表
   */
  getAudiences(): string[] {
    return this.auth.getAudiences();
  }

  /**
   * 检查 URL 是否在允许的认证域名白名单中
   */
  isAllowedUrl(url: string): boolean {
    return this.auth.isAllowedUrl(url);
  }

  // ==================== Profile API ====================

  /**
   * 获取用户 Profile（从 iris /user/profile）
   * @param endpoint 覆盖配置中的 profileEndpoint
   * @param audience 覆盖配置中的 profileAudience
   */
  async getProfile(
    endpoint?: string,
    audience?: string
  ): Promise<ProfileResponse> {
    const profileEndpoint =
      endpoint ?? this.config.profileEndpoint;
    if (!profileEndpoint) {
      throw new Error(
        'profileEndpoint is required. Provide it in config or as argument.'
      );
    }
    return this.auth.getProfile(
      profileEndpoint,
      audience ?? this.config.profileAudience ?? 'iris'
    );
  }

  /**
   * 更新用户 Profile（PATCH iris /user/profile）
   * @param data 要更新的字段
   * @param endpoint 覆盖配置中的 profileEndpoint
   * @param audience 覆盖配置中的 profileAudience
   */
  async updateProfile(
    data: UpdateProfileRequest,
    endpoint?: string,
    audience?: string
  ): Promise<ProfileResponse> {
    const profileEndpoint =
      endpoint ?? this.config.profileEndpoint;
    if (!profileEndpoint) {
      throw new Error(
        'profileEndpoint is required. Provide it in config or as argument.'
      );
    }
    return this.auth.updateProfile(
      profileEndpoint,
      data,
      audience ?? this.config.profileAudience ?? 'iris'
    );
  }

  /**
   * 登出
   */
  async logout(options?: { returnTo?: string }): Promise<void> {
    await this.auth.logout();

    if (options?.returnTo) {
      window.location.href = options.returnTo;
    }
  }

  /**
   * 检查是否已登录
   */
  async isAuthenticated(): Promise<boolean> {
    return this.auth.isAuthenticated();
  }

  /**
   * 获取当前用户的 Claims
   */
  async getClaims() {
    return this.auth.getClaims();
  }

  /**
   * 保存当前路径（用于登录后恢复）
   * 注意：loginWithRedirect 已自动保存，此方法用于手动保存场景
   */
  async saveCurrentPath(): Promise<void> {
    await this.auth.saveReturnTo(window.location.pathname + window.location.search);
  }

  /**
   * 路由守卫
   * 检查登录状态，未登录则跳转到登录页
   */
  async requireAuth(options?: {
    audience?: string;
    scopes?: string[];
    audiences?: Record<string, AudienceScope>;
  }): Promise<boolean> {
    const isAuth = await this.isAuthenticated();
    if (!isAuth) {
      const audience =
        options?.audience ?? this.config.defaultAudience;
      const scopes =
        options?.scopes ??
        this.config.defaultScopes ?? ['openid', 'profile'];

      if (!audience) {
        throw new Error(
          'audience is required. Provide it in options or set defaultAudience in config.'
        );
      }

      await this.loginWithRedirect({
        audience,
        scopes,
        audiences: options?.audiences,
      });
      return false;
    }
    return true;
  }

  /**
   * 添加事件监听
   */
  on: Auth['on'] = (...args) => this.auth.on(...args);

  /**
   * 移除事件监听
   */
  off: Auth['off'] = (...args) => this.auth.off(...args);
}

/**
 * React Hook: 创建 Auth Context 的辅助函数
 */
export function createAuthContext(auth: WebAuth) {
  return {
    auth,
    isAuthenticated: () => auth.isAuthenticated(),
    getAccessToken: (audience?: string) => auth.getAccessToken(audience),
    getAudiences: () => auth.getAudiences(),
    getProfile: (endpoint?: string, audience?: string) =>
      auth.getProfile(endpoint, audience),
    updateProfile: (
      data: UpdateProfileRequest,
      endpoint?: string,
      audience?: string
    ) => auth.updateProfile(data, endpoint, audience),
    isAllowedUrl: (url: string) => auth.isAllowedUrl(url),
    login: (options: {
      audience: string;
      scopes: string[];
      audiences?: Record<string, AudienceScope>;
    }) => auth.loginWithRedirect(options),
    logout: (returnTo?: string) => auth.logout({ returnTo }),
  };
}

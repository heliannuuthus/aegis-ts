/**
 * Web 浏览器适配器
 * 为浏览器环境提供开箱即用的 Auth 支持
 */

import type { AuthConfig } from '@/types';
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
   * 
   * @param options - 登录选项
   * @param options.audience - 目标服务 ID（必填）
   * @param options.scopes - 请求的 scope 列表（必填）
   * @param options.state - 自定义 state
   * @param options.redirectUri - 重定向 URI（覆盖默认配置）
   */
  async loginWithRedirect(options: { 
    audience: string; 
    scopes: string[];
    state?: string; 
    redirectUri?: string;
  }): Promise<void> {
    const { url } = await this.auth.authorize({
      audience: options.audience,
      scopes: options.scopes,
      state: options.state,
      redirectUri: options.redirectUri,
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

      // 尝试恢复原始路径
      const savedPath = sessionStorage.getItem('auth_redirect_path');
      if (savedPath) {
        sessionStorage.removeItem('auth_redirect_path');
      }

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
   * 如果已登录，返回 true；否则返回 false
   */
  async checkSession(): Promise<boolean> {
    return this.auth.isAuthenticated();
  }

  /**
   * 获取 Access Token（自动刷新）
   */
  async getAccessToken(): Promise<string | null> {
    return this.auth.getAccessToken();
  }

  /**
   * 获取用户信息
   */
  async getUserInfo() {
    return this.auth.getUserInfo();
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
   */
  saveCurrentPath(): void {
    sessionStorage.setItem('auth_redirect_path', window.location.pathname);
  }

  /**
   * 路由守卫
   * 检查登录状态，未登录则跳转到登录页
   * 
   * @param options - 登录选项（可选，不传则使用配置中的默认值）
   */
  async requireAuth(options?: {
    audience?: string;
    scopes?: string[];
  }): Promise<boolean> {
    const isAuth = await this.isAuthenticated();
    if (!isAuth) {
      const audience = options?.audience ?? this.config.defaultAudience;
      const scopes = options?.scopes ?? this.config.defaultScopes ?? ['openid', 'profile'];

      if (!audience) {
        throw new Error('audience is required. Provide it in options or set defaultAudience in config.');
      }

      this.saveCurrentPath();
      await this.loginWithRedirect({ audience, scopes });
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
    getAccessToken: () => auth.getAccessToken(),
    getUserInfo: () => auth.getUserInfo(),
    login: (options: { audience: string; scopes: string[] }) => 
      auth.loginWithRedirect(options),
    logout: (returnTo?: string) => auth.logout({ returnTo }),
  };
}

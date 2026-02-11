/**
 * Taro 小程序适配器
 * 为 Taro 框架提供开箱即用的 Auth 支持
 */

import type {
  StorageAdapter,
  HttpClient,
  HttpRequestConfig,
  HttpResponse,
  IDPType,
} from '@/types';
import { MiniProgramAuth, type MPLoginParams } from '@core/miniprogram';

// Taro 类型声明（避免强依赖）
interface TaroStatic {
  getStorageSync(key: string): string;
  setStorageSync(key: string, value: string): void;
  removeStorageSync(key: string): void;
  request(options: {
    url: string;
    method?: string;
    header?: Record<string, string>;
    data?: string | Record<string, unknown>;
    timeout?: number;
    success: (res: { statusCode: number; data: unknown }) => void;
    fail: (err: { errMsg: string }) => void;
  }): void;
  login(options: {
    success: (res: { code?: string; errMsg: string }) => void;
    fail: (err: { errMsg: string }) => void;
  }): void;
  getEnv(): string;
  ENV_TYPE: {
    WEAPP: string;
    TT: string;
    ALIPAY: string;
  };
}

declare const Taro: TaroStatic;

/**
 * Taro 存储适配器
 */
export class TaroStorageAdapter implements StorageAdapter {
  getItem(key: string): string | null {
    try {
      return Taro.getStorageSync(key) || null;
    } catch {
      return null;
    }
  }

  setItem(key: string, value: string): void {
    try {
      Taro.setStorageSync(key, value);
    } catch {
      console.warn('[Aegis SDK] Failed to save to Taro storage');
    }
  }

  removeItem(key: string): void {
    try {
      Taro.removeStorageSync(key);
    } catch {
      // ignore
    }
  }
}

/**
 * Taro HTTP 客户端
 */
export class TaroHttpClient implements HttpClient {
  async request<T = unknown>(config: HttpRequestConfig): Promise<HttpResponse<T>> {
    return new Promise((resolve, reject) => {
      // Taro 不支持 FormData，只处理 string 类型的 body
      const data = typeof config.body === 'string' ? config.body : undefined;
      
      Taro.request({
        url: config.url,
        method: config.method as 'GET' | 'POST' | 'PUT' | 'DELETE',
        header: config.headers,
        data,
        timeout: config.timeout ?? 10000,
        success: (res) => {
          resolve({
            status: res.statusCode,
            data: res.data as T,
          });
        },
        fail: (err) => {
          reject(new Error(err.errMsg));
        },
      });
    });
  }
}

/**
 * 检测当前平台对应的 IDP
 */
export function detectPlatformIDP(): IDPType {
  try {
    const env = Taro.getEnv();
    switch (env) {
      case Taro.ENV_TYPE.WEAPP:
        return 'wechat:mp';
      case Taro.ENV_TYPE.TT:
        return 'tt:mp';
      case Taro.ENV_TYPE.ALIPAY:
        return 'alipay:mp';
      default:
        console.warn('[Aegis SDK] Unknown platform, defaulting to wechat:mp');
        return 'wechat:mp';
    }
  } catch {
    return 'wechat:mp';
  }
}

/**
 * 获取平台登录码
 */
export function getPlatformLoginCode(): Promise<string> {
  return new Promise((resolve, reject) => {
    Taro.login({
      success: (res) => {
        if (res.code) {
          resolve(res.code);
        } else {
          reject(new Error('获取登录凭证失败'));
        }
      },
      fail: (err) => {
        reject(new Error(err.errMsg));
      },
    });
  });
}

/** Taro Auth 配置 */
export interface TaroAuthConfig {
  /** 认证服务器地址 */
  issuer: string;
  /** 自定义 IDP（默认自动检测） */
  idp?: IDPType;
  /** 启用调试日志 */
  debug?: boolean;
}

/**
 * 创建 Taro Auth
 */
export function createTaroAuth(config: TaroAuthConfig): TaroAuth {
  const idp = config.idp ?? detectPlatformIDP();

  const auth = new MiniProgramAuth({
    issuer: config.issuer,
    idp,
    storage: new TaroStorageAdapter(),
    httpClient: new TaroHttpClient(),
    debug: config.debug,
  });

  return new TaroAuth(auth, idp);
}

/**
 * Taro Auth 封装
 * 提供更便捷的 API
 */
export class TaroAuth {
  constructor(
    private auth: MiniProgramAuth,
    private idp: IDPType
  ) {}

  /**
   * 一键登录
   * 自动获取登录码并完成登录
   */
  async login(params?: { nickname?: string; avatar?: string }): Promise<void> {
    const code = await getPlatformLoginCode();
    await this.auth.login({
      code,
      nickname: params?.nickname,
      avatar: params?.avatar,
    });
  }

  /**
   * 使用自定义登录码登录
   */
  async loginWithCode(params: MPLoginParams): Promise<void> {
    await this.auth.login(params);
  }

  /**
   * 获取 Access Token
   */
  async getAccessToken(): Promise<string | null> {
    return this.auth.getAccessToken();
  }

  /**
   * 确保 Token 有效
   */
  async ensureValidToken(): Promise<string | null> {
    return this.auth.ensureValidToken();
  }

  /**
   * 获取用户信息
   */
  async getUserInfo() {
    return this.auth.getUserInfo();
  }

  /**
   * 更新用户信息
   */
  async updateUserInfo(data: { nickname?: string; avatar?: string }) {
    return this.auth.updateUserInfo(data);
  }

  /**
   * 绑定手机号
   */
  async bindPhone(phoneCode: string) {
    return this.auth.bindPhone(phoneCode);
  }

  /**
   * 登出
   */
  async logout(): Promise<void> {
    return this.auth.logout();
  }

  /**
   * 检查是否已登录
   */
  async isAuthenticated(): Promise<boolean> {
    return this.auth.isAuthenticated();
  }

  /**
   * 获取当前 IDP
   */
  getIDP(): IDPType {
    return this.idp;
  }

  /**
   * 添加事件监听
   */
  on: MiniProgramAuth['on'] = (...args) => this.auth.on(...args);

  /**
   * 移除事件监听
   */
  off: MiniProgramAuth['off'] = (...args) => this.auth.off(...args);
}

// 导出类型
export type { MPLoginParams };

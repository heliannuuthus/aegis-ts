import type {
  StorageAdapter,
  HttpClient,
  HttpRequestConfig,
  HttpResponse,
  IDPType,
} from '@/types';
import { MiniProgramAuth, type MPLoginParams } from '@core/miniprogram';

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

export class TaroStorageAdapter implements StorageAdapter {
  async getItem(key: string): Promise<string | null> {
    try { return Taro.getStorageSync(key) || null; } catch { return null; }
  }
  async setItem(key: string, value: string): Promise<void> {
    try { Taro.setStorageSync(key, value); } catch { /* noop */ }
  }
  async removeItem(key: string): Promise<void> {
    try { Taro.removeStorageSync(key); } catch { /* noop */ }
  }
}

export class TaroHttpClient implements HttpClient {
  async request<T = unknown>(config: HttpRequestConfig): Promise<HttpResponse<T>> {
    return new Promise((resolve, reject) => {
      const data = typeof config.body === 'string' ? config.body : undefined;
      Taro.request({
        url: config.url,
        method: config.method as 'GET' | 'POST' | 'PUT' | 'DELETE',
        header: config.headers,
        data,
        timeout: config.timeout ?? 10000,
        success: (res) => resolve({ status: res.statusCode, data: res.data as T }),
        fail: (err) => reject(new Error(err.errMsg)),
      });
    });
  }
}

export function detectPlatformIDP(): IDPType {
  try {
    const env = Taro.getEnv();
    switch (env) {
      case Taro.ENV_TYPE.WEAPP: return 'wechat:mp';
      case Taro.ENV_TYPE.TT: return 'tt:mp';
      case Taro.ENV_TYPE.ALIPAY: return 'alipay:mp';
      default: return 'wechat:mp';
    }
  } catch { return 'wechat:mp'; }
}

export function getPlatformLoginCode(): Promise<string> {
  return new Promise((resolve, reject) => {
    Taro.login({
      success: (res) => {
        if (res.code) resolve(res.code);
        else reject(new Error('获取登录凭证失败'));
      },
      fail: (err) => reject(new Error(err.errMsg)),
    });
  });
}

export interface TaroAuthConfig {
  issuer: string;
  idp?: IDPType;
}

export function createTaroAuth(config: TaroAuthConfig): TaroAuth {
  const idp = config.idp ?? detectPlatformIDP();
  const auth = new MiniProgramAuth({
    issuer: config.issuer,
    idp,
    storage: new TaroStorageAdapter(),
    httpClient: new TaroHttpClient(),
  });
  return new TaroAuth(auth, idp);
}

export class TaroAuth {
  constructor(
    private auth: MiniProgramAuth,
    private idp: IDPType
  ) {}

  async login(params?: { nickname?: string; avatar?: string }): Promise<void> {
    const code = await getPlatformLoginCode();
    await this.auth.login({ code, nickname: params?.nickname, avatar: params?.avatar });
  }

  async loginWithCode(params: MPLoginParams): Promise<void> {
    await this.auth.login(params);
  }

  async getAccessToken(): Promise<string | null> {
    return this.auth.getAccessToken();
  }

  async logout(): Promise<void> {
    return this.auth.logout();
  }

  async isAuthenticated(): Promise<boolean> {
    return this.auth.isAuthenticated();
  }

  getIDP(): IDPType {
    return this.idp;
  }

  on: MiniProgramAuth['on'] = (...args) => this.auth.on(...args);
  off: MiniProgramAuth['off'] = (...args) => this.auth.off(...args);
}

export type { MPLoginParams };

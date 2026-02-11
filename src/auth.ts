/**
 * 快速认证 API
 * 提供简洁的一行代码发起认证跳转
 */

import { generatePKCE } from '@utils/pkce';
import { BrowserStorageAdapter, StorageKeys } from '@utils/storage';
import type { StorageAdapter } from '@/types';

/** 快速认证配置 */
export interface AuthOptions {
  /** 认证服务器地址 */
  endpoint: string;
  /** Client ID */
  clientId: string;
  /** 目标 audience（单个或多个） */
  audience: string | string[];
  /** Scope（默认 'openid'） */
  scope?: string;
  /** 回调地址（默认当前页面） */
  redirectUri?: string;
  /** 自定义存储适配器 */
  storage?: StorageAdapter;
}

/** 认证回调结果 */
export interface AuthCallbackResult {
  /** 授权码 */
  code: string;
  /** State */
  state: string;
  /** Code Verifier（用于换取 token） */
  codeVerifier: string;
}

/**
 * 生成加密安全的 state
 */
const generateState = (): string => {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array, (byte) => byte.toString(16).padStart(2, '0')).join('');
};

/**
 * 获取默认存储适配器
 */
const getDefaultStorage = (): StorageAdapter => {
  if (typeof window !== 'undefined' && window.localStorage) {
    return new BrowserStorageAdapter();
  }
  throw new Error('No default storage available. Please provide a custom storage adapter.');
};

/**
 * 构建授权 URL
 */
const buildAuthorizeUrl = (
  endpoint: string,
  params: {
    clientId: string;
    audience: string;
    redirectUri: string;
    scope: string;
    codeChallenge: string;
    codeChallengeMethod: string;
    state: string;
  }
): string => {
  const searchParams = new URLSearchParams({
    response_type: 'code',
    client_id: params.clientId,
    audience: params.audience,
    redirect_uri: params.redirectUri,
    scope: params.scope,
    code_challenge: params.codeChallenge,
    code_challenge_method: params.codeChallengeMethod,
    state: params.state,
  });

  // 跳转到 aegis-ui 的 /authorize 页面，由 UI 发起真正的 API 请求
  return `${endpoint}/authorize?${searchParams.toString()}`;
};

/**
 * 发起认证（跳转到登录页）
 * 
 * @example
 * ```typescript
 * await auth({
 *   endpoint: 'https://auth.example.com',
 *   clientId: 'my-app',
 *   audience: 'api.example.com',
 *   scope: 'openid profile email'
 * });
 * ```
 */
export const auth = async (options: AuthOptions): Promise<void> => {
  const {
    endpoint,
    clientId,
    audience,
    scope = 'openid',
    redirectUri = window.location.href,
    storage = getDefaultStorage(),
  } = options;

  // 生成 PKCE 参数
  const pkce = await generatePKCE();

  // 生成 state
  const state = generateState();

  // 处理多个 audience
  const audienceStr = Array.isArray(audience) ? audience.join(' ') : audience;

  // 保存 code_verifier 和 state 到存储
  await Promise.all([
    Promise.resolve(storage.setItem(StorageKeys.CODE_VERIFIER, pkce.codeVerifier)),
    Promise.resolve(storage.setItem(StorageKeys.STATE, state)),
  ]);

  // 构建授权 URL
  const url = buildAuthorizeUrl(endpoint, {
    clientId,
    audience: audienceStr,
    redirectUri,
    scope,
    codeChallenge: pkce.codeChallenge,
    codeChallengeMethod: pkce.codeChallengeMethod,
    state,
  });

  // 跳转到认证页面
  window.location.href = url;
};

/**
 * 解析认证回调
 * 从 URL 中提取 code 和 state，并验证 state
 * 
 * @example
 * ```typescript
 * const result = await parseAuthCallback();
 * if (result) {
 *   // 使用 result.code 和 result.codeVerifier 换取 token
 * }
 * ```
 */
export const parseAuthCallback = async (
  options?: { storage?: StorageAdapter }
): Promise<AuthCallbackResult | null> => {
  const storage = options?.storage ?? getDefaultStorage();

  // 解析 URL 参数
  const params = new URLSearchParams(window.location.search);
  const code = params.get('code');
  const state = params.get('state');

  if (!code || !state) {
    return null;
  }

  // 获取并验证 state
  const savedState = await Promise.resolve(storage.getItem(StorageKeys.STATE));
  if (state !== savedState) {
    throw new Error('State mismatch. Possible CSRF attack.');
  }

  // 获取 code_verifier
  const codeVerifier = await Promise.resolve(storage.getItem(StorageKeys.CODE_VERIFIER));
  if (!codeVerifier) {
    throw new Error('Code verifier not found.');
  }

  // 清理存储
  await Promise.all([
    Promise.resolve(storage.removeItem(StorageKeys.STATE)),
    Promise.resolve(storage.removeItem(StorageKeys.CODE_VERIFIER)),
  ]);

  // 清理 URL 参数
  const cleanUrl = `${window.location.origin}${window.location.pathname}`;
  window.history.replaceState({}, document.title, cleanUrl);

  return {
    code,
    state,
    codeVerifier,
  };
};

/**
 * 检查当前页面是否是认证回调
 */
export const isAuthCallback = (): boolean => {
  const params = new URLSearchParams(window.location.search);
  return params.has('code') && params.has('state');
};

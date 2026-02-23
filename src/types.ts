/**
 * Aegis Auth SDK 类型定义
 */

// ==================== 基础类型 ====================

/** IDP 类型 */
export type IDPType =
  | 'wechat:mp'
  | 'tt:mp'
  | 'alipay:mp'
  | 'wechat:web'
  | 'wecom'
  | 'github'
  | 'google'
  | 'email';

/** 授权类型 */
export type GrantType = 'authorization_code' | 'refresh_token';

/** PKCE 验证方法（仅支持 S256） */
export type CodeChallengeMethod = 'S256';

// ==================== SDK 配置 ====================

/** SDK 配置 */
export interface AuthConfig {
  /** 认证服务器地址（必填） */
  endpoint: string;
  /** 应用 Client ID（必填） */
  clientId: string;
  /** 重定向 URI（可选，默认由 aegis-ui 处理） */
  redirectUri?: string;
  /** 自定义存储适配器 */
  storage?: StorageAdapter;
  /** 自定义 HTTP 客户端 */
  httpClient?: HttpClient;
  /** 启用调试日志 */
  debug?: boolean;
  /**
   * 允许跳转的认证域名白名单（可选）
   * 如果配置，authorize() 生成的 URL 会被校验，防止恶意配置篡改导致跳转到恶意地址
   * 未配置时自动从 endpoint 提取域名
   */
  allowedAuthHosts?: string[];
}

/** 授权请求选项 */
export interface AuthorizeOptions {
  /** 目标服务 ID（必填，授权阶段只能指定一个 audience） */
  audience: string;
  /** 请求的 scope 列表（必填） */
  scopes: string[];
  /** 自定义 state */
  state?: string;
  /** 重定向 URI（覆盖配置中的默认值） */
  redirectUri?: string;
  /**
   * 多 audience 配置（可选）
   * 如果指定，handleCallback 时会使用 JSON 模式请求多个 audience 的 token
   * key = audience (service_id)，value = 该 audience 的 scope 配置
   */
  audiences?: Record<string, AudienceScope>;
}

// ==================== 存储适配器 ====================

/** 存储适配器接口 */
export interface StorageAdapter {
  getItem(key: string): string | null | Promise<string | null>;
  setItem(key: string, value: string): void | Promise<void>;
  removeItem(key: string): void | Promise<void>;
}

// ==================== HTTP 客户端 ====================

/** HTTP 请求配置 */
export interface HttpRequestConfig {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  url: string;
  headers?: Record<string, string>;
  body?: string | FormData;
  timeout?: number;
}

/** HTTP 响应 */
export interface HttpResponse<T = unknown> {
  status: number;
  data: T;
  headers?: Record<string, string>;
}

/** HTTP 客户端接口 */
export interface HttpClient {
  request<T = unknown>(config: HttpRequestConfig): Promise<HttpResponse<T>>;
}

// ==================== Token 相关 ====================

/** Token 响应（单 audience） */
export interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  token_type: string;
  expires_in: number;
  scope?: string;
}

/** 多 audience token 交换请求中的单个 audience scope 配置 */
export interface AudienceScope {
  /** 该 audience 请求的 scope，默认 "openid" */
  scope?: string;
}

/** 多 audience token 交换响应：audience → TokenResponse */
export type MultiAudienceTokenResponse = Record<string, TokenResponse>;

/** Token 存储（单 audience） */
export interface TokenStore {
  accessToken: string | null;
  refreshToken: string | null;
  expiresAt: number | null;
  scope: string | null;
}

/** 多 audience Token 存储 */
export type MultiAudienceTokenStore = Record<string, TokenStore>;

/** JWT Claims */
export interface JWTClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat: number;
  scope?: string;
  openid?: string;
  [key: string]: unknown;
}

// ==================== 用户信息 ====================

/** 用户 Profile（从 iris /user/profile 获取，完整用户资料） */
export interface ProfileResponse {
  id: string;
  nickname?: string;
  picture?: string;
  email?: string;
  email_verified: boolean;
  phone?: string;
}

/** 更新 Profile 请求（JSON Merge Patch 语义，undefined = 不修改，null = 清除） */
export interface UpdateProfileRequest {
  nickname?: string | null;
  picture?: string | null;
  old_password?: string;
  password?: string | null;
}

// ==================== 授权请求 ====================

/** 授权请求参数 */
export interface AuthorizeParams {
  responseType?: 'code';
  scope?: string;
  state?: string;
  /** 额外参数 */
  [key: string]: string | undefined;
}

/** PKCE 参数 */
export interface PKCEParams {
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: CodeChallengeMethod;
}

// ==================== 小程序登录 ====================

/** 小程序登录参数 */
export interface MiniProgramLoginParams {
  /** 登录码（由平台 login API 获取） */
  code: string;
  /** IDP 类型 */
  idp: IDPType;
  /** 用户昵称（可选） */
  nickname?: string;
  /** 用户头像（可选） */
  avatar?: string;
}

/** 小程序获取手机号参数 */
export interface GetPhoneParams {
  /** 手机号授权码 */
  code: string;
  /** IDP 类型 */
  idp: IDPType;
}

// ==================== 错误 ====================

/** Auth 错误 */
export class AuthError extends Error {
  constructor(
    public code: string,
    public description?: string,
    public data?: Record<string, unknown>
  ) {
    super(description || code);
    this.name = 'AuthError';
  }
}

/** 标准错误码 */
export const ErrorCodes = {
  INVALID_REQUEST: 'invalid_request',
  UNAUTHORIZED_CLIENT: 'unauthorized_client',
  ACCESS_DENIED: 'access_denied',
  INVALID_CLIENT: 'invalid_client',
  INVALID_GRANT: 'invalid_grant',
  INVALID_TOKEN: 'invalid_token',
  SERVER_ERROR: 'server_error',
  NETWORK_ERROR: 'network_error',
  TOKEN_EXPIRED: 'token_expired',
  NOT_AUTHENTICATED: 'not_authenticated',
} as const;

// ==================== 事件 ====================

/** 事件类型 */
export type AuthEventType =
  | 'login'
  | 'logout'
  | 'token_refreshed'
  | 'token_expired'
  | 'error';

/** 事件数据 */
export interface AuthEvent {
  type: AuthEventType;
  data?: unknown;
}

/** 事件监听器 */
export type AuthEventListener = (event: AuthEvent) => void;

// ==================== Connections ====================

/** Connection 配置 */
export interface ConnectionConfig {
  connection: string;
  strategy: string[];
  identifier?: string;
  require?: RequireConfig;
  delegate?: DelegateConfig;
}

/** 前置验证要求 */
export interface RequireConfig {
  vchan: string[];
}

/** 委托验证配置 */
export interface DelegateConfig {
  mfa: string[];
}

/** VChan 配置 */
export interface VChanConfig {
  connection: string;
  strategy: string;
  identifier: string;
}

/** Connections 响应 */
export interface ConnectionsResponse {
  idp: ConnectionConfig[];
  vchan: VChanConfig[];
  mfa: string[];
}

// ==================== Challenge ====================

/** Challenge 类型 */
// VChan 类型（验证渠道，非 MFA）
// MFA 类型（多因素认证），命名规范：{channel}-{method}
export type ChallengeType = 
  | 'captcha'    // 人机验证（Turnstile）
  | 'email-otp'  // 邮箱 OTP
  | 'totp'       // TOTP 动态口令（Authenticator App）
  | 'sms-otp'    // 短信 OTP
  | 'tg-otp';    // Telegram OTP

/** 创建 Challenge 请求 */
export interface CreateChallengeRequest {
  type: ChallengeType;
  flow_id?: string;
  user_id?: string;
  email?: string;
  captcha_token?: string;
}

/** 创建 Challenge 响应 */
export interface CreateChallengeResponse {
  challenge_id: string;
  /** 有 required 时不返回 */
  type?: string;
  /** 有 required 时不返回 */
  expires_in?: number;
  data?: Record<string, unknown>;
  /** 需要先完成的前置验证（复用 VChanConfig） */
  required?: VChanConfig;
}

/** 验证 Challenge 请求 */
export interface VerifyChallengeRequest {
  /** 验证证明（captcha token / OTP code） */
  proof: string;
}

/** 验证 Challenge 响应 */
export interface VerifyChallengeResponse {
  verified: boolean;
  /** 后续 challenge ID（captcha 验证后返回原 challenge ID） */
  challenge_id?: string;
  /** 附加数据（如 masked_email, next 等） */
  data?: Record<string, unknown>;
}

// ==================== Login ====================

/** 登录请求 */
export interface LoginRequest {
  connection: string;
  data: Record<string, unknown>;
}

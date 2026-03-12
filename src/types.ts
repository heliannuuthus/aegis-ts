// ==================== 基础类型 ====================

export type IDPType =
  | 'wechat:mp'
  | 'tt:mp'
  | 'alipay:mp'
  | 'wechat:web'
  | 'wecom'
  | 'github'
  | 'google'
  | 'email';

export type GrantType = 'authorization_code' | 'refresh_token';

export type CodeChallengeMethod = 'S256';

// ==================== SDK 配置 ====================

export interface AuthConfig {
  endpoint: string;
  clientId: string;
  redirectUri?: string;
  storage?: StorageAdapter;
  httpClient?: HttpClient;
}

export interface AuthorizeOptions {
  audience?: string;
  audiences?: Record<string, AudienceScope>;
  scopes: string[];
  state?: string;
  redirectUri?: string;
}

// ==================== 存储适配器 ====================

export interface StorageAdapter {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
}

// ==================== HTTP 客户端 ====================

export interface HttpRequestConfig {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  url: string;
  headers?: Record<string, string>;
  body?: string | FormData;
  timeout?: number;
}

export interface HttpResponse<T = unknown> {
  status: number;
  data: T;
  headers?: Record<string, string>;
  /** 当响应体非 JSON 时保留原始文本，便于错误诊断 */
  rawText?: string;
}

export interface HttpClient {
  request<T = unknown>(config: HttpRequestConfig): Promise<HttpResponse<T>>;
}

// ==================== Token ====================

export interface TokenResponse {
  access_token: string;
  id_token?: string;
  refresh_token?: string;
  token_type: string;
  expires_in: number;
  scope?: string;
}

/** Result of handleCallback: tokens + returnTo path (consumed and cleared by SDK). */
export interface CallbackResult extends TokenResponse {
  returnTo: string | null;
}

export interface AudienceScope {
  scope?: string;
}

export type MultiAudienceTokenResponse = Record<string, TokenResponse>;

export interface TokenStore {
  accessToken: string | null;
  refreshToken: string | null;
}

// ==================== ID Token ====================

export interface IDTokenClaims {
  sub: string;
  iss: string;
  aud: string;
  iat: string;
  exp: string;
  nic?: string;
  pic?: string;
}

export interface PublicKeyInfo {
  version: string;
  purpose: string;
  public_key: string;
}

export interface PublicKeysResponse {
  main: PublicKeyInfo;
  keys: PublicKeyInfo[];
}

// ==================== PKCE ====================

export interface PKCEParams {
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: CodeChallengeMethod;
}

// ==================== 错误 ====================

export class AuthError extends Error {
  constructor(
    public code: string,
    public description?: string,
    public data?: Record<string, unknown>,
    public status?: number
  ) {
    super(description || code);
    this.name = 'AuthError';
  }
}

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

export type AuthEventType =
  | 'login'
  | 'logout'
  | 'token_refreshed'
  | 'token_expired'
  | 'error';

export interface AuthEvent {
  type: AuthEventType;
  data?: unknown;
}

export type AuthEventListener = (event: AuthEvent) => void;

// ==================== Connections ====================

export interface ConnectionConfig {
  connection: string;
  strategy: string[];
  identifier?: string;
  require?: RequireConfig;
  delegate?: DelegateConfig;
}

export interface RequireConfig {
  vchan: string[];
}

export interface DelegateConfig {
  mfa: string[];
}

export interface VChanConfig {
  connection: string;
  strategy: string;
  identifier: string;
}

export interface ConnectionsResponse {
  idp: ConnectionConfig[];
  vchan: VChanConfig[];
  mfa: string[];
}

// ==================== Challenge ====================

export type ChallengeType =
  | 'captcha'
  | 'email-otp'
  | 'totp'
  | 'sms-otp'
  | 'tg-otp';

export interface CreateChallengeRequest {
  type: ChallengeType;
  flow_id?: string;
  user_id?: string;
  email?: string;
  captcha_token?: string;
}

export interface CreateChallengeResponse {
  challenge_id: string;
  type?: string;
  expires_in?: number;
  data?: Record<string, unknown>;
  required?: VChanConfig;
}

export interface VerifyChallengeRequest {
  proof: string;
}

export interface VerifyChallengeResponse {
  verified: boolean;
  challenge_id?: string;
  data?: Record<string, unknown>;
}

// ==================== Login ====================

export interface LoginRequest {
  connection: string;
  data: Record<string, unknown>;
}

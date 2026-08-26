// ==================== 基础类型 ====================

export type IDPType =
  | "wechat:mp"
  | "tt:mp"
  | "alipay:mp"
  | "wechat:web"
  | "wecom"
  | "github"
  | "google"
  | "email";

export type GrantType = "authorization_code" | "refresh_token";

export type CodeChallengeMethod = "S256";

// ==================== SDK 配置 ====================

export interface AuthConfig {
  endpoint: string;
  clientId: string;
  redirectUri: string;
  storage?: StorageAdapter;
  httpClient?: HttpClient;
}

export interface AuthorizeOptions {
  audience?: string;
  audiences?: Record<string, AudienceScope>;
  scopes: string[];
  prompt?: string;
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
  method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
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
    public status?: number,
  ) {
    super(description || code);
    this.name = "AuthError";
  }
}

export const ErrorCodes = {
  INVALID_REQUEST: "invalid_request",
  UNAUTHORIZED_CLIENT: "unauthorized_client",
  ACCESS_DENIED: "access_denied",
  INVALID_CLIENT: "invalid_client",
  INVALID_GRANT: "invalid_grant",
  INVALID_TOKEN: "invalid_token",
  SERVER_ERROR: "server_error",
  NETWORK_ERROR: "network_error",
  TOKEN_EXPIRED: "token_expired",
  NOT_AUTHENTICATED: "not_authenticated",
} as const;

// ==================== 事件 ====================

export type AuthEventType =
  | "login"
  | "logout"
  | "token_refreshed"
  | "token_expired"
  | "error";

export interface AuthEvent {
  type: AuthEventType;
  data?: unknown;
}

export type AuthEventListener = (event: AuthEvent) => void;

// ==================== Connections ====================

export interface ConnectionConfig {
  connection: string;
  identifier?: string;
  strategy?: string[];
  delegate?: string[];
  require?: string[];
}

export interface ConnectionsResponse {
  idp?: ConnectionConfig[];
  vchan?: ConnectionConfig[];
  factor?: ConnectionConfig[];
}

// ==================== Challenge ====================

export type ChallengeType = string;
export type ChallengeChannelType = string;

export interface ChallengeRequiredConfig {
  identifier?: string;
  strategy?: string[];
}

export type ChallengeRequired = Record<string, ChallengeRequiredConfig>;

export interface CreateChallengeRequest {
  client_id: string;
  audience: string;
  type?: ChallengeType;
  channel_type: ChallengeChannelType;
  channel: string;
}

export interface CreateChallengeResponse {
  challenge_id?: string;
  retry_after?: number;
  required?: ChallengeRequired;
  challenge_token?: string;
  expires_in?: number;
  options?: unknown;
}

export interface VerifyChallengeRequest {
  type: string;
  strategy?: string;
  proof: unknown;
}

export interface VerifyChallengeResponse {
  verified: boolean;
  challenge_token?: string;
  required?: ChallengeRequired;
  retry_after?: number;
  expires_in?: number;
  options?: unknown;
}

// ==================== Login ====================

export interface LoginRequest {
  connection: string;
  strategy?: string;
  principal?: string;
  uid?: string;
  proof?: unknown;
}

export interface RedirectAction {
  location: string;
  actions: string[];
  params: Record<string, string>;
}

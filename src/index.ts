/**
 * @aegis/sdk
 * Aegis Auth SDK - 支持 Web 和小程序的认证 SDK
 */

// ==================== 快速认证 API ====================
export { auth, parseAuthCallback, isAuthCallback } from '@/auth';
export type { AuthOptions, AuthCallbackResult } from '@/auth';

// ==================== 核心类 ====================
export { Auth } from '@core/client';
export { MiniProgramAuth } from '@core/miniprogram';
export type { MPLoginParams, MPAuthConfig } from '@core/miniprogram';

// ==================== 类型 ====================
export type {
  AuthConfig,
  AuthorizeOptions,
  StorageAdapter,
  HttpClient,
  HttpRequestConfig,
  HttpResponse,
  TokenResponse,
  TokenStore,
  // Multi-audience
  AudienceScope,
  MultiAudienceTokenResponse,
  MultiAudienceTokenStore,
  // User
  ProfileResponse,
  UpdateProfileRequest,
  JWTClaims,
  AuthorizeParams,
  PKCEParams,
  IDPType,
  GrantType,
  CodeChallengeMethod,
  AuthEvent,
  AuthEventType,
  AuthEventListener,
  // Connections
  ConnectionConfig,
  RequireConfig,
  DelegateConfig,
  VChanConfig,
  ConnectionsResponse,
  // Challenge
  ChallengeType,
  CreateChallengeRequest,
  CreateChallengeResponse,
  VerifyChallengeRequest,
  VerifyChallengeResponse,
  // Login
  LoginRequest,
} from '@/types';

export { AuthError, ErrorCodes } from '@/types';

// ==================== 工具函数 ====================
export { generatePKCE, generateCodeVerifier, generateCodeChallenge, isValidCodeVerifier } from '@utils/pkce';
export { parseJWT, isJWTExpired, getJWTExpiresAt, getJWTScope } from '@utils/jwt';
export { BrowserStorageAdapter, MemoryStorageAdapter, TokenStorageManager, FlowStateManager, StorageKeys } from '@utils/storage';

// ==================== 命名空间导出 ====================
import { auth, parseAuthCallback, isAuthCallback } from '@/auth';
import { Auth } from '@core/client';
import { MiniProgramAuth } from '@core/miniprogram';

export const aegis = {
  auth,
  parseAuthCallback,
  isAuthCallback,
  Auth,
  MiniProgramAuth,
};

// ==================== 版本 ====================
export const VERSION = '1.0.0';

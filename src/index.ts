export { Auth } from '@core/client';
export { MiniProgramAuth } from '@core/miniprogram';
export type { MPLoginParams, MPAuthConfig } from '@core/miniprogram';

export type {
  AuthConfig,
  AuthorizeOptions,
  StorageAdapter,
  HttpClient,
  HttpRequestConfig,
  HttpResponse,
  TokenResponse,
  TokenStore,
  AudienceScope,
  MultiAudienceTokenResponse,
  MultiAudienceTokenStore,
  IDTokenClaims,
  IDPType,
  GrantType,
  PKCEParams,
  AuthEvent,
  AuthEventType,
  AuthEventListener,
  ConnectionConfig,
  RequireConfig,
  DelegateConfig,
  VChanConfig,
  ConnectionsResponse,
  ChallengeType,
  CreateChallengeRequest,
  CreateChallengeResponse,
  VerifyChallengeRequest,
  VerifyChallengeResponse,
  LoginRequest,
} from '@/types';

export { AuthError, ErrorCodes } from '@/types';

export { BrowserStorageAdapter, MemoryStorageAdapter } from '@core/storage';

export const VERSION = '1.0.0';

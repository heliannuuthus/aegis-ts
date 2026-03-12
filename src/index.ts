export { Auth } from '@core/client';

export type {
  AuthConfig,
  AuthorizeOptions,
  StorageAdapter,
  HttpClient,
  HttpRequestConfig,
  HttpResponse,
  TokenResponse,
  CallbackResult,
  TokenStore,
  AudienceScope,
  MultiAudienceTokenResponse,
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

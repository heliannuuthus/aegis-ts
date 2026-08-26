export { Auth } from "@core/client";
export { WebAuth } from "@adapters/web";

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
  ConnectionsResponse,
  ChallengeType,
  ChallengeChannelType,
  ChallengeRequiredConfig,
  ChallengeRequired,
  CreateChallengeRequest,
  CreateChallengeResponse,
  VerifyChallengeRequest,
  VerifyChallengeResponse,
  LoginRequest,
  RedirectAction,
  PublicKeyInfo,
  PublicKeysResponse,
  CodeChallengeMethod,
} from "@/types";

export type { AuthorizeParams, WebAuthConfig } from "@adapters/web";

export { AuthError, ErrorCodes } from "@/types";

export { BrowserStorageAdapter, MemoryStorageAdapter } from "@core/storage";

export const VERSION = "1.3.2";

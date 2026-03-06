import type { AudienceScope, IDTokenClaims, AuthConfig } from '@/types';
import { Auth } from '@core/client';
import { BrowserStorageAdapter } from '@core/storage';

export interface WebAuthConfig {
  endpoint: string;
  clientId: string;
  redirectUri?: string;
}

export interface AuthorizeParams {
  audience?: string;
  audiences?: Record<string, AudienceScope>;
  scopes: string[];
  redirectUri?: string;
  prompt?: string;
  state?: string;
  returnTo?: string;
}

export class WebAuth {
  private auth: Auth;
  private config: WebAuthConfig;

  constructor(config: WebAuthConfig) {
    this.config = config;
    const authConfig: AuthConfig = {
      endpoint: config.endpoint,
      clientId: config.clientId,
      redirectUri: config.redirectUri,
      storage: new BrowserStorageAdapter(),
    };
    this.auth = new Auth(authConfig);
  }

  async authorize(params: AuthorizeParams): Promise<void> {
    const returnTo = params.returnTo ?? (window.location.pathname + window.location.search);
    await this.auth.saveReturnTo(returnTo);

    const audiences = params.audiences ?? undefined;
    const audience = audiences ? undefined : params.audience;

    const { url } = await this.auth.authorize({
      audience,
      audiences,
      scopes: params.scopes,
      state: params.state,
      redirectUri: params.redirectUri ?? this.config.redirectUri,
    });
    window.location.href = url;
  }

  async handleRedirectCallback(): Promise<{
    success: boolean;
    error?: string;
    redirectTo?: string;
  }> {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const state = params.get('state');
    const error = params.get('error');
    const errorDescription = params.get('error_description');

    window.history.replaceState({}, '', window.location.pathname);

    if (error) return { success: false, error: errorDescription || error };
    if (!code) return { success: false, error: 'No authorization code found' };

    try {
      await this.auth.handleCallback(code, state ?? undefined);
      const savedPath = await this.auth.consumeReturnTo();
      return { success: true, redirectTo: savedPath || '/' };
    } catch (err) {
      return { success: false, error: (err as Error).message };
    }
  }

  async getAccessToken(audience?: string): Promise<string | null> {
    return this.auth.getAccessToken(audience);
  }

  async getUser(): Promise<IDTokenClaims | null> {
    return this.auth.getUser();
  }

  async audiences(): Promise<string[]> {
    return this.auth.audiences();
  }

  async isAuthenticated(): Promise<boolean> {
    return this.auth.isAuthenticated();
  }

  async logout(options?: { returnTo?: string }): Promise<void> {
    await this.auth.logout();
    if (options?.returnTo) window.location.href = options.returnTo;
  }

  on: Auth['on'] = (...args) => this.auth.on(...args);
  off: Auth['off'] = (...args) => this.auth.off(...args);
}

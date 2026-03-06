import type {
  StorageAdapter,
  HttpClient,
  TokenResponse,
  AuthEventType,
  AuthEventListener,
  IDPType,
} from '@/types';
import { AuthError, ErrorCodes } from '@/types';
import { EventBus } from '@core/event-bus';
import { TokenManager } from '@core/token-manager';

export interface MPLoginParams {
  code: string;
  nickname?: string;
  avatar?: string;
}

export interface MPAuthConfig {
  issuer: string;
  idp: IDPType;
  storage: StorageAdapter;
  httpClient: HttpClient;
}

export class MiniProgramAuth {
  private config: MPAuthConfig;
  private events: EventBus;
  private tokens: TokenManager;

  constructor(config: MPAuthConfig) {
    this.config = config;
    this.events = new EventBus();
    this.tokens = new TokenManager({
      storage: config.storage,
      events: this.events,
      http: config.httpClient,
      endpoint: config.issuer,
      clientId: '',
    });
  }

  async login(params: MPLoginParams): Promise<TokenResponse> {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: `${this.config.idp}:${params.code}`,
    });
    if (params.nickname) body.append('nickname', params.nickname);
    if (params.avatar) body.append('avatar', params.avatar);

    const res = await this.config.httpClient.request<TokenResponse>({
      method: 'POST',
      url: `${this.config.issuer}/api/token`,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    if (res.status !== 200) {
      const err = res.data as unknown as { error?: string; error_description?: string };
      throw new AuthError(err?.error ?? ErrorCodes.INVALID_GRANT, err?.error_description ?? 'Login failed');
    }

    await this.tokens.persist(res.data.access_token, res.data.refresh_token ?? null);
    this.events.emit('login', res.data);
    return res.data;
  }

  async getAccessToken(): Promise<string | null> {
    return this.tokens.getAccessToken();
  }

  async refreshToken(refreshToken?: string): Promise<TokenResponse> {
    return this.tokens.refreshToken(refreshToken);
  }

  async logout(): Promise<void> {
    await this.tokens.purge();
    this.events.emit('logout');
  }

  async isAuthenticated(): Promise<boolean> {
    return this.tokens.isAuthenticated();
  }

  on(event: AuthEventType, listener: AuthEventListener): () => void {
    return this.events.on(event, listener);
  }

  off(event: AuthEventType, listener: AuthEventListener): void {
    this.events.off(event, listener);
  }
}

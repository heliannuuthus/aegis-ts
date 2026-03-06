import type {
  HttpClient,
  ConnectionsResponse,
  CreateChallengeRequest,
  CreateChallengeResponse,
  VerifyChallengeRequest,
  VerifyChallengeResponse,
  LoginRequest,
} from '@/types';
import { AuthError, ErrorCodes } from '@/types';

export class API {
  constructor(
    private http: HttpClient,
    private endpoint: string,
  ) {}

  async getConnections(): Promise<ConnectionsResponse> {
    const res = await this.http.request<ConnectionsResponse>({
      method: 'GET',
      url: `${this.endpoint}/api/connections`,
      headers: { 'Content-Type': 'application/json' },
    });
    if (res.status !== 200) throw new AuthError(ErrorCodes.SERVER_ERROR, 'Failed to get connections');
    return res.data;
  }

  async createChallenge(req: CreateChallengeRequest): Promise<CreateChallengeResponse> {
    const res = await this.http.request<CreateChallengeResponse>({
      method: 'POST',
      url: `${this.endpoint}/api/challenge`,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req),
    });
    if (res.status !== 200) {
      const err = res.data as unknown as { error?: string; error_description?: string };
      throw new AuthError(err?.error ?? ErrorCodes.SERVER_ERROR, err?.error_description ?? 'Failed to create challenge');
    }
    return res.data;
  }

  async verifyChallenge(challengeId: string, req: VerifyChallengeRequest): Promise<VerifyChallengeResponse> {
    const res = await this.http.request<VerifyChallengeResponse>({
      method: 'PUT',
      url: `${this.endpoint}/api/challenge?challenge_id=${encodeURIComponent(challengeId)}`,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req),
    });
    if (res.status !== 200) {
      const err = res.data as unknown as { error?: string; error_description?: string };
      throw new AuthError(err?.error ?? ErrorCodes.SERVER_ERROR, err?.error_description ?? 'Failed to verify challenge');
    }
    return res.data;
  }

  async login(req: LoginRequest): Promise<void> {
    const res = await this.http.request({
      method: 'POST',
      url: `${this.endpoint}/api/login`,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req),
    });
    if (res.status !== 200) {
      const err = res.data as unknown as { error?: string; error_description?: string };
      throw new AuthError(err?.error ?? ErrorCodes.ACCESS_DENIED, err?.error_description ?? 'Login failed');
    }
  }

  async revokeSession(accessToken: string): Promise<void> {
    await this.http.request({
      method: 'POST',
      url: `${this.endpoint}/api/logout`,
      headers: { Authorization: `Bearer ${accessToken}` },
    });
  }
}

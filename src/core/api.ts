import type {
  HttpClient,
  ConnectionsResponse,
  CreateChallengeRequest,
  CreateChallengeResponse,
  VerifyChallengeRequest,
  VerifyChallengeResponse,
  LoginRequest,
  RedirectAction,
} from "@/types";
import { AuthError, ErrorCodes } from "@/types";

export class API {
  constructor(
    private http: HttpClient,
    private endpoint: string,
  ) {}

  async getConnections(): Promise<ConnectionsResponse> {
    const res = await this.http.request<ConnectionsResponse>({
      method: "GET",
      url: `${this.endpoint}/api/connections`,
      headers: { "Content-Type": "application/json" },
    });
    if (res.status !== 200)
      throwResponseError(
        res,
        ErrorCodes.SERVER_ERROR,
        "Failed to get connections",
      );
    return res.data;
  }

  async createChallenge(
    req: CreateChallengeRequest,
  ): Promise<CreateChallengeResponse> {
    const res = await this.http.request<CreateChallengeResponse>({
      method: "POST",
      url: `${this.endpoint}/api/challenge`,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(req),
    });
    if (res.status !== 200) {
      throwResponseError(
        res,
        ErrorCodes.SERVER_ERROR,
        "Failed to create challenge",
      );
    }
    return res.data;
  }

  async verifyChallenge(
    challengeId: string,
    req: VerifyChallengeRequest,
  ): Promise<VerifyChallengeResponse> {
    const res = await this.http.request<VerifyChallengeResponse>({
      method: "POST",
      url: `${this.endpoint}/api/challenge/${encodeURIComponent(challengeId)}`,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(req),
    });
    if (res.status !== 200) {
      throwResponseError(
        res,
        ErrorCodes.SERVER_ERROR,
        "Failed to verify challenge",
      );
    }
    return res.data;
  }

  async login(req: LoginRequest): Promise<RedirectAction> {
    const res = await this.http.request({
      method: "POST",
      url: `${this.endpoint}/api/login`,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(req),
    });
    if (res.status !== 300)
      throwResponseError(res, ErrorCodes.ACCESS_DENIED, "Login failed");
    const location = responseHeader(res.headers, "location");
    if (!location)
      throw new AuthError(
        ErrorCodes.SERVER_ERROR,
        "Login action is missing Location header",
      );
    return parseRedirectAction(location, this.endpoint);
  }

  async revokeSession(accessToken: string): Promise<void> {
    await this.http.request({
      method: "POST",
      url: `${this.endpoint}/api/logout`,
      headers: { Authorization: `Bearer ${accessToken}` },
    });
  }
}

function throwResponseError(
  response: { status: number; data: unknown },
  fallbackCode: string,
  fallbackDescription: string,
): never {
  const error = response.data as { error?: string; error_description?: string };
  throw new AuthError(
    error?.error ?? fallbackCode,
    error?.error_description ?? fallbackDescription,
    undefined,
    response.status,
  );
}

function responseHeader(
  headers: Record<string, string> | undefined,
  name: string,
): string | undefined {
  if (!headers) return undefined;
  const expected = name.toLowerCase();
  const entry = Object.entries(headers).find(
    ([key]) => key.toLowerCase() === expected,
  );
  return entry?.[1];
}

function parseRedirectAction(
  location: string,
  endpoint: string,
): RedirectAction {
  const url = new URL(location, endpoint);
  const params = Object.fromEntries(url.searchParams);
  const actions = (params.actions ?? "").split(",").filter(Boolean);
  delete params.actions;
  return { location, actions, params };
}

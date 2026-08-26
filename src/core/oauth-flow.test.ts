import { describe, expect, it } from "vitest";

import type { HttpClient } from "@/types";
import { Auth } from "./client";
import { MemoryStorageAdapter } from "./storage";

const unusedHTTP: HttpClient = {
  async request() {
    throw new Error("HTTP should not be called while building authorize URL");
  },
};

describe("OAuth authorize contract", () => {
  it("forwards prompt and PKCE parameters to the authorize endpoint", async () => {
    const auth = new Auth({
      endpoint: "https://aegis.example.com",
      clientId: "portal",
      redirectUri: "https://portal.example.com/auth/callback",
      storage: new MemoryStorageAdapter(),
      httpClient: unusedHTTP,
    });

    const { url } = await auth.authorize({
      audience: "hermes",
      scopes: ["openid", "profile"],
      prompt: "login",
    });
    const authorizeURL = new URL(url);

    expect(authorizeURL.pathname).toBe("/authorize");
    expect(authorizeURL.searchParams.get("client_id")).toBe("portal");
    expect(authorizeURL.searchParams.get("audience")).toBe("hermes");
    expect(authorizeURL.searchParams.get("scope")).toBe("openid profile");
    expect(authorizeURL.searchParams.get("prompt")).toBe("login");
    expect(authorizeURL.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authorizeURL.searchParams.get("code_challenge")).toBeTruthy();
  });
});

import { describe, expect, it } from "vitest";

import type { HttpClient, HttpRequestConfig, HttpResponse } from "@/types";
import { API } from "./api";

function stubHTTP(response: HttpResponse<unknown>) {
  const requests: HttpRequestConfig[] = [];
  const http: HttpClient = {
    async request<T>(config: HttpRequestConfig): Promise<HttpResponse<T>> {
      requests.push(config);
      return response as HttpResponse<T>;
    },
  };
  return { http, requests };
}

describe("API contract", () => {
  it("continues a challenge with POST and a path identifier", async () => {
    const { http, requests } = stubHTTP({
      status: 200,
      data: { verified: true, challenge_token: "token" },
    });
    const api = new API(http, "https://aegis.example.com");

    await api.verifyChallenge("challenge/1", {
      type: "email-code",
      proof: "123456",
    });

    expect(requests).toEqual([
      {
        method: "POST",
        url: "https://aegis.example.com/api/challenge/challenge%2F1",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type: "email-code", proof: "123456" }),
      },
    ]);
  });

  it("parses a 300 login action from the Location header", async () => {
    const { http } = stubHTTP({
      status: 300,
      data: {},
      headers: {
        Location: "/login?actions=captcha%2Cemail-code&source=password",
      },
    });
    const api = new API(http, "https://aegis.example.com");

    const result = await api.login({
      connection: "staff",
      strategy: "password",
      principal: "user@example.com",
      proof: "secret",
    });

    expect(result).toEqual({
      location: "/login?actions=captcha%2Cemail-code&source=password",
      actions: ["captcha", "email-code"],
      params: { source: "password" },
    });
  });
});

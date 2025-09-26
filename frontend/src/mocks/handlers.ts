import { http, HttpResponse } from "msw";

export const handlers = [
  http.post("http://localhost:3000/api/auth/refresh", async () => {
    return HttpResponse.json({ accessToken: "dev-access-token" });
  }),
  http.post("http://localhost:3000/api/auth/login", async () => {
    return HttpResponse.json({ accessToken: "dev-access-token" });
  }),
  http.get("http://localhost:3000/api/auth/me", async () => {
    return HttpResponse.json({ id: "user_1", role: "patient", name: "Dev User" });
  }),
  http.post("http://localhost:3000/api/auth/register", async () => {
    return HttpResponse.json({ message: "registered" });
  }),
];

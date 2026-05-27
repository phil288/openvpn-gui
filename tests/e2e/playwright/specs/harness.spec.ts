import { test, expect } from "@playwright/test";

test.describe("OpenVPN Manager test harness", () => {
  test("health endpoint responds", async ({ request }) => {
    const res = await request.get("/health");
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.status).toBe("ok");
  });

  test("build-command does not hit os scoping bug", async ({ request }) => {
    const res = await request.get("/api/build-command");
    expect(res.ok()).toBeTruthy();
    const body = await res.json();
    expect(body.ok).toBe(true);
    expect(body.error).toBeUndefined();
    expect(body.has_unix_management).toBe(true);
    expect(body.has_management_client_user).toBe(true);
    expect(body.has_auth_file).toBe(true);
    expect(body.command).not.toContain("pkexec");
    expect(
      body.command.some((part: string) => part.includes("openvpn")),
    ).toBe(true);
  });

  test("parse-ovpn extracts server metadata", async ({ request }) => {
    const res = await request.get("/api/parse-ovpn");
    const body = await res.json();
    expect(body.ok).toBe(true);
    expect(body.meta.server).toBe("vpn.example.com");
    expect(body.meta.needs_auth).toBe(true);
  });

  test("argv parser collects ovpn paths", async ({ request }) => {
    const res = await request.get("/api/argv-ovpn");
    const body = await res.json();
    expect(body.ok).toBe(true);
    expect(body.paths).toEqual(["/tmp/a.ovpn"]);
  });
});

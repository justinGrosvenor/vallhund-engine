import { describe, it, expect } from "vitest";
import { templatePath, isSensitivePath, isFileExfilPath, fileExfilFamily } from "./paths.ts";

describe("templatePath", () => {
  it("folds numeric ids", () => {
    expect(templatePath("/users/123")).toBe("/users/:id");
    expect(templatePath("/users/123/posts/456")).toBe("/users/:id/posts/:id");
  });
  it("folds uuids and long hashes", () => {
    expect(templatePath("/o/550e8400-e29b-41d4-a716-446655440000")).toBe("/o/:uuid");
    expect(templatePath("/blob/9f8e7d6c5b4a3f2e1d0c")).toBe("/blob/:hash");
  });
  it("folds hashed asset names", () => {
    expect(templatePath("/static/main.4b8c9d2e1f0a.js")).toBe("/static/:id");
  });
  it("drops the query string and trailing slash", () => {
    expect(templatePath("/search?q=hello")).toBe("/search");
    expect(templatePath("/users/123/")).toBe("/users/:id");
  });
  it("normalizes root and empty", () => {
    expect(templatePath("/")).toBe("/");
    expect(templatePath("")).toBe("/");
  });
  it("leaves ordinary words alone", () => {
    expect(templatePath("/api/v1/health")).toBe("/api/v1/health");
  });
});

describe("isSensitivePath", () => {
  it("flags auth/admin/api/account routes", () => {
    expect(isSensitivePath("/login")).toBe(true);
    expect(isSensitivePath("/admin/users")).toBe(true);
    expect(isSensitivePath("/api/users/:id")).toBe(true);
    expect(isSensitivePath("/account/billing")).toBe(true);
    expect(isSensitivePath("/oauth/token")).toBe(true);
  });
  it("does not flag ordinary content routes", () => {
    expect(isSensitivePath("/")).toBe(false);
    expect(isSensitivePath("/blog/hello-world")).toBe(false);
    expect(isSensitivePath("/static/:id")).toBe(false);
  });
});

describe("file-exfil paths", () => {
  it("recognizes secret-file probes", () => {
    expect(isFileExfilPath("/.git/config")).toBe(true);
    expect(isFileExfilPath("/.env")).toBe(true);
    expect(isFileExfilPath("/wp-config.php")).toBe(true);
    expect(isFileExfilPath("/backup.sql")).toBe(true);
    expect(isFileExfilPath("/api/users/:id")).toBe(false); // app-surface, not a file fetch
    expect(isFileExfilPath("/admin")).toBe(false);
  });

  it("groups by family so a wide-open .git stays one family", () => {
    expect(fileExfilFamily("/.git/config")).toBe(".git");
    expect(fileExfilFamily("/.git/HEAD")).toBe(".git"); // same family as /.git/config
    expect(fileExfilFamily("/.env")).toBe(".env");
    expect(fileExfilFamily("/backup.sql")).toBe(".sql");
    expect(fileExfilFamily("/admin")).toBeNull();
  });
});

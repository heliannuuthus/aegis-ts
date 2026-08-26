import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const packageJson = JSON.parse(
  readFileSync(join(root, "package.json"), "utf8"),
);
const fixture = mkdtempSync(join(tmpdir(), "aegis-ts-package-"));

try {
  const packResult = JSON.parse(
    execFileSync("npm", ["pack", "--json", "--pack-destination", fixture], {
      cwd: root,
      encoding: "utf8",
    }),
  );
  const tarball = join(fixture, packResult[0].filename);

  writeFileSync(
    join(fixture, "package.json"),
    JSON.stringify({ private: true, type: "module" }),
  );
  execFileSync("npm", ["install", "--ignore-scripts", tarball], {
    cwd: fixture,
    stdio: "pipe",
  });

  const esm = JSON.parse(
    execFileSync(
      process.execPath,
      [
        "--input-type=module",
        "--eval",
        [
          'import * as root from "@heliantheons/aegis-ts";',
          'import * as web from "@heliantheons/aegis-ts/web";',
          "console.log(JSON.stringify({ root: Object.keys(root), web: Object.keys(web), version: root.VERSION }));",
        ].join(""),
      ],
      { cwd: fixture, encoding: "utf8" },
    ),
  );
  assert.ok(esm.root.includes("Auth"));
  assert.ok(esm.root.includes("WebAuth"));
  assert.ok(esm.web.includes("WebAuth"));
  assert.equal(esm.version, packageJson.version);

  const cjs = JSON.parse(
    execFileSync(
      process.execPath,
      [
        "--input-type=commonjs",
        "--eval",
        [
          'const root = require("@heliantheons/aegis-ts");',
          'const web = require("@heliantheons/aegis-ts/web");',
          "console.log(JSON.stringify({ root: Object.keys(root), web: Object.keys(web), version: root.VERSION }));",
        ].join(""),
      ],
      { cwd: fixture, encoding: "utf8" },
    ),
  );
  assert.ok(cjs.root.includes("Auth"));
  assert.ok(cjs.root.includes("WebAuth"));
  assert.ok(cjs.web.includes("WebAuth"));
  assert.equal(cjs.version, packageJson.version);

  writeFileSync(
    join(fixture, "consumer.mts"),
    [
      'import { Auth, WebAuth, type WebAuthConfig } from "@heliantheons/aegis-ts";',
      'import { WebAuth as CompatibleWebAuth } from "@heliantheons/aegis-ts/web";',
      "const config: WebAuthConfig = { endpoint: 'https://aegis.example.com', clientId: 'portal', redirectUri: 'https://portal.example.com/callback' };",
      "void [Auth, WebAuth, CompatibleWebAuth, config];",
    ].join("\n"),
  );
  writeFileSync(
    join(fixture, "consumer.cts"),
    [
      'import SDK = require("@heliantheons/aegis-ts");',
      'import WebSDK = require("@heliantheons/aegis-ts/web");',
      "void [SDK.Auth, SDK.WebAuth, WebSDK.WebAuth];",
    ].join("\n"),
  );
  writeFileSync(
    join(fixture, "tsconfig.json"),
    JSON.stringify({
      compilerOptions: {
        module: "NodeNext",
        moduleResolution: "NodeNext",
        target: "ES2020",
        lib: ["ES2020", "DOM"],
        strict: true,
        noEmit: true,
        skipLibCheck: false,
      },
      include: ["consumer.mts", "consumer.cts"],
    }),
  );
  execFileSync(
    process.execPath,
    [
      join(root, "node_modules", "typescript", "bin", "tsc"),
      "--project",
      join(fixture, "tsconfig.json"),
    ],
    { cwd: fixture, stdio: "pipe" },
  );
} finally {
  rmSync(fixture, { recursive: true, force: true });
}

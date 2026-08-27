import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

if (process.env.CI !== "true" || process.env.GITHUB_ACTIONS !== "true") {
  throw new Error(
    "Refusing to open a vault outside an ephemeral GitHub Actions runner.",
  );
}

const binaryArgument = process.argv[2];
if (!binaryArgument) {
  throw new Error("usage: node scripts/smoke-cli.mjs <kru executable>");
}
const binary = path.resolve(binaryArgument);
assert.ok(fs.existsSync(binary), `KRU executable does not exist: ${binary}`);

const smokeRoot = fs.mkdtempSync(path.join(os.tmpdir(), "kru-cli-smoke-"));
const smokeEnv = {
  ...process.env,
  HOME: path.join(smokeRoot, "home"),
  XDG_DATA_HOME: path.join(smokeRoot, "data"),
  XDG_CONFIG_HOME: path.join(smokeRoot, "config"),
  XDG_CACHE_HOME: path.join(smokeRoot, "cache"),
  XDG_STATE_HOME: path.join(smokeRoot, "state"),
};
for (const directory of [
  smokeEnv.HOME,
  smokeEnv.XDG_DATA_HOME,
  smokeEnv.XDG_CONFIG_HOME,
  smokeEnv.XDG_CACHE_HOME,
  smokeEnv.XDG_STATE_HOME,
]) {
  fs.mkdirSync(directory, { recursive: true });
}

// dirs::data_dir honors HOME on macOS and XDG_DATA_HOME on Linux. On Windows
// it deliberately uses FOLDERID_RoamingAppData, which cannot be redirected by
// an environment variable. This script therefore only runs on GitHub's
// disposable runner and refuses to reuse any vault that was already present.
let expectedVault;
if (process.platform === "win32") {
  assert.ok(process.env.APPDATA, "GitHub Windows runner has no APPDATA");
  expectedVault = path.join(process.env.APPDATA, "mcp-vault", "v2");
} else if (process.platform === "darwin") {
  expectedVault = path.join(
    smokeEnv.HOME,
    "Library",
    "Application Support",
    "mcp-vault",
    "v2",
  );
} else {
  expectedVault = path.join(smokeEnv.XDG_DATA_HOME, "mcp-vault", "v2");
}
assert.ok(
  !fs.existsSync(expectedVault),
  `Refusing to reuse an existing vault: ${expectedVault}`,
);

function runConfig(format) {
  const result = spawnSync(binary, ["config", format], {
    encoding: "utf8",
    env: smokeEnv,
    timeout: 15_000,
    windowsHide: true,
  });
  assert.equal(result.error, undefined, `${format}: ${result.error?.message}`);
  assert.equal(result.status, 0, `${format}: ${result.stderr || result.stdout}`);
  assert.ok(result.stdout.trim(), `${format}: no stdout`);
  return result.stdout.trim();
}

function mcpSmoke() {
  return new Promise((resolve, reject) => {
    const child = spawn(binary, ["mcp", "stdio"], {
      env: smokeEnv,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    const pending = new Map();
    let completed = false;
    let settled = false;

    const timer = setTimeout(() => {
      child.kill();
      settle(new Error(`MCP smoke timed out. stderr: ${stderr.slice(-2000)}`));
    }, 15_000);

    function settle(error) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) {
        child.kill();
        reject(error);
      }
      else resolve();
    }

    function send(message) {
      child.stdin.write(`${JSON.stringify(message)}\n`);
    }

    function request(id, method, params = {}) {
      return new Promise((requestResolve, requestReject) => {
        pending.set(id, { resolve: requestResolve, reject: requestReject });
        send({ jsonrpc: "2.0", id, method, params });
      });
    }

    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
      if (stderr.length > 1_000_000) stderr = stderr.slice(-1_000_000);
    });
    child.stdin.on("error", (error) => settle(error));
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
      if (stdout.length > 2_000_000) {
        settle(new Error("MCP stdout exceeded 2 MB"));
        return;
      }
      for (;;) {
        const newline = stdout.indexOf("\n");
        if (newline < 0) break;
        const line = stdout.slice(0, newline).trim();
        stdout = stdout.slice(newline + 1);
        if (!line) continue;
        let message;
        try {
          message = JSON.parse(line);
        } catch (error) {
          settle(new Error(`MCP emitted non-JSON stdout: ${line.slice(0, 500)}`, { cause: error }));
          return;
        }
        if (message.id === undefined) continue;
        const waiter = pending.get(message.id);
        if (!waiter) continue;
        pending.delete(message.id);
        if (message.error) waiter.reject(new Error(JSON.stringify(message.error)));
        else waiter.resolve(message.result);
      }
    });
    child.on("error", (error) => settle(error));
    child.on("exit", (code, signal) => {
      if (!completed || pending.size > 0 || code !== 0) {
        settle(new Error(`MCP exited early (${code ?? signal}). stderr: ${stderr.slice(-2000)}`));
      } else {
        settle();
      }
    });

    (async () => {
      const initialized = await request(1, "initialize", {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "kru-ci-smoke", version: "1.0.0" },
      });
      assert.ok(initialized.serverInfo?.name, "initialize returned no server name");
      send({ jsonrpc: "2.0", method: "notifications/initialized", params: {} });

      const toolList = await request(2, "tools/list");
      const toolNames = toolList.tools?.map((tool) => tool.name) ?? [];
      const expectedTools = [
        "vault_items_list",
        "secret_fill",
        "terminal_open",
        "terminal_input",
        "terminal_read",
        "terminal_close",
        "ssh_execute",
        "api_request",
      ];
      for (const toolName of expectedTools) {
        assert.ok(toolNames.includes(toolName), `${toolName} is missing`);
      }

      const listResult = await request(3, "tools/call", {
        name: "vault_items_list",
        arguments: {},
      });
      assert.ok(Array.isArray(listResult.content), "vault_items_list returned no MCP content");
      assert.notEqual(listResult.isError, true, "vault_items_list returned an MCP error");
      const textBlock = listResult.content.find((block) => block.type === "text");
      assert.ok(textBlock?.text, "vault_items_list returned no text payload");
      assert.deepEqual(
        JSON.parse(textBlock.text),
        { items: [] },
        "smoke vault was not empty",
      );
      completed = true;
      child.stdin.end();
    })().catch(settle);
  });
}

try {
  const jsonConfig = JSON.parse(runConfig("stdio-json"));
  assert.deepEqual(jsonConfig.mcpServers?.kru?.args, ["mcp", "stdio"]);
  assert.ok(jsonConfig.mcpServers?.kru?.command, "stdio-json: missing command");
  const configuredBinary = path.resolve(jsonConfig.mcpServers.kru.command);
  assert.ok(fs.existsSync(configuredBinary), `configured executable does not exist: ${configuredBinary}`);
  assert.equal(
    fs.realpathSync.native(configuredBinary),
    fs.realpathSync.native(binary),
    "stdio-json points to a different executable",
  );

  const tomlConfig = runConfig("stdio-toml");
  assert.match(tomlConfig, /\[mcp_servers\.kru\]/);
  assert.match(tomlConfig, /args\s*=\s*\["mcp",\s*"stdio"\]/);

  await mcpSmoke();
  assert.ok(
    fs.existsSync(path.join(expectedVault, "vault.json")),
    `KRU did not create its vault in the expected isolated location: ${expectedVault}`,
  );
  if (process.platform === "darwin") {
    const keyFile = path.join(expectedVault, "master.key");
    assert.ok(fs.existsSync(keyFile), "macOS KRU did not create its private master-key file");
    assert.equal(fs.statSync(expectedVault).mode & 0o777, 0o700, "macOS vault directory is not mode 0700");
    assert.equal(fs.statSync(keyFile).mode & 0o777, 0o600, "macOS master-key file is not mode 0600");
  }
  console.log("KRU config and MCP stdio smoke passed.");
} finally {
  fs.rmSync(smokeRoot, { recursive: true, force: true });
}

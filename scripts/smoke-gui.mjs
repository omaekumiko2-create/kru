import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

if (process.env.CI !== "true" || process.env.GITHUB_ACTIONS !== "true") {
  throw new Error("Refusing to launch the GUI outside an ephemeral GitHub Actions runner.");
}

const executableArgument = process.argv[2];
if (!executableArgument) {
  throw new Error("usage: node scripts/smoke-gui.mjs <kru executable>");
}
const executable = path.resolve(executableArgument);
assert.ok(fs.existsSync(executable), `KRU executable does not exist: ${executable}`);

const smokeRoot = fs.mkdtempSync(path.join(os.tmpdir(), "kru-gui-smoke-"));
const env = {
  ...process.env,
  HOME: path.join(smokeRoot, "home"),
  XDG_DATA_HOME: path.join(smokeRoot, "data"),
  XDG_CONFIG_HOME: path.join(smokeRoot, "config"),
  XDG_CACHE_HOME: path.join(smokeRoot, "cache"),
  XDG_STATE_HOME: path.join(smokeRoot, "state"),
};
for (const directory of [env.HOME, env.XDG_DATA_HOME, env.XDG_CONFIG_HOME, env.XDG_CACHE_HOME, env.XDG_STATE_HOME]) {
  fs.mkdirSync(directory, { recursive: true });
}

const child = spawn(executable, [], {
  env,
  stdio: ["ignore", "pipe", "pipe"],
  windowsHide: true,
  detached: process.platform !== "win32",
});
let output = "";
for (const stream of [child.stdout, child.stderr]) {
  stream.on("data", (chunk) => {
    output = `${output}${chunk}`.slice(-4000);
  });
}

try {
  await new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, 4_000);
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("exit", (code, signal) => {
      clearTimeout(timer);
      reject(new Error(`KRU GUI exited early (${code ?? signal}). ${output}`));
    });
  });
  assert.equal(child.exitCode, null, `KRU GUI did not remain alive. ${output}`);
  console.log("KRU GUI remained alive for 4 seconds.");
} finally {
  if (process.platform === "win32" && child.pid) {
    spawnSync("taskkill", ["/pid", String(child.pid), "/t", "/f"], { stdio: "ignore" });
  } else if (child.pid) {
    try {
      process.kill(-child.pid, "SIGTERM");
    } catch (error) {
      if (error.code !== "ESRCH") throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
    try {
      process.kill(-child.pid, "SIGKILL");
    } catch (error) {
      if (error.code !== "ESRCH") throw error;
    }
  }
  fs.rmSync(smokeRoot, { recursive: true, force: true });
}

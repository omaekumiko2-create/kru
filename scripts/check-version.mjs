import fs from "node:fs";

function fail(message) {
  console.error(`version check failed: ${message}`);
  process.exit(1);
}

const packageVersion = JSON.parse(fs.readFileSync("package.json", "utf8")).version;
const packageLock = JSON.parse(fs.readFileSync("package-lock.json", "utf8"));
const packageLockVersion = packageLock.version;
const packageLockRootVersion = packageLock.packages?.[""]?.version;
const tauriVersion = JSON.parse(
  fs.readFileSync("src-tauri/tauri.conf.json", "utf8"),
).version;

const cargoLines = fs.readFileSync("src-tauri/Cargo.toml", "utf8").split(/\r?\n/);
let inPackage = false;
let cargoVersion;
for (const line of cargoLines) {
  const trimmed = line.trim();
  if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
    inPackage = trimmed === "[package]";
    continue;
  }
  if (inPackage) {
    const match = trimmed.match(/^version\s*=\s*"([^"]+)"$/);
    if (match) {
      cargoVersion = match[1];
      break;
    }
  }
}

const cargoLock = fs.readFileSync("src-tauri/Cargo.lock", "utf8");
const cargoLockVersion = cargoLock.match(
  /\[\[package\]\]\s+name = "kru"\s+version = "([^"]+)"/,
)?.[1];

const versions = {
  "package.json": packageVersion,
  "package-lock.json": packageLockVersion,
  "package-lock.json root": packageLockRootVersion,
  "Cargo.toml": cargoVersion,
  "Cargo.lock": cargoLockVersion,
  "tauri.conf.json": tauriVersion,
};
if (Object.values(versions).some((version) => !version)) {
  fail(`could not read every source version: ${JSON.stringify(versions)}`);
}
if (new Set(Object.values(versions)).size !== 1) {
  fail(Object.entries(versions).map(([file, version]) => `${file}=${version}`).join(", "));
}

const tag = process.env.GITHUB_REF?.startsWith("refs/tags/")
  ? process.env.GITHUB_REF.slice("refs/tags/".length)
  : "";
if (tag && tag !== `v${packageVersion}`) {
  fail(`tag ${tag} does not match v${packageVersion}`);
}

console.log(`KRU version ${packageVersion} is consistent${tag ? ` (${tag})` : ""}.`);

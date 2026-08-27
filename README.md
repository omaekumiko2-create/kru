<p align="center">
  <img src=".github/assets/kru-hero.svg" alt="KRU — Key Relay Unit" width="100%" />
</p>

<p align="center">
  <strong>A local MCP credential relay that keeps agent workflows moving without exposing hidden plaintext.</strong>
</p>

<p align="center">
  Local only&nbsp;&nbsp;·&nbsp;&nbsp;Free and open source&nbsp;&nbsp;·&nbsp;&nbsp;No account&nbsp;&nbsp;·&nbsp;&nbsp;Windows / macOS / Linux
</p>

<p align="center">
  <a href="../../releases/latest"><strong>Download</strong></a>
  &nbsp;&nbsp;·&nbsp;&nbsp;
  <a href="README.zh-CN.md">中文</a>
  &nbsp;&nbsp;·&nbsp;&nbsp;
  <a href="SECURITY.md">Security</a>
</p>

---

## Use KRU like this

Once KRU is connected, describe the task normally. Include the unique KRU item name for the most reliable match, or simply tell the agent to check KRU when authentication is needed.

| Goal | Example |
| --- | --- |
| **Server task** | `Use "Production Server" in KRU MCP to deploy the current build and verify the service.` |
| **Authenticated API** | `Use "DNS Provider" in KRU MCP to list the domains in this account.` |
| **Browser sign-in** | `Open the admin console. When credentials are required, use "Admin Account" in KRU MCP.` |
| **Automatic lookup** | `Continue the task. If authentication is required, check KRU first.` |

The quoted text is the item name saved in KRU. If you omit it, the agent can inspect KRU's item list and choose a match.

## What KRU does

KRU is a small local MCP tool for saving and using credentials without breaking an agent's workflow. The agent controls the task, while KRU performs the final credential operation locally—filling a focused field, authenticating an SSH session, or sending an authenticated API request.

KRU stores credentials as independent modules rather than fixed “login / SSH / API” item types. Username, password, API credential, private key, key passphrase, TOTP, host, port, URL, and custom fields can be combined in one item. The available MCP actions are derived automatically from that combination.

There is no KRU account, subscription, cloud vault, or remote MCP service. KRU is free and open source, runs on Windows, macOS, and Linux, and keeps vault data encrypted on the current device. Its local `stdio` MCP starts only when an agent calls it.

<table>
  <tr>
    <td width="33%"><strong>01 / STORE</strong><br><br>Save only the modules the item needs. Values are encrypted locally.</td>
    <td width="33%"><strong>02 / DISCOVER</strong><br><br>The agent sees item names, field names, non-secret targets, and available actions.</td>
    <td width="33%"><strong>03 / USE</strong><br><br>KRU performs the selected credential action locally without returning hidden plaintext.</td>
  </tr>
</table>

<p align="center">
  <img src=".github/assets/kru-flow.svg" alt="Agent delegates the credential step to KRU" width="100%" />
</p>

## Start in three steps

1. **Download and open KRU**
   Choose the portable build for your platform. No registration is required.

2. **Connect your agent**
   Open **Settings → Agent connection**, connect a detected client, then start a new agent session.

3. **Save an item**
   Give it a unique name and add only the modules you need. You can start from a preset or build the item module by module.

KRU registers a local `stdio` MCP command. The MCP process starts on demand when the agent calls it.

## One item, several actions

| Action | When KRU advertises it | What happens locally |
| --- | --- | --- |
| **Fill** | The item contains a credential module | KRU writes the selected value into a focused browser, desktop control, or managed terminal |
| **SSH** | Host + port + username + password/private key | KRU authenticates locally and runs the command requested by the agent |
| **HTTP** | The item contains an API credential | KRU injects authentication and sends the constrained request |
| **Terminal** | The agent opens a managed terminal | KRU can write a selected secret without returning it to the agent |

An item may advertise more than one action. KRU has no observation, diagnostic, restricted, or execution mode: if `ssh_execute` is available, the agent sends the command the task actually requires.

## Plaintext visibility is per module

Every module has its own Agent visibility switch:

- **Hidden** — the default for credential modules. KRU can use the value, but it is not included in MCP responses.
- **Visible** — the value may be returned to the agent only after you explicitly enable the switch.
- **TOTP** — KRU derives the current six-digit code; the permanent seed is never returned.

The eye and copy controls in the editor are for the local owner. The optional six-digit PIN locks plaintext viewing in the GUI; it does not replace vault encryption and does not disable MCP actions.

## Built for local use

<table>
  <tr>
    <td width="33%"><strong>Encrypted vault</strong><br><br>XChaCha20-Poly1305 protects stored fields. The machine key stays local.</td>
    <td width="33%"><strong>Portable backup</strong><br><br>Export an encrypted <code>.mvault</code> package and import it on another device.</td>
    <td width="33%"><strong>Auditable</strong><br><br>Local activity records show which client requested which action without logging secret values.</td>
  </tr>
</table>

## Browser, SSH, and API behavior

### Browser filling

Reliable unattended browser filling uses the bundled Chromium extension. KRU writes one selected field into the currently focused control; it does not inspect the page, choose a field, click submit, or export cookies. Chrome, Edge, and Brave require one manual extension load on first use.

### SSH

KRU supports password and private-key authentication. The server fingerprint is recorded on first connection and must be explicitly reset if the host identity changes. Authentication plaintext is not returned to the agent.

### HTTP APIs

KRU recognizes common API providers and falls back to Bearer Token when no provider matches. A saved service URL locks requests to the same origin. Without one, the agent must provide an absolute HTTPS URL; plain HTTP is allowed only for loopback addresses.

## Local app controls

The Settings page includes:

- desktop shortcut (where supported) and launch-at-login controls;
- close-to-tray or quit behavior;
- optional six-digit local PIN;
- Agent connection and repair;
- Browser Bridge pairing;
- encrypted backup import/export and direct access to the local data folder.

Replacing or upgrading the executable does not remove your vault. KRU intentionally reuses the current OS user's data directory:

| Platform | Vault location |
| --- | --- |
| Windows | `%APPDATA%\mcp-vault\v2` |
| macOS | `~/Library/Application Support/mcp-vault/v2` |
| Linux | `${XDG_DATA_HOME:-~/.local/share}/mcp-vault/v2` |

Exported `.mvault` packages are encrypted and portable, but they contain their own unlock material for easy import. Protect a backup file as carefully as the original credentials.

## Downloads

| Target | Package | Notes |
| --- | --- | --- |
| Windows x64 | `.zip` | Portable GUI, tray, desktop input, and browser extension |
| macOS arm64 | `.zip` | Native `.app`; Accessibility permission is required for desktop input |
| Linux x64 GUI | `.tar.gz` | AppImage GUI; desktop input supports X11 |
| Linux x64 headless | `.tar.gz` | No WebView dependency; MCP, SSH, HTTP, terminal, backup, and browser bridge |

<p align="center">
  <a href="../../releases/latest"><strong>OPEN LATEST RELEASE →</strong></a>
</p>

<details>
  <summary>Watch the short product demo</summary>
  <p><a href="https://www.youtube.com/watch?v=GKQLEgAdbTU">KRU demo on YouTube →</a></p>
</details>

## MCP surface

KRU's server instructions use one consistent workflow: discover credentials with `vault_items_list`, pass the known item name as `query`, and call only an action advertised by that item. Hidden plaintext must never be requested from the user, and KRU has no invented observation, diagnostic, or execution modes.

| Tool | Purpose | MCP impact hint |
| --- | --- | --- |
| `vault_items_list(query?)` | Find usable items, modules, targets, and actions | Read-only, idempotent, local |
| `secret_fill` | Write one saved value into an approved local target | Changes local state |
| `ssh_execute` | Run the requested command through a stored SSH identity | External effects possible |
| `api_request` | Send an authenticated, policy-checked HTTP request | External effects possible |
| `terminal_open` | Start a managed local process | Changes local state |
| `terminal_input` | Write ordinary input or a selected saved value | External effects possible |
| `terminal_read` | Read redacted managed-terminal output | Read-only, idempotent, local |
| `terminal_close` | Close a managed terminal session | Idempotent state change |

With no `query`, `vault_items_list` returns all usable items. With one, an exact case-insensitive name match wins; otherwise KRU returns names containing the query. This keeps unrelated credential metadata out of the Agent context when the item is already known.

Every successful tool call returns both typed `structuredContent` and equivalent JSON text for older MCP clients. Business failures return an MCP tool result with `isError=true`; malformed protocol input remains a protocol error. Tool annotations help clients describe impact, but all real security restrictions are enforced by KRU's backend.

There is no unrestricted `get_secret` tool. `vault_items_list` returns item and module metadata, non-secret target information, and derived actions. A credential value is included only when its Agent visibility switch is on.

Manual `stdio` configuration:

```json
{
  "mcpServers": {
    "kru": {
      "command": "C:\\absolute\\path\\to\\kru.exe",
      "args": ["mcp", "stdio"]
    }
  }
}
```

KRU can also print client-ready configuration:

```text
kru config stdio-json
kru config stdio-toml
```

## Security model

KRU is designed to keep hidden values out of normal MCP parameters, responses, activity records, application logs, and LLM API traffic. The KRU process and the final target necessarily handle plaintext briefly while an action runs.

KRU is not a sandbox. It does not defend against a malicious agent, a compromised machine or browser, or another process running as the same OS user. It cannot determine whether the agent focused the correct input or chose a trustworthy target. Read the complete [security policy and threat boundary](SECURITY.md) before relying on KRU for sensitive infrastructure.

## Build from source

Requirements: Rust 1.88+, Node.js 22+, and the [Tauri 2 platform prerequisites](https://v2.tauri.app/start/prerequisites/).

```bash
npm install
npm run check
npm test
npm run build
npm run portable
```

Additional release targets:

```bash
npm run release:mac
npm run release:linux
npm run release:headless
```

## License

[MIT](LICENSE) — use it, inspect it, and improve it.

# Security

KRU is a local credential execution tool exposed through stdio MCP. Its primary goal is to let an Agent complete authentication without placing hidden credential plaintext in ordinary MCP arguments or responses.

## Security goals

- Vault secrets are encrypted at rest with authenticated encryption.
- Modules that are not marked `agentVisible` do not return plaintext through `items_search`.
- Hidden values can be used locally by `credential_fill`, `ssh_run`, `ssh_upload`, `ssh_download`, and `http_send`.
- Known stored credentials are redacted from activity errors, terminal output, SSH output, and API responses where KRU can identify them.
- Saved API targets stay on their stored Origin; same-origin redirects are allowed, and KRU-controlled authentication headers cannot be replaced by the caller.

## Explicitly agent-visible values

The per-module **Agent visible** switch is a disclosure decision. When it is enabled, `items_search` includes that module's `value`, and the value may enter the Agent's context and its model provider's logs. For a visible TOTP module, KRU returns only the current six-digit code, never the permanent TOTP seed.

Do not enable Agent visibility for a value that must remain outside the Agent context. This switch is separate from whether the module may be used by KRU for fill, SSH, or API actions.

## What KRU does not protect against

KRU is not a sandbox, policy engine, DLP system, or authorization server. It does not defend against:

- a malicious or compromised Agent;
- another process running as the same operating-system user;
- a compromised browser, extension, terminal, remote host, or operating system;
- an Agent focusing the wrong desktop or browser control;
- sensitive data newly produced by a command or remote service;
- a task whose requested destination or operation is itself unsafe.

MCP tool annotations are descriptive hints. KRU enforces its actual restrictions in the Rust backend and never treats annotations or prompt instructions as authorization.

## Action boundaries

### Browser and desktop fill

`credential_fill` writes one value to the currently focused control. When the caller sets `submit=true`, KRU also submits the focused browser form or presses Enter in a desktop or managed-terminal target. Desktop fill depends on the real operating-system foreground focus; background DOM focus is not sufficient. KRU cannot prove that the focused destination is trustworthy.

### Managed terminal

KRU starts the requested program or native Windows script and does not add a policy shell. The child inherits KRU's normal user environment so installed tools behave as they do for the user. Ordinary terminal input can execute commands in an interactive program and may affect local or external systems. Redaction covers values filled by KRU and common encodings of those values, not environment variables or every secret a process may print.

### SSH

An item advertising SSH actions grants the Agent full command execution and SFTP file-transfer access through that stored SSH identity. Upload and download paths are selected by the Agent for the user's task, and existing destination files are replaced by default. KRU has no observation, diagnostic, restricted, or execution mode. It does not pin or compare SSH host fingerprints; the stored host and port are the destination selected by the user.

### API requests

When an item stores a service URL, KRU restricts requests to the same Origin; the caller can omit the URL, use a relative path, and choose the method needed for the task. When no service URL is stored, the Agent may supply any absolute HTTPS URL; HTTP is allowed only for loopback addresses. This means an addressless API item permits the Agent to choose which HTTPS service receives the hidden credential. Store a service URL when the credential must be bound to one Origin.

KRU follows redirects only while they stay on the same permitted Origin. The configured authentication header or query parameter is injected last and replaces a caller value with the same name. Set-Cookie is excluded from returned response headers, but ordinary request and response headers are preserved. Activity records include the HTTP method, Origin, and path without the query string. Known stored secrets are redacted before the activity is saved.

`http_send` can upload local files or save a response to a local file when the caller supplies a path. The saved Origin restriction still applies, but KRU does not independently decide whether a user-requested local file is appropriate to send or where an explicitly requested response should be stored. Existing response files are replaced by default; the caller can explicitly disable replacement.

## Local data and backups

The vault and master-key files remain in the current user's application-data directory. PIN protects casual GUI viewing; it is not a separate encryption key and does not stop another process running as the same user.

`.mvault` backups are self-contained authenticated-encryption packages that KRU unlocks automatically. They prevent accidental plaintext reading and detect modification, but they are not access-controlled. Anyone who obtains a backup can decode it with KRU or another format-aware tool. Protect backup files as if they contained plaintext secrets.

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub Security Advisories. Do not include real credentials, vault files, backups, master-key files, API responses, terminal output, or sensitive local paths.

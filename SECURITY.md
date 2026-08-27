# Security

KRU is a local credential execution tool exposed through stdio MCP. Its primary goal is to let an Agent complete authentication without placing hidden credential plaintext in ordinary MCP arguments or responses.

## Security goals

- Vault secrets are encrypted at rest with authenticated encryption.
- Modules that are not marked `agentVisible` do not return plaintext through `items_search`.
- Hidden values can be used locally by `credential_fill`, `ssh_run`, and `http_send`.
- Known stored credentials are redacted from activity errors, terminal output, SSH output, and API responses where KRU can identify them.
- API redirects and caller-supplied authentication, cookie, proxy-authentication, and host headers are blocked.

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

`credential_fill` writes one value and never submits it. The paired browser extension writes only to the currently focused control. Desktop fill depends on the real operating-system foreground focus; background DOM focus is not sufficient. KRU cannot prove that the focused destination is trustworthy.

### Managed terminal

KRU starts the requested program directly and does not insert a shell. Ordinary terminal input can still execute commands in an interactive program and may affect local or external systems. Redaction covers values filled by KRU and common encodings of those values, not every secret a process may print.

### SSH

An item advertising `ssh_run` grants the Agent full command execution through that stored SSH identity. KRU has no observation, diagnostic, restricted, or execution mode. Host fingerprints are bound to their host and port, but users must still review unexpected host-key changes.

### API requests

When an item stores a service URL, KRU restricts requests to the same Origin and applies its configured method and path rules. When no service URL is stored, the Agent may supply any absolute HTTPS URL; HTTP is allowed only for loopback addresses. This means an addressless API item permits the Agent to choose which HTTPS service receives the hidden credential. Store a service URL when the credential must be bound to one Origin.

KRU disables redirects and ignores caller-supplied sensitive authentication headers. Activity records include the HTTP method, Origin, and path without the query string. Known stored secrets are redacted before the activity is saved.

## Local data and backups

The vault and master-key files remain in the current user's application-data directory. PIN protects casual GUI viewing; it is not a separate encryption key and does not stop another process running as the same user.

`.mvault` backups are self-contained authenticated-encryption packages that KRU unlocks automatically. They prevent accidental plaintext reading and detect modification, but they are not access-controlled. Anyone who obtains a backup can decode it with KRU or another format-aware tool. Protect backup files as if they contained plaintext secrets.

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub Security Advisories. Do not include real credentials, vault files, backups, master-key files, API responses, terminal output, or sensitive local paths.

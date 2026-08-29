# Security

KRU is a local credential execution tool exposed through stdio MCP. Its primary goal is to let an Agent complete authentication without placing hidden credential plaintext in ordinary MCP arguments or responses.

## Security goals

- Vault secrets are encrypted at rest with authenticated encryption.
- Modules that are not marked `agentVisible` do not return plaintext through `items_search`.
- Hidden values can be used locally by `credential_fill`, `ssh_run`, `ssh_upload`, `ssh_download`, and `http_send`.
- Known stored credentials are redacted from activity errors, terminal output, SSH output, and API responses where KRU can identify them.
- KRU-controlled authentication headers cannot be replaced by the caller; saved service URLs are defaults rather than authorization boundaries.

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

KRU remembers the most recently selected compatible project and the current managed terminal within each stdio MCP session. A unique `items_search` result or any explicit item selects the project, allowing later fill, SSH, transfer, HTTP, and terminal actions to omit the repeated name. `terminal_start`, or explicitly using another terminal ID, selects the current terminal so later write, read, fill, and stop calls can omit the repeated UUID. A PTY also keeps its own project binding until it ends. This is conversational convenience state, not an authorization boundary; ended terminals and disabled, deleted, or incompatible projects are ignored automatically.

KRU does not add a policy shell. `terminal_run` executes an ordinary one-shot local shell command, while `terminal_start` opens the requested program or native Windows script when an interactive process is needed. Children inherit KRU's normal user environment so installed tools behave as they do for the user. `terminal_run` can write caller-provided text directly to standard input, avoiding shell interpolation and temporary files. It and `terminal_start` can substitute `{{kru:module}}` placeholders in commands or working directories; one-shot stdin, PTY arguments, and later `terminal_write` input support the same local substitution, and `secretEnv` can inject selected modules into a child environment. `terminal_write` may press Enter and `terminal_read` may wait for a requested marker without a KRU deadline unless the caller supplies one. Those values and common encodings are redacted from returned output. Local commands and ordinary terminal input may affect local or external systems. Redaction covers values filled or injected by KRU, not unrelated environment variables or every secret a process may print.

### SSH

An item with a saved password or private key can grant the Agent full SSH command execution and recursive SFTP file-or-directory transfer. Host, port, and username may be saved as defaults or supplied by the Agent for the current call; port 22 is used when neither source provides a port. `ssh_run` can write caller-provided text directly to the remote process's standard input and substitute `{{kru:module}}` placeholders in that input, its command, or working directory. `secretEnv` can inject additional stored modules into the remote environment. KRU redacts those values from returned output. Upload and download paths are selected by the Agent for the user's task, and existing destinations are replaced by default after a complete temporary copy has been prepared, including file-to-directory and directory-to-file changes. KRU has no observation, diagnostic, restricted, or execution mode. It does not pin or compare SSH host fingerprints; using an SSH credential delegates selection of the runtime destination to the Agent.

### API requests

Any enabled item with a configured secret can be used as an HTTP request context. When an item stores a service URL, the caller may omit the request URL to use it, pass a relative path, or provide another absolute HTTP/HTTPS URL. Without a saved URL, the Agent supplies an absolute HTTP/HTTPS URL. The saved URL is a convenience, not an Origin allowlist: using an item for HTTP delegates selection of the request destination to the Agent.

For authentication schemes not covered by the built-in API credential or Basic combinations, placeholders such as `{{kru:password}}` or `{{kru:service token}}` resolve the named module directly and are substituted locally in URL, header, query, JSON/text body, or form values. `http_send.secretBindings` is only an optional alias map when the placeholder name differs from the module. The resolved value is added to response and activity redaction without being returned to the caller; TOTP bindings use the current code rather than the stored seed.

KRU follows HTTP/HTTPS redirects, including redirects to another Origin, until the service stops redirecting or the caller's optional timeout is reached. The caller may send ordinary headers, cookies, `Host`, or its own authorization values; only headers KRU injects for the saved credential remain controlled by KRU. Response headers and bodies are not classified by field name: only secret values already known to KRU are redacted, so new cookies, credentials, or other sensitive data returned by a service can enter Agent context. Activity records include the HTTP method, Origin, and path without the query string. Known stored secrets are redacted before the activity is saved.

`http_send` can upload local files or save a response to a local file when the caller supplies a path. KRU does not independently decide whether a user-requested local file is appropriate to send, which HTTP/HTTPS destination should receive it, or where an explicitly requested response should be stored. Existing response files are replaced by default; the caller can explicitly disable replacement.

## Local data and backups

The vault and master-key files remain in the current user's application-data directory. PIN protects casual GUI viewing; it is not a separate encryption key and does not stop another process running as the same user.

`.mvault` backups are self-contained authenticated-encryption packages that KRU unlocks automatically. They prevent accidental plaintext reading and detect modification, but they are not access-controlled. Anyone who obtains a backup can decode it with KRU or another format-aware tool. Protect backup files as if they contained plaintext secrets.

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub Security Advisories. Do not include real credentials, vault files, backups, master-key files, API responses, terminal output, or sensitive local paths.

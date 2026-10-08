# 安全说明

[English](SECURITY.md) · **简体中文**

KRU 是通过 stdio MCP 提供的本地凭据执行工具。它的主要目标是让 Agent 完成认证，同时避免把隐藏凭据明文放入普通 MCP 参数或响应。

## 安全目标

- Vault 秘密使用经过认证的加密方式静态存储。
- 未标记 `agentVisible` 的模块不会通过 `items_search` 返回明文。
- `credential_fill`、`ssh_run`、`ssh_upload`、`ssh_download` 和 `http_send` 可在本地使用隐藏值。
- 对 KRU 能识别的已存凭据，在活动错误、终端输出、SSH 输出和 API 响应中进行脱敏。
- 调用方不能替换 KRU 控制的认证头；保存的服务 URL 是默认值，不是授权边界。

## 明确对 Agent 可见的值

每个模块的 **Agent visible** 开关是一项披露决定。启用后，`items_search` 包含该模块的 `value`，此值可能进入 Agent 上下文及模型提供方日志。TOTP 模块可见时，KRU 只返回当前六位验证码，绝不返回永久 TOTP 种子。

需要留在 Agent 上下文之外的值，不应启用 Agent 可见性。该开关与模块能否被 KRU 用于填写、SSH 或 API 操作是独立的。

## KRU 不防御的情况

KRU 不是沙箱、策略引擎、DLP 系统或授权服务器，不能防御：

- 恶意或已被攻破的 Agent；
- 以同一操作系统用户身份运行的其他进程；
- 已被攻破的浏览器、扩展、终端、远端主机或操作系统；
- Agent 聚焦了错误的桌面/浏览器控件；
- 命令或远端服务新产生的敏感数据；
- 所请求目标或操作本身不安全的任务。

MCP 工具注解只是描述性提示。KRU 在 Rust 后端执行实际限制，绝不把注解或提示词指令当作授权。

## 操作边界

### 浏览器与桌面填写

`credential_fill` 向当前聚焦控件写入一个值。调用方设置 `submit=true` 时，KRU 还会提交聚焦浏览器表单，或在桌面/托管终端目标按 Enter。桌面填写依赖真实操作系统前台焦点，仅有后台 DOM 焦点不够。KRU 无法证明当前聚焦目标可信。

### 托管终端

每个 stdio MCP 会话中，KRU 记住最近选择的兼容项目和当前托管终端。唯一的 `items_search` 结果或明确指定的 item 会选中项目，后续填写、SSH、传输、HTTP 和终端操作可省略重复名称。`terminal_start` 或明确使用另一终端 ID 会选中当前终端，后续 write、read、fill、stop 可省略重复 UUID。PTY 也保留自己的项目绑定直到结束。这是对话便利状态，不是授权边界；已结束终端及被禁用、删除或不兼容项目会自动忽略。

KRU 不添加策略 shell。`terminal_run` 执行普通单次本地 shell 命令；需要交互进程时，`terminal_start` 打开所请求程序或原生 Windows 脚本。子进程继承 KRU 的普通用户环境，使已安装工具保持用户原有行为。`terminal_run` 可把调用方文本直接写入标准输入，避免 shell 插值和临时文件。它和 `terminal_start` 可在命令或工作目录中替换 `{{kru:module}}`；单次 stdin、PTY 参数及后续 `terminal_write` 也支持相同的本地替换，`secretEnv` 可把选定模块注入子进程环境。`terminal_write` 可按 Enter；除非调用方指定截止时间，`terminal_read` 可等待目标标记而不受 KRU 截止时间限制。这些值及常见编码会从返回输出中脱敏。本地命令和普通终端输入可能影响本地或外部系统。脱敏覆盖 KRU 填写或注入的值，不覆盖无关环境变量或进程可能打印的每一种秘密。

### SSH

保存了密码或私钥的 item 可授予 Agent 完整 SSH 命令执行和递归 SFTP 文件/目录传输能力。主机、端口和用户名可保存为默认值，也可由 Agent 在当前调用指定；两种来源均无端口时使用 22。`ssh_run` 可将调用方文本直接写入远端进程标准输入，并在 stdin、命令或工作目录中替换 `{{kru:module}}`。`secretEnv` 可向远端环境注入其他已存模块。KRU 会从返回输出中脱敏这些值。Agent 按用户任务选择上传/下载路径；默认在准备好完整临时副本后替换现有目标，包括文件转目录或目录转文件。KRU 没有 observation、diagnostic、restricted 或 execution 模式，也不固定或比较 SSH 主机指纹；使用 SSH 凭据即把本次运行目标的选择交给 Agent。

### API 请求

任何启用且配置了秘密的 item 都可用作 HTTP 请求上下文。保存服务 URL 时，调用方可省略请求 URL 使用该值，提供相对路径，或指定其他绝对 HTTP/HTTPS URL。没有保存 URL 时，由 Agent 提供绝对 HTTP/HTTPS URL。保存 URL 是便利设置，不是 Origin 允许列表；使用 item 发起 HTTP 即把请求目标选择交给 Agent。

对于内置 API 凭据或 Basic 组合未覆盖的认证方式，`{{kru:password}}` 或 `{{kru:service token}}` 等占位符直接解析所指模块，在 URL、header、query、JSON/文本 body 或 form 值中本地替换。`http_send.secretBindings` 仅在占位符名与模块名不同时作为可选别名映射。解析值加入响应和活动脱敏，不返回给调用方；TOTP 绑定使用当前验证码，而非保存的种子。

KRU 跟随 HTTP/HTTPS 重定向，包括跨 Origin 重定向，直到服务停止重定向或达到调用方可选超时。调用方可发送普通 header、cookie、`Host` 或自己的认证值；只有 KRU 为已存凭据注入的 header 受 KRU 控制。响应头和响应体不按字段名分类，仅脱敏 KRU 已知秘密值，因此服务新返回的 cookie、凭据或其他敏感数据可能进入 Agent 上下文。活动记录包含 HTTP 方法、Origin 和不含 query 的路径，已知已存秘密在保存活动前脱敏。

调用方提供路径时，`http_send` 可上传本地文件或把响应保存到本地。KRU 不独立判断用户请求的本地文件是否适合发送、应发送给哪个 HTTP/HTTPS 目标，或明确请求的响应应存在哪里。默认替换现有响应文件，调用方可明确关闭替换。

## 本地数据与备份

Vault 和主密钥文件保存在当前用户的应用数据目录。PIN 用于防止随意查看 GUI，不是独立加密密钥，也不能阻止以同一用户身份运行的其他进程。

`.mvault` 备份是 KRU 可自动解锁的自包含认证加密包，能够防止意外明文读取并检测修改，但不具备访问控制。任何取得备份的人都可通过 KRU 或其他了解格式的工具解码。应按包含明文秘密的文件保护备份。

## 漏洞报告

通过 GitHub Security Advisories 私密报告疑似漏洞。不要包含真实凭据、Vault 文件、备份、主密钥文件、API 响应、终端输出或敏感本地路径。

# Local TOTP CLI

面向 Windows、macOS 和 Linux 的离线 TOTP 命令行工具。读取本地 PNG/JPEG 二维码截图，将密钥存入操作系统凭据库，按系统时间生成验证码。

## 平台与存储

| 平台 | 密钥存储 | 运行条件 |
| --- | --- | --- |
| Windows 10/11 | Windows Credential Manager，当前用户、当前机器 | Python 3.10–3.14，优先 64 位；PowerShell 或 CMD |
| macOS | macOS Keychain | Python 3.10–3.14，已解锁的登录钥匙串 |
| Linux | Secret Service，例如 GNOME Keyring | Python 3.10–3.14，运行中的用户 D-Bus 会话及已解锁的 Secret Service |

同一套 Python 源码用于全部平台。Windows 不需要 WSL、Bash、OpenCV 或额外安装 ZBar。WSL 按 Linux 处理，不能直接使用本工具的 Windows 凭据库。无桌面的 Linux 主机需要自行提供 Secret Service；本工具没有明文存储回退。

## Windows 快速开始

将源码解压到 Windows，在包含 `pyproject.toml` 的目录打开 PowerShell。安装 Python 3.10–3.14 后执行：

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements.lock
.\.venv\Scripts\python.exe -m pip install --no-deps .
.\.venv\Scripts\totp.exe --help

.\.venv\Scripts\totp.exe add work --qr "C:\Users\Alice\Pictures\enrollment.png"
.\.venv\Scripts\totp.exe list
.\.venv\Scripts\totp.exe code work
.\.venv\Scripts\totp.exe code work --watch
```

这些命令也可在 CMD 中运行，不需要激活虚拟环境或修改 PowerShell 执行策略。`py` 不存在时，可替换为已安装的 Python 可执行文件。图片路径支持空格及中文。

如果已安装 `uv`，可在源码目录执行：

```powershell
uv sync --locked --no-dev
uv run --no-sync totp add work --qr "C:\Users\Alice\Pictures\enrollment.png"
uv run --no-sync totp code work
```

项目没有发布到 PyPI。安装源是此源码目录，或本地构建的 wheel；不要假设存在同名公开安装包。

## macOS / Linux 安装

在源码目录执行：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.lock
.venv/bin/python -m pip install --no-deps .
.venv/bin/totp add work --qr "/absolute/path/enrollment.png"
.venv/bin/totp code work
```

安装依赖需要网络；安装完成后的二维码导入、密钥读取及验证码生成均在本机运行。

## 命令

| 命令 | 行为 |
| --- | --- |
| `totp add NAME --qr PATH` | 导入一个标准 TOTP 二维码；同名账户不覆盖 |
| `totp list` | 显示别名、发行方、账户及算法参数；不读取密钥 |
| `totp list --json` | 输出不含密钥的账户元数据 JSON |
| `totp code NAME` | 标准输出只包含验证码及换行，保留前导零 |
| `totp code NAME --watch` | 同一行刷新验证码及倒计时，Ctrl+C 退出；需要交互终端 |
| `totp remove NAME` | 删除本机凭据及索引，不改变网站的 2FA 设置 |
| `totp doctor` | 显示当前平台、凭据后端、索引路径及账户数量 |
| `totp --data-dir PATH COMMAND` | 指定非敏感索引目录；密钥仍保存在系统凭据库 |

别名支持字母、数字、中文、点、下划线和连字符，最长 64 个字符；以字母或数字开头。查询不区分大小写。退出码：成功 `0`，操作失败 `1`，参数错误 `2`，Ctrl+C `130`。错误写入标准错误。

## 二维码与账户注册

支持 `otpauth://totp/...`，默认 SHA1、6 位、30 秒；也支持 SHA256、SHA512、8 位以及 1–86400 秒的整数周期。按二维码参数原样计算，不猜测不支持的算法。

只接受本地 PNG/JPEG，最大 20 MiB、4000 万像素。支持旋转及反色二维码。若截图有多个不同的 TOTP 二维码，需要裁剪为一个。未知参数、重复参数、非法 Base32、发行方冲突和控制字符均会被拒绝，错误不回显二维码内容。

Microsoft Authenticator 的推送注册、Passkey、HOTP 和 Google Authenticator 批量迁移二维码不属于当前支持范围。网站若支持第三方 TOTP，可使用该选项提供的标准二维码。

`add` 成功只表示导入本机；若网站仍在开启 2FA 的流程，需将 `code` 生成的首个验证码提交给网站完成确认。读取原始截图不会修改或删除它。

## 数据保存

每个账户使用独立随机凭据 ID。Windows 使用独立的 Credential Manager service 名，避免多账户共用 service 导致查找冲突；设置为本机持久化。macOS 使用 Keychain，Linux 显式使用 Secret Service，不加载任意自定义 `keyring` 后端。

普通 JSON 只保存账户标签、凭据 ID、算法、位数和周期。位置如下，也可用 `doctor` 查询：

| 平台 | 默认索引 |
| --- | --- |
| Windows | `%LOCALAPPDATA%\local-totp-cli\accounts.json` |
| macOS | `~/Library/Application Support/local-totp-cli/accounts.json` |
| Linux | `${XDG_DATA_HOME:-~/.local/share}/local-totp-cli/accounts.json` |

索引更新使用进程锁及原子替换；导入失败会尝试撤销新写入的凭据。密钥不会写入配置、日志、导出或命令行参数。验证码仅在请求 `code` 时输出。二维码截图本身包含长期密钥，软件不会自动备份或上传它。

账户不会自动同步到另一台机器。复制 JSON 索引不能复制系统凭据；换机需重新导入原始 TOTP 凭据或在网站重新绑定。系统凭据库并不阻止所有以同一登录用户身份运行的软件访问密钥，本工具也没有为每次生成验证码增加独立主密码。

## 构建独立可执行文件

构建目标系统的可执行文件时，应在该系统上运行。以下命令在 Windows 生成 `dist/totp.exe`，macOS / Linux 生成 `dist/totp`。产物包含 Python 运行时，无需用户另外安装 Python。

```powershell
uv sync --locked --all-groups
uv run --no-sync python scripts/build_binary.py
.\dist\totp.exe --help
```

构建脚本可用 `--dist-dir` 和 `--work-dir` 指定输出及中间文件目录。所附 GitHub Actions 工作流包含 Windows、macOS、Linux 测试和原生构建，并在 Windows 运行凭据库及 `totp.exe` 的端到端测试。源码需要位于仓库根目录，工作流才会被 GitHub 识别。没有配置发布、部署或代码签名。

## 验证

```bash
uv sync --locked --group dev
uv run --no-sync ruff check src tests scripts
uv run --no-sync ruff format --check src tests scripts
uv run --no-sync pytest -q
```

普通测试使用内存凭据库，覆盖 RFC 6238 的全部 18 个 SHA1/SHA256/SHA512 测试向量、时间边界、前导零、PNG/JPEG、旋转与反色、异常 URI、多账户、并发、回滚及错误脱敏。原生凭据库测试默认跳过，以下命令只创建并清理使用公开 RFC 测试密钥的临时凭据：

```powershell
$env:TOTP_TEST_NATIVE = "1"
uv run --no-sync pytest -q tests/test_native.py
uv run --no-sync python scripts/smoke_native.py
uv run --no-sync python scripts/smoke_native.py --binary dist/totp.exe
```

当前交付在 macOS arm64 / Python 3.14 上已通过 94 项普通测试、原生 Keychain 测试、完整 CLI 流程及打包可执行文件的完整流程。Windows 和 Linux 已实现适配及 CI 配置，但当前环境未运行这两个系统；不能将 CI 配置视为已通过的结果。

## 参考

- [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238)：TOTP 算法与测试向量。
- [Key URI Format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)：二维码载荷格式。
- [PyOTP](https://pyauth.github.io/pyotp/)：验证码计算库。
- [keyring](https://keyring.readthedocs.io/en/latest/)：操作系统凭据库接口。
- [zxing-cpp](https://pypi.org/project/zxing-cpp/)：本地二维码识别。
- [PyInstaller](https://pyinstaller.org/en/stable/operating-mode.html)：按操作系统构建独立可执行文件。

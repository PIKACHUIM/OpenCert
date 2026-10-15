# OpenCert Manager Desktop

本目录只包含 **桌面客户端**（Go + Wails v2，目录 `wails/`）。它把本地管理端后端
（`clients/`）以**同进程**方式内嵌，因此交付物是**单个可执行文件**。

> 历史版本曾提供 Electron 壳（`main.js` / `preload.js`），现已移除：Electron 需要
> 额外的 Node 运行时与独立后端进程，且在本机环境下出现过 `electron.exe` 访问违例崩溃。
> 桌面端统一由 `wails/` 提供。

## 架构

```
┌──────────────────────────────────────────────┐
│            OpenCertManager.exe               │
│                                              │
│  Wails WebView 窗口                          │
│         │                                    │
│         ▼  同源请求（/、/api/*）              │
│  Wails AssetServer（反向代理，等待页兜底）      │
│         │                                    │
│         ▼                                    │
│  内嵌 client-card 后端（clients/pkg/app）      │
│    · REST API  :1026                         │
│    · 前端静态资源（React 构建产物）             │
│    · IPC Named Pipe / Unix Socket            │
│    · 证书传播、云端同步等后台任务               │
│                                              │
│  系统托盘：显示窗口 / 后端状态 / 重启后端        │
│           注册 pkcs11-mock / 打开数据目录 …    │
└──────────────────────────────────────────────┘
```

要点：

- **单进程内嵌**：通过 `go.mod` 的 `replace github.com/globaltrusts/client-card => ../../clients`
  直接复用 `clients/pkg/app`，不再以子进程方式拉起后端。
- **前端只维护一份**：Wails 不打包前端资源，而是把请求反向代理到内嵌后端，
  因此 `clients/front` 的构建产物同时服务于浏览器端与桌面端。
- **等待页兜底**：后端初始化（TPM 探测、数据库迁移）期间由内置等待页占位并自动刷新，不会白屏。
- **降级连接已有服务**：Named Pipe 与端口 1026 都是单例资源。若本机已运行其它 client-card
  （例如安装包把后端注册成了 Windows 服务），桌面端会自动改为连接该实例而不是启动失败。
- **单实例锁**：重复启动会唤起已有窗口。
- **关闭行为**：托盘可用时关闭窗口 = 最小化到托盘；托盘不可用时按普通退出处理。

## 目录结构

```
wails/
├── main.go              # Wails 入口：窗口、资源代理、单实例锁
├── desktop.go           # 桌面端对象：后端生命周期 + 暴露给前端的绑定方法
├── tray.go              # 系统托盘菜单
├── proxy.go             # AssetServer 反向代理 + 后端未就绪时的等待页
├── icon.go              # 运行时生成托盘图标（Windows: ICO；其它平台: PNG）
├── native.go            # 跨平台：查找 pkcs11-mock 驱动
├── native_windows.go    # regsvr32 注册 / 打开目录与链接
├── native_darwin.go     # tokend 复制 / open
├── native_linux.go      # modutil 注册 NSS 数据库 / xdg-open
├── wails.json           # Wails CLI 工程配置（可选，使用 wails CLI 时需要）
└── go.mod               # 独立 Go module，通过 replace 引用 clients
```

## 环境要求

| 平台 | 依赖 |
|------|------|
| Windows | Go ≥ 1.22、**WebView2 Runtime**（Win10 1803+ / Win11 内置）、C 编译器（MinGW-w64 或 MSVC，Wails 需要 cgo） |
| macOS | Go ≥ 1.22、Xcode Command Line Tools |
| Linux | Go ≥ 1.22、`libgtk-3-dev`、`libwebkit2gtk-4.0-dev`、`libayatana-appindicator3-dev` |

> Windows 下交叉编译（含 CI 的 ubuntu runner）时使用 `CGO_ENABLED=0`，此时不需要 C 编译器，
> 也不需要 WebView2 SDK：WebView2 由系统 Edge 运行时提供，其 loader 已内嵌在 `go-webview2` 中。

## 构建

### 推荐：使用统一构建脚本（同时产出桌面端与后端）

```bash
# 在仓库根目录执行；产物：dist/clients/
#   OpenCertManager-windows-{amd64,arm64}.exe   桌面客户端
#   client-card-windows-{amd64,arm64}.exe       本地管理端后端
./scripts/build-clients.sh v2.1.0
```

脚本会先构建 `clients/front` 前端并同步到 `clients/ui/dist`（供 `go:embed` 嵌入），
再交叉编译两个架构。可用环境变量：`OUT_DIR`、`SKIP_FRONTEND=1`、`ARCHES="amd64"`。

### 单独构建桌面端

```bash
cd desktop/wails
go mod download

# Windows（GUI 子系统 + 注入版本信息）
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -tags "desktop,production" \
  -ldflags "-s -w -H windowsgui -X main.Version=2.1.0" \
  -o ../dist/OpenCertManager.exe .

# 当前平台（Linux / macOS）
go build -tags "desktop,production" -o ../dist/OpenCertManager .
```

`desktop/dist/` 已在 `.gitignore` 中忽略。

若已安装 Wails CLI（`go install github.com/wailsapp/wails/v2/cmd/wails@v2.10.2`），
也可以使用 `wails build -s`（`-s` 跳过前端构建，前端资源由内嵌后端提供）、
`wails dev`（前端代理到 `127.0.0.1:1026`）。

## 运行说明

- 后端默认监听 `127.0.0.1:1026`，配置与数据库位于：
  - 配置：`%APPDATA%\clients\config.yaml`（macOS/Linux 为对应的用户数据目录）
  - 数据库：内嵌模式为可执行文件同级的 `data/clients.db`；外接服务模式使用服务自己的库
- 桌面端日志：`%APPDATA%\clients\logs\desktop.log`
- 无界面方式验证后端：`curl http://127.0.0.1:1026/api/health`

## 前端可调用的绑定

页面可通过 `window.go.main.Desktop.*` 调用（仅桌面端可用）：

| 方法 | 说明 |
|------|------|
| `Status()` | 桌面端与后端状态（是否内嵌 / 外接、API 地址、配置与数据库路径、日志路径） |
| `Version()` | 版本号 |
| `RestartBackend()` | 重启后端并返回最新状态 |
| `RegisterPKCS11Mock()` | 把 pkcs11-mock 注册到系统（Windows 需管理员权限） |
| `OpenInBrowser()` | 用系统浏览器打开管理界面 |
| `OpenDataDir()` / `OpenLogFile()` | 打开数据目录 / 日志文件 |
| `Quit()` | 退出桌面端（会优雅关闭内嵌后端） |

## 发布

- CI：`.github/workflows/ci.yml` 的 `build-clients` 任务构建 Windows x64/arm64 客户端。
- 发布：`.github/workflows/release-beta.yml` 的 `build-clients-windows` 任务产出
  `clients-windows-{amd64,arm64}.zip`（含桌面端与后端）。
- 安装包：`.github/workflows/windows-setup.yml` 调用同一脚本，把
  `OpenCertManager.exe` + `client-card.exe` 交给 Inno Setup（`scripts/setup/opencert.iss`）打包。

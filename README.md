
<div align="center">

# 🔐 OpenCert Manager

**企业级 CA + 智能卡 + X.509 / GPG / SSH 证书管理平台**

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green)](./drivers/LICENSE)
[![Version](https://img.shields.io/badge/Version-v2.1.0-blue)](./roadmap/11-ROADMAP.MD)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()

[📖 在线文档](https://pikachuim.github.io/PKCS11MiniDriver) · [🚀 快速开始](#快速开始) · [📋 路线图](./roadmap/11-ROADMAP.MD) · [🐛 问题反馈](https://github.com/PIKACHUIM/PKCS11MiniDriver/issues)

</div>

---

## 📌 项目简介

OpenCert Manager 是一套完整的 **CA + 智能卡 + 证书管理平台**，涵盖云端证书颁发管理、本地虚拟智能卡驱动、PKCS#11 标准兼容三大核心能力。

```
pkcs11-mock (C DLL)  ←→  client-card (Go + Electron)  ←→  server-card (Go)
   PKCS#11 驱动            本地管理端 :1026                云端平台 :1027
```

### 核心价值

- **全生命周期证书管理**：CA 创建 → 模板配置 → 证书颁发 → 吊销 → 续期完整闭环
- **多类型证书支持**：X.509、GPG、SSH，以及 TOTP/FIDO/登录信息等安全凭据
- **虚拟智能卡驱动**：通过 PKCS#11 v2.40 标准接口，将证书注册到操作系统
- **多级安全保障**：TPM2 硬件保护 / 云端 HSM / 本地 AES-256 三种安全等级
- **企业级 PKI 服务**：ACME 自动化、CRL/OCSP 吊销服务、CT 透明度日志

---

## 🏗️ 系统架构

```
┌─────────────────────────────────────────────────────────┐
│              应用层（Firefox / SSH / GPG / CSP）          │
└──────────────────────┬──────────────────────────────────┘
                       │ PKCS#11 v2.40 标准接口
┌──────────────────────▼──────────────────────────────────┐
│              pkcs11-mock（C DLL/SO/DYLIB）                │
│         IPC: Named Pipe (Win) / Unix Socket (Linux/macOS) │
└──────────────────────┬──────────────────────────────────┘
                       │ IPC 二进制帧协议
┌──────────────────────▼──────────────────────────────────┐
│              client-card（Go + React + Electron）         │
│   ┌──────────────┐ ┌──────────────┐ ┌────────────────┐  │
│   │  Local Slot  │ │  TPM2 Slot   │ │   Cloud Slot   │  │
│   │ SQLite+AES256│ │ TPM芯片+AES  │ │  REST 转发     │  │
│   └──────────────┘ └──────────────┘ └────────────────┘  │
└──────────────────────┬──────────────────────────────────┘
                       │ HTTPS REST API
┌──────────────────────▼──────────────────────────────────┐
│              server-card（Go）                            │
│   CA管理 · 证书颁发 · 用户认证 · ACME · CRL/OCSP · CT    │
│                    PostgreSQL / HSM                       │
└─────────────────────────────────────────────────────────┘
```

---

## 📦 组件说明

| 组件 | 语言 | 说明 |
|------|------|------|
| [`drivers/`](./drivers) | C / CMake | PKCS#11 v2.40 标准驱动，注册到操作系统 |
| [`clients/`](./clients) | Go 1.22+ | 本地管理端后端，监听 `:1026`，管理三种虚拟智能卡 |
| [`servers/`](./servers) | Go 1.22+ | 云端 CA 平台后端，监听 `:1027`，提供完整 PKI 服务 |
| [`docpage/`](./docpage) | React + Vite | 项目文档站点 |

---

## ✨ 功能特性

### 云端平台（server-card）

| 模块 | 功能 |
|------|------|
| 用户管理 | 注册/登录/TOTP 双因素/RBAC 角色权限/公钥对管理 |
| 智能卡存储域 | 本地数据库 / HSM 硬件存储区域管理 |
| CA 管理 | 创建/导入 CA、证书链、CRL 吊销管理 |
| 证书颁发 | 基于模板的 X.509/GPG/SSH 证书颁发 |
| 模板体系 | 颁发模板、主体模板、扩展信息模板、密钥用途模板、存储类型模板 |
| PKI 服务 | ACME（RFC 8555）、CRL 分发、OCSP 响应、CT 透明度日志 |
| 订单/支付 | 证书购买、审批流程、多支付插件 |
| OID 管理 | 自定义 OID（EKU、主体字段、EV 声明、ASN.1 扩展） |

### 本地管理端（client-card）

| 模块 | 功能 |
|------|------|
| 智能卡管理 | Local / TPM2 / Cloud 三种卡槽 CRUD |
| 证书管理 | 导入（PKCS12/PEM/私钥匹配）、导出、删除 |
| PKI 工具 | CSR 生成、本地 CA、证书签发、自签名证书 |
| TOTP 管理 | TOTP/HOTP 验证器，实时验证码显示 |
| 云端同步 | 证书下发到本地/智能卡，自动/手动同步 |
| 系统注册 | 通过 pkcs11-mock 将证书注册到操作系统 |

### PKCS#11 驱动（pkcs11-mock）

| 能力 | 支持范围 |
|------|---------|
| 密钥类型 | RSA 1024–8192、ECC P-256/384/521、Brainpool、Ed25519/X25519、SM2 |
| 摘要算法 | SHA-1/256/384/512、SHA3、MD5、MD4、SM3 |
| 加密算法 | AES-128/256（GCM/CBC）、RC4、ChaCha20-Poly1305、SM4 |
| 证书类型 | X.509、GPG、SSH |
| IPC 通信 | Named Pipe（Windows）/ Unix Socket（Linux/macOS） |

---

## 🔐 安全设计

### 三层加密架构

```
用户密码 → Argon2id → AES-256-GCM → 卡片主密钥（32字节随机）
                                          ↓
                              HMAC-SHA256 → AES-256-GCM → 临时密钥（每证书独立）
                                                                ↓
                                                    AES-256-GCM(AAD) → 私钥密文
```

### 密钥安全等级

| 等级 | 存储方式                  | 可恢复 | 可导出 |
|------|-----------------------|--------|--------|
| 🟢 高安全性 | TPM 内部，密钥不可导出         | ❌ | ❌ |
| 🟡 中安全性 | 本地 DB + TPM 加密/云端公钥加密 | ✅ | ❌ |
| 🔴 低安全性 | 本地 DB + 密码加密/云端公钥加密   | ✅ | ✅ |

---

## 🚀 快速开始

### 环境要求

| 工具 | 版本要求 |
|------|---------|
| Go | ≥ 1.22 |
| Node.js | ≥ 18 LTS |
| GCC / MinGW | C 编译器（驱动构建） |
| CMake | ≥ 3.20（驱动构建） |

### 一、构建并运行云端平台

```bash
cd servers
go mod download
go build -o opencert-platform ./cmd/servers/
./opencert-platform

# 验证
curl http://localhost:1027/api/health
```

### 二、构建并运行本地管理端

```bash
# 构建前端
cd clients/front
npm install && npm run build

# 构建 Go 后端
cd clients
go mod download
go build -o opencert-manager ./cmd/clients/
./opencert-manager

# 浏览器访问
open http://localhost:1026
```

### 三、构建 PKCS#11 驱动

```bash
cd drivers

# Windows（MinGW / MSVC）
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
# 产物：build/Release/pkcs11-mock.dll

# Linux
cmake -B build && cmake --build build
# 产物：build/libpkcs11-mock.so

# macOS
cmake -B build && cmake --build build
# 产物：build/libpkcs11-mock.dylib
```

### 四、注册驱动

```bash
# Windows
regsvr32 pkcs11-mock.dll

# Linux（Firefox）
modutil -dbdir ~/.mozilla/firefox/<profile> \
        -add "OpenCert PKCS11" \
        -libfile /usr/lib/pkcs11/libpkcs11-mock.so

# SSH 配置
echo "PKCS11Provider /usr/lib/pkcs11/libpkcs11-mock.so" >> ~/.ssh/config
```

### 使用 Makefile 一键构建

```bash
make build          # 完整构建（前端 + 后端）
make build-frontend # 仅构建前端
make build-backend  # 仅构建后端
make test           # 运行所有测试
make dev            # 启动前端开发服务器（:5173）
make clean          # 清理构建产物
```

### Docker 快速部署（云端平台）

```yaml
# docker-compose.yml
version: '3.8'
services:
  opencert-platform:
    image: opencert-platform:latest
    ports:
      - "1027:1027"
    volumes:
      - ./config.yaml:/etc/opencert/config.yaml
    depends_on:
      - db
  db:
    image: postgres:16
    environment:
      POSTGRES_USER: opencert
      POSTGRES_PASSWORD: password
      POSTGRES_DB: opencert
    volumes:
      - pgdata:/var/lib/postgresql/data
volumes:
  pgdata:
```

```bash
docker-compose up -d
```

---

## 📁 目录结构

```
PKCS11Driver/
├── clients/                    # client-card 本地管理端（Go 1.22）
│   ├── cmd/clients/            # 启动入口
│   ├── configs/                # 配置加载（YAML/ENV）
│   ├── internal/
│   │   ├── card/               # SlotProvider 接口 + 三种 Slot 实现
│   │   │   ├── local/          # Local Slot（SQLite + AES-256）
│   │   │   ├── tpm2/           # TPM2 Slot（TPM 芯片）
│   │   │   └── cloud/          # Cloud Slot（REST 转发）
│   │   ├── crypto/             # AES/HMAC/Argon2id 加密工具
│   │   ├── ipc/                # IPC 服务（Named Pipe/Unix Socket）
│   │   ├── storage/            # SQLite 存储层
│   │   └── api/                # REST API Handler
│   ├── front/                  # React + Ant Design 前端
│   └── test/                   # 测试文件
├── servers/                    # server-card 云端平台（Go 1.22）
│   ├── cmd/servers/            # 启动入口
│   ├── configs/                # 配置加载
│   └── internal/
│       ├── api/                # REST API Handler
│       ├── auth/               # JWT 认证
│       ├── ca/                 # CA 引擎
│       ├── cert/               # 证书颁发/管理
│       ├── template/           # 模板管理
│       ├── order/              # 订单系统
│       ├── acme/               # ACME 服务
│       ├── revoke/             # CRL/OCSP 服务
│       └── storage/            # PostgreSQL 存储层
├── drivers/                    # pkcs11-mock PKCS#11 驱动（C）
│   ├── src/                    # C 源代码
│   ├── include/                # PKCS#11 头文件
│   └── CMakeLists.txt
├── docpage/                    # 文档站点（React + Vite）
└── roadmap/                    # 设计文档
    ├── 01-OVERVIEW.MD          # 项目总览
    ├── 02-ARCHITECTURE.MD      # 系统架构
    ├── 03-CLOUD-PLATFORM.MD    # 云端平台设计
    ├── 04-LOCAL-MANAGER.MD     # 本地管理端设计
    ├── 05-PKCS11-DRIVER.MD     # 驱动设计
    ├── 06-SECURITY.MD          # 安全设计
    ├── 07-API.MD               # API 规范
    ├── 08-FRONTEND.MD          # 前端设计
    ├── 09-DATABASE.MD          # 数据库设计
    ├── 10-DEPLOY.MD            # 部署运维
    └── 11-ROADMAP.MD           # 开发路线图
```

---

## 🗺️ 开发路线图

| 阶段 | 内容 | 状态 |
|------|------|------|
| Phase 1–3 | 项目骨架、Local Slot、REST API | ✅ 已完成 |
| Phase 4–5 | TPM2 Slot、Cloud Slot + server-card | ✅ 已完成 |
| Phase 6–7 | 前端界面、pkcs11-mock C 驱动 | ✅ 已完成 |
| Phase 8 | 集成测试、CI/CD 流水线、安全审计自动化 | ✅ 已完成 |
| Phase 9 | 云端平台完善（CA/模板/订单/支付插件） | ✅ 已完成 |
| Phase 10 | PKI 服务（ACME TLS-ALPN-01/CRL/OCSP/CT） | ✅ 已完成 |
| Phase 11 | TPM EK 认证、安全凭据、GPG/SSH 映射、i18n | ✅ 已完成 |
| Phase 12 | 安全加固、性能优化、正式发布 v2.1.0 | 🚧 进行中 |

详细计划见 [roadmap/11-ROADMAP.MD](./roadmap/11-ROADMAP.MD)。

---

## 🛠️ 技术栈

| 层级 | 技术选型 |
|------|---------|
| 云端后端 | Go 1.22+ / `net/http` 标准库 / PostgreSQL |
| 本地后端 | Go 1.22+ / `net/http` 标准库 / SQLite（modernc） |
| PKCS#11 驱动 | C11 / CMake / Named Pipe / Unix Socket |
| 前端框架 | React 18 + TypeScript + Ant Design 5.x |
| 状态管理 | Zustand |
| 桌面端 | Electron |
| 构建工具 | Vite |
| 国际化 | i18next（中/英双语） |
| TPM 支持 | go-tpm（Win/Linux）/ Security.framework（macOS） |
| 密码学 | Argon2id / AES-256-GCM / HMAC-SHA256 / ECDSA |

---

## 📚 文档

| 文档 | 说明 |
|------|------|
| [项目总览](./roadmap/01-OVERVIEW.MD) | 项目定位、系统全景、技术栈 |
| [系统架构](./roadmap/02-ARCHITECTURE.MD) | 组件交互、IPC 协议、Slot 设计 |
| [云端平台](./roadmap/03-CLOUD-PLATFORM.MD) | server-card 全部功能详细设计 |
| [本地管理端](./roadmap/04-LOCAL-MANAGER.MD) | client-card 功能设计 |
| [PKCS#11 驱动](./roadmap/05-PKCS11-DRIVER.MD) | 驱动设计与函数映射 |
| [安全设计](./roadmap/06-SECURITY.MD) | 加密方案、威胁模型、安全策略 |
| [API 规范](./roadmap/07-API.MD) | 完整 REST API 接口规范 |
| [前端设计](./roadmap/08-FRONTEND.MD) | 前端架构、页面规划、菜单设计 |
| [数据库设计](./roadmap/09-DATABASE.MD) | 数据模型、表结构、索引设计 |
| [部署运维](./roadmap/10-DEPLOY.MD) | 构建、配置、部署、运维指南 |

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

1. Fork 本仓库
2. 创建特性分支：`git checkout -b feature/your-feature`
3. 提交变更：`git commit -m 'feat: add your feature'`
4. 推送分支：`git push origin feature/your-feature`
5. 提交 Pull Request

---

## 📄 许可证

本项目采用 [MIT License](./drivers/LICENSE) 开源协议。

---

<div align="center">
<sub>OpenCert Manager · v2.1.0 · 2026-05-26</sub>
</div>

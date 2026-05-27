import DocPage from '../components/DocPage'

const algorithms = [
  { category: '非对称密钥', items: ['RSA 1024–8192', 'ECC P-256/P-384/P-521', 'Brainpool P256/P384/P512', 'Ed25519 / X25519', 'SM2'] },
  { category: '摘要算法', items: ['SHA-1 / SHA-256 / SHA-384 / SHA-512', 'SHA3-256 / SHA3-384 / SHA3-512', 'MD5 / MD4', 'SM3'] },
  { category: '对称加密', items: ['AES-128 / AES-256 (GCM/CBC)', 'RC4', 'ChaCha20-Poly1305', 'SM4-CBC'] },
  { category: '证书格式', items: ['X.509 v3', 'OpenPGP / GPG', 'SSH 公钥格式'] },
]

const pkcs11Functions = [
  { func: 'C_Initialize',        cmd: 'Handshake (0x00FF)', desc: '初始化库，与 client-card 进行版本协商' },
  { func: 'C_Finalize',          cmd: '—',                  desc: '关闭 IPC 连接，释放所有资源' },
  { func: 'C_GetInfo',           cmd: 'CmdGetInfo',         desc: '获取库信息（版本、厂商、描述）' },
  { func: 'C_GetSlotList',       cmd: 'CmdGetSlotList',     desc: '列出所有 Slot（每张智能卡对应一个 Slot）' },
  { func: 'C_GetSlotInfo',       cmd: 'CmdGetSlotInfo',     desc: '获取 Slot 信息（名称、厂商、标志位）' },
  { func: 'C_GetTokenInfo',      cmd: 'CmdGetTokenInfo',    desc: '获取 Token 信息（标签、序列号、PIN 长度）' },
  { func: 'C_GetMechanismList',  cmd: 'CmdGetMechanismList',desc: '列出 Slot 支持的算法机制' },
  { func: 'C_GetMechanismInfo',  cmd: 'CmdGetMechanismInfo',desc: '获取指定算法机制的详细信息' },
  { func: 'C_OpenSession',       cmd: 'CmdOpenSession',     desc: '打开会话（支持 RO/RW 模式）' },
  { func: 'C_CloseSession',      cmd: 'CmdCloseSession',    desc: '关闭指定会话' },
  { func: 'C_CloseAllSessions',  cmd: 'CmdCloseAllSessions',desc: '关闭某 Slot 的所有会话' },
  { func: 'C_GetSessionInfo',    cmd: 'CmdGetSessionInfo',  desc: '获取会话状态（PUBLIC/USER/SO）' },
  { func: 'C_Login',             cmd: 'CmdLogin',           desc: '用户登录（CKU_USER / CKU_SO）' },
  { func: 'C_Logout',            cmd: 'CmdLogout',          desc: '用户登出' },
  { func: 'C_InitPIN',           cmd: 'CmdInitPIN',         desc: '初始化 PIN（需 SO 权限）' },
  { func: 'C_SetPIN',            cmd: 'CmdSetPIN',          desc: '修改 PIN（需 USER 权限）' },
  { func: 'C_FindObjectsInit',   cmd: 'CmdFindObjectsInit', desc: '初始化对象搜索（按属性模板过滤）' },
  { func: 'C_FindObjects',       cmd: 'CmdFindObjects',     desc: '获取搜索结果（证书/公钥/私钥对象）' },
  { func: 'C_FindObjectsFinal',  cmd: 'CmdFindObjectsFinal',desc: '结束对象搜索' },
  { func: 'C_GetAttributeValue', cmd: 'CmdGetAttributeValue',desc: '获取对象属性（证书内容、密钥类型等）' },
  { func: 'C_CreateObject',      cmd: 'CmdCreateObject',    desc: '创建对象（导入证书/密钥）' },
  { func: 'C_DestroyObject',     cmd: 'CmdDestroyObject',   desc: '删除对象' },
  { func: 'C_SignInit',          cmd: 'CmdSignInit',        desc: '初始化签名操作，指定算法和私钥' },
  { func: 'C_Sign',              cmd: 'CmdSign',            desc: '执行签名，返回签名结果' },
  { func: 'C_DecryptInit',       cmd: 'CmdDecryptInit',     desc: '初始化解密操作' },
  { func: 'C_Decrypt',           cmd: 'CmdDecrypt',         desc: '执行解密' },
  { func: 'C_EncryptInit',       cmd: 'CmdEncryptInit',     desc: '初始化加密操作' },
  { func: 'C_Encrypt',           cmd: 'CmdEncrypt',         desc: '执行加密' },
  { func: 'C_GenerateKeyPair',   cmd: 'CmdGenerateKeyPair', desc: '片上生成密钥对（RSA/ECC/EdDSA/SM2）' },
]

const notImplemented = [
  'C_DigestInit / C_Digest / C_DigestUpdate / C_DigestFinal',
  'C_SignUpdate / C_SignFinal',
  'C_VerifyInit / C_Verify / C_VerifyUpdate / C_VerifyFinal',
  'C_EncryptUpdate / C_EncryptFinal',
  'C_DecryptUpdate / C_DecryptFinal',
  'C_WrapKey / C_UnwrapKey / C_DeriveKey',
  'C_GenerateKey',
  'C_SeedRandom / C_GenerateRandom',
  'C_WaitForSlotEvent',
]

const buildArtifacts = [
  { platform: 'Windows x64',      artifact: 'pkcs11-mock.dll',         compiler: 'MSVC / MinGW' },
  { platform: 'Linux x64',        artifact: 'libpkcs11-mock.so',       compiler: 'GCC' },
  { platform: 'macOS arm64/x64',  artifact: 'libpkcs11-mock.dylib',    compiler: 'Clang' },
]

export default function DriverPage() {
  return (
    <DocPage
      title="PKCS#11 驱动"
      subtitle="pkcs11-mock 是符合 PKCS#11 v2.40 标准的 C 语言动态库，通过 IPC（Named Pipe / Unix Socket）与 client-card 通信，将虚拟智能卡注册到操作系统"
      badge="PKCS#11 v2.40"
    >
      <h2>⚙ 驱动架构</h2>
      <pre>{`应用程序 (Firefox / Chrome / OpenSSH / GPG Agent / Windows CSP)
    │
    │  PKCS#11 v2.40 标准 C 接口（系统调用）
    ▼
pkcs11-mock.dll / libpkcs11-mock.so / libpkcs11-mock.dylib
    │
    │  IPC 通信（二进制帧协议）
    │  Windows : Named Pipe  \\\\.\\pipe\\opencert-pkcs11
    │  Linux   : Unix Socket /tmp/opencert-pkcs11.sock
    │  macOS   : Unix Socket /tmp/opencert-pkcs11.sock
    ▼
client-card (Go 后端 :1026)
    │
    ├── local slot  → SQLite + AES-256-GCM 本地加密存储
    ├── tpmv2 slot  → TPM 2.0 / Secure Enclave 硬件保护
    └── cloud slot  → server-card 云端 REST API (:1027)`}</pre>

      <div className="callout callout-info">
        <span className="callout-icon">ℹ️</span>
        <div className="callout-body">
          <strong>IPC 通信安全</strong>
          pkcs11-mock 与 client-card 之间通过本地 IPC 通道通信，
          Windows 使用 Named Pipe 并配置 DACL（仅当前用户 + SYSTEM 可访问），
          Linux/macOS 使用 Unix Domain Socket 并设置文件权限 0600，无需网络端口。
        </div>
      </div>

      <h2>📡 IPC 帧协议</h2>
      <p>每条消息由固定 12 字节帧头 + JSON Payload 组成：</p>
      <pre>{`┌──────────┬──────────┬──────────┬─────────────────┐
│  Magic   │ Command  │  Length  │  JSON Payload   │
│  4 bytes │  4 bytes │  4 bytes │    N bytes      │
│  "PK11"  │BigEndian │BigEndian │  UTF-8 JSON     │
└──────────┴──────────┴──────────┴─────────────────┘`}</pre>
      <table>
        <thead>
          <tr><th>命令码</th><th>名称</th><th>说明</th></tr>
        </thead>
        <tbody>
          {[
            ['0x0000', 'CmdPing',      '心跳，30 秒空闲发送，3 次无响应触发重连'],
            ['0x00FF', 'CmdHandshake', 'C_Initialize 阶段版本协商'],
            ['0x0001', 'CmdGetInfo',   '获取库信息'],
            ['0x0002–0x0006', 'Slot/Token/Mechanism', 'Slot、Token、算法信息查询'],
            ['0x0007–0x0009', 'Session', '会话管理（Open/Close/GetInfo）'],
            ['0x000A–0x000B', 'Login/Logout', '用户认证'],
            ['0x000C–0x000E', 'FindObjects', '对象查找三步骤'],
            ['0x000F–0x0013', 'Object', '对象属性读写与管理'],
            ['0x0014–0x001D', 'Crypto', '签名 / 解密 / 加密操作'],
            ['0x001E', 'CmdGenerateKeyPair', '片上密钥对生成'],
            ['0x0023–0x0024', 'PIN', 'InitPIN / SetPIN'],
          ].map(([code, name, desc]) => (
            <tr key={code as string}>
              <td><code>{code}</code></td>
              <td><strong>{name}</strong></td>
              <td>{desc}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p>响应格式：<code>{`{ "rv": 0, "data": { ... } }`}</code>，其中 <code>rv</code> 为 PKCS#11 标准返回值（CKR_OK = 0）。</p>

      <h2>🔧 支持的算法</h2>
      <div className="card-grid">
        {algorithms.map((a) => (
          <div key={a.category} className="info-card">
            <div className="info-card-title">🔐 {a.category}</div>
            <div className="info-card-body">
              <ul style={{ paddingLeft: '1rem', margin: 0 }}>
                {a.items.map((item) => (
                  <li key={item} style={{ marginBottom: '2px' }}>{item}</li>
                ))}
              </ul>
            </div>
          </div>
        ))}
      </div>

      <h2>📋 已实现的 PKCS#11 函数（29 个）</h2>
      <table>
        <thead>
          <tr><th>PKCS#11 函数</th><th>IPC 命令</th><th>说明</th></tr>
        </thead>
        <tbody>
          {pkcs11Functions.map((f) => (
            <tr key={f.func}>
              <td><code>{f.func}</code></td>
              <td><code style={{ fontSize: '0.75rem', color: 'var(--color-text-muted)' }}>{f.cmd}</code></td>
              <td>{f.desc}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>🚫 未实现函数（返回 CKR_FUNCTION_NOT_SUPPORTED）</h2>
      <ul>
        {notImplemented.map((fn) => (
          <li key={fn}><code>{fn}</code></li>
        ))}
      </ul>

      <h2>🔑 片上密钥生成与 CSR 签名</h2>
      <p>
        为确保私钥真正在智能卡上生成（而非用户自行生成后导入），
        pkcs11-mock 实现了片上生成与 CSR 签名机制：
      </p>
      <pre>{`# 片上密钥生成流程
1. 应用调用 C_GenerateKeyPair
2. pkcs11-mock 发送 CmdGenerateKeyPair 到 client-card
3. client-card 在指定 Slot 上生成密钥对：
   - Local Slot  : 软件生成，AES-256-GCM 加密存储
   - TPM2 Slot   : TPM 芯片内生成（高安全性）或软件生成+TPM加密（中/低）
   - Cloud Slot  : 云端服务器生成，私钥不离开服务器
4. 返回公钥和私钥的对象句柄

# CSR 签名确认流程
1. 生成密钥对（片上生成）
2. 构造 CSR（主体信息 + 扩展信息）
3. 使用片上私钥对 CSR 签名
4. 云端验证签名，确认密钥来自合法智能卡
5. 颁发证书`}</pre>

      <h2>🖥️ 安装配置</h2>
      <h3>构建产物</h3>
      <table>
        <thead>
          <tr><th>平台</th><th>产物文件</th><th>编译器</th></tr>
        </thead>
        <tbody>
          {buildArtifacts.map((b) => (
            <tr key={b.platform}>
              <td>{b.platform}</td>
              <td><code>{b.artifact}</code></td>
              <td>{b.compiler}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h3>Windows</h3>
      <pre>{`# 编译驱动
cd drivers
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
# 产物: build/Release/pkcs11-mock.dll

# Firefox 配置（证书管理器 → 安全设备 → 加载）
# 或使用 about:config → security.osclientcerts.autoload = true

# SSH 配置（PowerShell）
# 在 ~/.ssh/config 中添加：
# PKCS11Provider C:\\path\\to\\pkcs11-mock.dll`}</pre>

      <h3>Linux</h3>
      <pre>{`# 编译驱动
cd drivers && mkdir build && cd build
cmake .. && make -j$(nproc)
# 产物: build/libpkcs11-mock.so

# 安装到标准路径
sudo cp build/libpkcs11-mock.so /usr/lib/pkcs11/

# Firefox 配置（使用 modutil）
modutil -dbdir ~/.mozilla/firefox/<profile> \\
        -add "OpenCert PKCS11" \\
        -libfile /usr/lib/pkcs11/libpkcs11-mock.so

# SSH 配置（~/.ssh/config）
# PKCS11Provider /usr/lib/pkcs11/libpkcs11-mock.so`}</pre>

      <h3>macOS</h3>
      <pre>{`# 编译驱动
cd drivers && mkdir build && cd build
cmake .. && make -j$(sysctl -n hw.ncpu)
# 产物: build/libpkcs11-mock.dylib

# Firefox 配置
modutil -dbdir ~/Library/Application\\ Support/Firefox/Profiles/<profile> \\
        -add "OpenCert PKCS11" \\
        -libfile /usr/local/lib/libpkcs11-mock.dylib`}</pre>

      <h3>验证安装</h3>
      <pre>{`# 使用 pkcs11-tool 验证（需先启动 client-card）
pkcs11-tool --module pkcs11-mock.dll --list-slots
pkcs11-tool --module pkcs11-mock.dll --list-objects
pkcs11-tool --module pkcs11-mock.dll --test`}</pre>

      <h2>🔐 密钥安全级别</h2>
      <table>
        <thead>
          <tr><th>级别</th><th>密钥存储位置</th><th>TPM 保护</th><th>可导出</th><th>可恢复</th><th>云端备份</th></tr>
        </thead>
        <tbody>
          <tr>
            <td><span className="badge badge-green">高安全</span></td>
            <td>TPM 内部（不可导出）</td>
            <td>✅ 片上不可导出</td>
            <td>❌</td>
            <td>❌</td>
            <td>❌</td>
          </tr>
          <tr>
            <td><span className="badge badge-orange">中安全</span></td>
            <td>本地 DB + TPM 加密</td>
            <td>✅ TPM 密钥加密</td>
            <td>❌</td>
            <td>✅</td>
            <td>可选</td>
          </tr>
          <tr>
            <td><span className="badge badge-blue">低安全</span></td>
            <td>本地 DB + 密码加密</td>
            <td>❌ 纯软件加密</td>
            <td>✅</td>
            <td>✅</td>
            <td>可选</td>
          </tr>
        </tbody>
      </table>

      <div className="callout callout-warning">
        <span className="callout-icon">⚠️</span>
        <div className="callout-body">
          <strong>TPM2 要求</strong>
          TPM2 高安全模式需要系统具备 TPM 2.0 芯片并在 BIOS 中启用。
          Windows 11 设备通常已满足此要求。macOS 仅支持 Secure Enclave（EC P-256），
          不支持 RSA 硬件保护。TPM 不可用时自动降级为 Local Slot（纯软件加密）。
        </div>
      </div>

      <h2>🔄 连接与重连机制</h2>
      <table>
        <thead>
          <tr><th>场景</th><th>行为</th></tr>
        </thead>
        <tbody>
          {[
            ['C_Initialize 调用时', '尝试连接 IPC 通道，发送 Handshake 帧协商版本，启动心跳线程（30 秒间隔）'],
            ['心跳超时（3 次无响应）', '标记连接断开，后续 PKCS#11 调用返回 CKR_DEVICE_ERROR'],
            ['client-card 未启动', 'C_Initialize 连接超时，返回 CKR_DEVICE_ERROR，应用可稍后重试'],
            ['C_Finalize 调用时', '停止心跳线程，关闭 IPC 连接，释放所有资源'],
            ['多线程并发调用', '所有 IPC 通信使用互斥锁保护，句柄分配使用原子操作'],
          ].map(([scene, behavior]) => (
            <tr key={scene as string}>
              <td><strong>{scene}</strong></td>
              <td style={{ fontSize: '0.85rem' }}>{behavior}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </DocPage>
  )
}

import DocPage from '../components/DocPage'

export default function CryptoFlowPage() {
  return (
    <DocPage
      title="加密流程图"
      subtitle="智能卡主密钥、PIN/PUK/AdminKey、证书密钥的生成、存储、加密、解密完整流程"
      badge="Crypto v2.0"
    >
      <h2>🔑 密钥体系总览</h2>
      <p>系统采用三层加密架构，确保私钥在存储和传输过程中的安全性：</p>

      <pre>{`密钥层次关系：

┌─────────────────────────────────────────────────────────────┐
│  用户凭据层                                                  │
│    PIN 码 / PUK 码 / Admin Key / 卡片密码                    │
│         │                                                    │
│         ▼ HMAC-SHA256(凭据, salt) → AES-256-GCM             │
├─────────────────────────────────────────────────────────────┤
│  主密钥层                                                    │
│    卡片主密钥 (32 字节 CSPRNG 随机)                           │
│         │                                                    │
│         ▼ HMAC-SHA256(masterKey, salt) → AES-256-GCM        │
├─────────────────────────────────────────────────────────────┤
│  临时密钥层（每证书独立）                                     │
│    临时密钥 (32 字节随机)                                     │
│         │                                                    │
│         ▼ AES-256-GCM                                       │
├─────────────────────────────────────────────────────────────┤
│  私钥层                                                      │
│    证书私钥 (RSA/EC/Ed25519 DER 编码)                        │
└─────────────────────────────────────────────────────────────┘`}</pre>

      <h2>💳 主密钥生成流程</h2>
      <pre>{`创建新智能卡：

  ┌──────────────────┐
  │ crypto/rand 生成  │
  │ 32 字节随机数     │ ──→ masterKey
  └──────────────────┘
           │
           ▼
  ┌──────────────────────────────────────┐
  │ 安全等级判断                          │
  ├──────────────────────────────────────┤
  │ low:    masterKey 直接用于加密        │
  │ medium: 额外生成 TPM 证书密钥         │
  │ high:   TPM Seal(masterKey) → blob   │
  └──────────────────────────────────────┘
           │
           ▼
  ┌──────────────────────────────────────┐
  │ 用 PIN 加密主密钥                     │
  │   salt = crypto/rand(32B)            │
  │   AES密钥 = HMAC-SHA256(PIN, salt)   │
  │   enc = AES-256-GCM(AES密钥, master) │
  │   存储 CardKeyEntry{salt, enc}       │
  └──────────────────────────────────────┘`}</pre>

      <h2>🔐 主密钥加密存储格式</h2>
      <pre>{`CardKeyEntry (JSON BLOB)：
┌─────────────────────────────────────────────────────────────┐
│  key_type:       "pin" | "card" | "admin" | "puk" | "user"  │
│  user_uuid:      "" (仅 user 类型有效)                       │
│  salt:           [32 字节随机盐值]                            │
│  enc_master_key: [nonce(12B) + 密文 + tag(16B)]             │
│  attempts:       0 (失败次数)                                │
│  locked:         false                                       │
├─────────────────────────────────────────────────────────────┤
│  加密算法:                                                   │
│    AES密钥 = HMAC-SHA256(凭据明文, salt)                     │
│    enc_master_key = AES-256-GCM(AES密钥, 主密钥明文)        │
└─────────────────────────────────────────────────────────────┘`}</pre>

      <h2>🔓 主密钥解密流程（Login）</h2>
      <pre>{`用户输入 PIN → Slot.Login()：

  1. 遍历 card.CardKeys 列表
  2. 对每条 entry:
     │
     ├─ AES密钥 = HMAC-SHA256(PIN, entry.Salt)
     ├─ 尝试 AES-GCM-Decrypt(AES密钥, entry.EncMasterKey)
     │
     ├─ 成功 → masterKey 明文 ✓
     │   ├─ 保存 masterKey 到内存
     │   ├─ 重置 PINFailedCount = 0
     │   └─ 加载证书对象到缓存
     │
     └─ 失败 → 尝试下一条 entry
         └─ 全部失败 → PINFailedCount++
             └─ 超过 maxRetries → PIN 锁定`}</pre>

      <h2>🛡️ PIN / PUK / Admin Key 三级凭据</h2>

      <h3>凭据关系</h3>
      <pre>{`权限层级：

  Admin Key (最高权限)
    │
    ├─ 可直接解密主密钥
    ├─ 可重置 PUK
    └─ 可重置 PIN

  PUK 码 (恢复权限)
    │
    ├─ 加密存储的是 PIN 明文（非主密钥）
    └─ 可重置 PIN

  PIN 码 (日常使用)
    │
    └─ 解密主密钥 → 操作私钥`}</pre>

      <h3>PUK 特殊设计</h3>
      <div className="callout callout-warning">
        <strong>PUK 加密 PIN 而非主密钥</strong>
        <p>PUK 条目的 enc_master_key 字段实际存储的是 AES-GCM(HMAC(PUK,salt), PIN明文)。
        这确保 PUK 不能绕过 PIN 直接操作私钥，只能用于重置 PIN。</p>
      </div>

      <h3>PUK 重置 PIN 流程</h3>
      <pre>{`输入: PUK + 新PIN

  1. AES密钥 = HMAC(PUK, puk_entry.Salt)
  2. 旧PIN = AES-GCM-Decrypt(AES密钥, puk_entry.EncMasterKey)
  3. AES密钥2 = HMAC(旧PIN, pin_entry.Salt)
  4. masterKey = AES-GCM-Decrypt(AES密钥2, pin_entry.EncMasterKey)
  5. 新salt = crypto/rand(32B)
  6. AES密钥3 = HMAC(新PIN, 新salt)
  7. 新enc = AES-GCM-Encrypt(AES密钥3, masterKey)
  8. 替换 pin_entry = {salt: 新salt, enc: 新enc}
  9. 重新加密 PUK 条目（存储新PIN）`}</pre>

      <h3>错误次数与锁定</h3>
      <pre>{`状态机：

  正常 ──PIN正确──→ 正常 (重置计数)
    │
    └──PIN错误──→ attempts++ ──超过maxRetries──→ PIN锁定
                                                    │
                                    ┌───────────────┤
                                    ▼               ▼
                              PUK解锁          Admin解锁
                                    │               │
                                    └───→ 正常 ←────┘`}</pre>

      <h2>📜 证书密钥加密存储</h2>

      <h3>生成与加密流程</h3>
      <pre>{`GenerateKeyPair 请求：

  1. 生成密钥对
     ├─ RSA: rsa.GenerateKey(2048/4096)
     ├─ EC:  ecdsa.GenerateKey(P256/P384/P521)
     └─ Ed:  ed25519.GenerateKey()

  2. 序列化
     ├─ privDER = x509.MarshalPKCS8PrivateKey(privKey)
     └─ pubDER  = x509.MarshalPKIXPublicKey(pubKey)

  3. 三层加密 (encryptAndStoreCert)
     ├─ ① tempKey     = crypto/rand(32B)        // 临时密钥
     ├─ ② tempKeySalt = crypto/rand(32B)        // 盐值
     ├─ ③ 加密密钥    = HMAC-SHA256(masterKey, tempKeySalt)
     ├─ ④ tempKeyEnc  = AES-256-GCM(加密密钥, tempKey)
     └─ ⑤ privateData = AES-256-GCM(tempKey, privDER)

  4. 存储 Certificate{
       cert_content:  pubDER,
       temp_key_salt: tempKeySalt,
       temp_key_enc:  tempKeyEnc,
       private_data:  privateData
     }`}</pre>

      <h3>解密流程（签名/解密操作时）</h3>
      <pre>{`Sign(handle, mechanism, data)：

  前提: 已通过 Login() 解锁 masterKey

  1. cert = objects[handle]                    // 从缓存获取证书
  2. tempKeyAES = HMAC-SHA256(masterKey, cert.TempKeySalt)
  3. tempKey = AES-GCM-Decrypt(tempKeyAES, cert.TempKeyEnc)
  4. privDER = AES-GCM-Decrypt(tempKey, cert.PrivateData)
  5. privKey = x509.ParsePKCS8PrivateKey(privDER)
  6. 执行签名: rsa.SignPKCS1v15 / ecdsa.Sign / ed25519.Sign
  7. zeroBytes(tempKey)  // 清零临时密钥
  8. zeroBytes(privDER)  // 清零私钥 DER`}</pre>

      <h2>🖥️ 三级安全模式对比</h2>
      <table>
        <thead><tr><th>安全等级</th><th>主密钥保护</th><th>私钥保护</th><th>可导出</th></tr></thead>
        <tbody>
          <tr>
            <td><span className="badge badge-blue">Low</span></td>
            <td>PIN 加密主密钥</td>
            <td>masterKey → tempKey → AES 加密</td>
            <td>✅ 可导出</td>
          </tr>
          <tr>
            <td><span className="badge badge-orange">Medium</span></td>
            <td>PIN 加密 + TPM 证书密钥</td>
            <td>masterKey + tpmCertKey 双重保护</td>
            <td>⚠️ 需 AdminKey</td>
          </tr>
          <tr>
            <td><span className="badge badge-green">High (TPM2)</span></td>
            <td>TPM Seal(masterKey) → blob</td>
            <td>TPM 绑定设备，不可导出</td>
            <td>❌ 不可导出</td>
          </tr>
        </tbody>
      </table>

      <h3>TPM2 高安全性模式</h3>
      <pre>{`创建卡片 (TPM2)：
  1. masterKey = crypto/rand(32B)
  2. tpmBlob = TPM.Seal(masterKey)        // TPM 封装
  3. AES密钥 = HMAC(PIN, salt)
  4. enc = AES-GCM(AES密钥, tpmBlob)     // 加密 TPM blob
  5. 存储 CardKeyEntry{enc_master_key = 加密的tpmBlob}

登录解锁 (TPM2)：
  1. AES密钥 = HMAC(PIN, entry.Salt)
  2. tpmBlob = AES-GCM-Decrypt(AES密钥, entry.EncMasterKey)
  3. masterKey = TPM.Unseal(tpmBlob)      // TPM 解封
  4. masterKey 保存到内存`}</pre>

      <h2>🔄 密码修改时的密钥轮换</h2>
      <pre>{`修改 PIN (旧PIN → 新PIN)：

  1. AES密钥 = HMAC(旧PIN, old_entry.Salt)
  2. masterKey = AES-GCM-Decrypt(AES密钥, old_entry.EncMasterKey)
  3. 新salt = crypto/rand(32B)
  4. 新AES密钥 = HMAC(新PIN, 新salt)
  5. 新enc = AES-GCM-Encrypt(新AES密钥, masterKey)
  6. 原子更新: 替换 pin_entry = {salt: 新salt, enc: 新enc}

  注意: 证书的 tempKey/privateData 无需变更
  因为 masterKey 本身没变，只是加密 masterKey 的密码变了`}</pre>

      <h2>📊 加密参数汇总</h2>
      <table>
        <thead><tr><th>组件</th><th>算法</th><th>密钥</th><th>Nonce</th><th>Tag</th><th>盐值</th></tr></thead>
        <tbody>
          {[
            ['主密钥加密', 'AES-256-GCM', '32B', '12B', '16B', '32B'],
            ['临时密钥加密', 'AES-256-GCM', '32B', '12B', '16B', '32B'],
            ['私钥加密', 'AES-256-GCM', '32B', '12B', '16B', '—'],
            ['PUK加密PIN', 'AES-256-GCM', '32B', '12B', '16B', '32B'],
            ['密钥派生(新)', 'Argon2id', '32B输出', '—', '—', '32B'],
            ['密钥派生(旧)', 'HMAC-SHA256', '32B输出', '—', '—', '32B'],
            ['随机数生成', 'crypto/rand', '—', '—', '—', '—'],
          ].map(([c, a, k, n, t, s]) => (
            <tr key={c}><td><strong>{c}</strong></td><td>{a}</td><td>{k}</td><td>{n}</td><td>{t}</td><td>{s}</td></tr>
          ))}
        </tbody>
      </table>

      <h2>🛡️ 安全设计要点</h2>

      <div className="callout callout-info">
        <strong>GCM 认证标签作为密码验证机制</strong>
        <p>不单独存储密码哈希，而是通过 GCM 解密成功/失败来验证密码正确性。GCM 的 16 字节认证标签本身就是密码正确性的证明。</p>
      </div>

      <div className="callout callout-info">
        <strong>每证书独立临时密钥</strong>
        <p>每个 Certificate 有独立的 tempKey + tempKeySalt。单个证书泄露不影响其他证书，删除证书时只需清除该证书的加密数据。</p>
      </div>

      <div className="callout callout-warning">
        <strong>内存安全</strong>
        <p>所有密钥使用后立即清零：defer zeroBytes(masterKey)、defer zeroBytes(tempKey)。Logout 时清零 slot.masterKey 并清空对象缓存。</p>
      </div>

      <h2>📁 代码文件对照</h2>
      <table>
        <thead><tr><th>流程</th><th>文件</th><th>函数</th></tr></thead>
        <tbody>
          {[
            ['主密钥生成', 'card/local/keymgr.go', 'CreateCardWithCreds()'],
            ['主密钥加密', 'card/local/keymgr.go', 'encryptMasterKey()'],
            ['主密钥解密', 'card/local/slot.go', 'unlockMasterKey()'],
            ['PIN重置', 'card/local/keymgr.go', 'ResetPIN()'],
            ['证书密钥生成+加密', 'card/local/keymgr.go', 'encryptAndStoreCert()'],
            ['证书密钥解密', 'card/local/slot.go', 'decryptPrivateKey()'],
            ['签名操作', 'card/local/slot.go', 'Sign()'],
            ['TPM2 主密钥加密', 'card/tpm2/keymgr.go', 'encryptTPMBlob()'],
            ['TPM2 主密钥解密', 'card/tpm2/slot.go', 'unlockMasterKey()'],
            ['AES-256-GCM', 'crypto/aes.go', 'EncryptAES256GCM()'],
            ['HMAC-SHA256', 'crypto/hmac.go', 'HMACSHA256()'],
            ['Argon2id', 'crypto/argon2.go', 'DeriveKeyArgon2id()'],
          ].map(([p, f, fn]) => (
            <tr key={p}><td><strong>{p}</strong></td><td><code>{f}</code></td><td><code>{fn}</code></td></tr>
          ))}
        </tbody>
      </table>
    </DocPage>
  )
}

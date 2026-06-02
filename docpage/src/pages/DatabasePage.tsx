import DocPage from '../components/DocPage'

export default function DatabasePage() {
  return (
    <DocPage
      title="数据库设计"
      subtitle="本地 SQLite 与云端 PostgreSQL 的数据模型、表结构与索引设计"
      badge="Database v2.0"
    >
      <h2>🗄️ 数据库架构总览</h2>
      <table>
        <thead><tr><th>组件</th><th>数据库</th><th>特点</th></tr></thead>
        <tbody>
          <tr><td><strong>client-card</strong></td><td>SQLite (SQLCipher)</td><td>零依赖单文件、全库加密、本地存储</td></tr>
          <tr><td><strong>server-card</strong></td><td>PostgreSQL</td><td>高并发、SSL 连接、完整事务支持</td></tr>
        </tbody>
      </table>

      <h2>📦 本地数据库（SQLite / SQLCipher）</h2>

      <h3>users 表</h3>
      <table>
        <thead><tr><th>字段</th><th>类型</th><th>说明</th></tr></thead>
        <tbody>
          {[
            ['uuid', 'TEXT PK', '用户唯一标识'],
            ['user_type', 'TEXT', 'local / cloud'],
            ['display_name', 'TEXT', '显示名称'],
            ['email', 'TEXT', '用户邮箱'],
            ['enabled', 'INTEGER', '是否启用'],
            ['password_hash', 'TEXT', 'Argon2id/bcrypt 哈希'],
            ['cloud_url', 'TEXT', '云端 API URL'],
            ['auth_key', 'BLOB', 'JWT Token（加密存储）'],
            ['created_at', 'TEXT', 'ISO 8601 时间'],
          ].map(([f, t, d]) => <tr key={f}><td><code>{f}</code></td><td>{t}</td><td>{d}</td></tr>)}
        </tbody>
      </table>

      <h3>cards 表</h3>
      <table>
        <thead><tr><th>字段</th><th>类型</th><th>说明</th></tr></thead>
        <tbody>
          {[
            ['uuid', 'TEXT PK', '卡片唯一标识'],
            ['slot_type', 'TEXT', 'local / tpm2 / cloud'],
            ['card_name', 'TEXT', '卡片显示名称'],
            ['user_uuid', 'TEXT FK', '所属用户'],
            ['card_keys', 'TEXT', 'JSON: CardKeyEntry[] 加密主密钥列表'],
            ['security_level', 'TEXT', 'high / medium / low'],
            ['pin_retries', 'INTEGER', 'PIN 最大重试次数（默认 3）'],
            ['pin_failed_count', 'INTEGER', '当前连续错误次数'],
            ['pin_locked', 'INTEGER', 'PIN 是否被锁定'],
            ['tpm_cert_key_enc', 'BLOB', 'medium 模式：加密的 TPM 证书密钥'],
            ['tpm_cert_key_salt', 'BLOB', 'medium 模式：盐值'],
            ['cloud_url', 'TEXT', 'Cloud Slot：服务地址'],
            ['cloud_card_uuid', 'TEXT', 'Cloud Slot：远端卡片 UUID'],
            ['expires_at', 'TEXT', '有效期'],
          ].map(([f, t, d]) => <tr key={f}><td><code>{f}</code></td><td>{t}</td><td>{d}</td></tr>)}
        </tbody>
      </table>

      <h3>certificates 表</h3>
      <table>
        <thead><tr><th>字段</th><th>类型</th><th>说明</th></tr></thead>
        <tbody>
          {[
            ['uuid', 'TEXT PK', '证书唯一标识'],
            ['slot_type', 'TEXT', 'local / tpm2 / cloud'],
            ['card_uuid', 'TEXT FK', '所属卡片'],
            ['cert_type', 'TEXT', 'x509/ssh/gpg/totp/fido-umdf/login/note/payment/text'],
            ['key_type', 'TEXT', 'rsa2048/ec256/ed25519/...'],
            ['cert_content', 'BLOB', '公开部分（公钥 DER / 证书 DER）'],
            ['temp_key_salt', 'BLOB', '32 字节随机盐值'],
            ['temp_key_enc', 'BLOB', '加密的临时密钥'],
            ['private_data', 'BLOB', '加密的私钥/私密数据'],
            ['tpm_platform', 'TEXT', 'tpm2 / medium / 空'],
            ['tpm_private_blob', 'BLOB', 'TPM Seal 后的密钥 blob'],
            ['tpm_public_blob', 'BLOB', 'TPM 公钥 blob'],
            ['tpm_pcr_policy', 'BLOB', 'PCR 策略'],
            ['tpm_auth_policy', 'BLOB', 'TPM 证书密钥盐值引用'],
          ].map(([f, t, d]) => <tr key={f}><td><code>{f}</code></td><td>{t}</td><td>{d}</td></tr>)}
        </tbody>
      </table>

      <h3>logs 表</h3>
      <table>
        <thead><tr><th>字段</th><th>类型</th><th>说明</th></tr></thead>
        <tbody>
          {[
            ['id', 'INTEGER PK', '自增 ID'],
            ['log_type', 'TEXT', 'operation / security / error'],
            ['slot_type', 'TEXT', '关联的 Slot 类型'],
            ['card_uuid', 'TEXT', '关联的卡片'],
            ['user_uuid', 'TEXT', '操作用户'],
            ['log_level', 'TEXT', 'debug / info / warn / error'],
            ['recorded_at', 'TEXT', '记录时间'],
            ['title', 'TEXT', '日志标题'],
            ['content', 'TEXT', '日志内容'],
          ].map(([f, t, d]) => <tr key={f}><td><code>{f}</code></td><td>{t}</td><td>{d}</td></tr>)}
        </tbody>
      </table>

      <h2>☁️ 云端数据库（PostgreSQL）</h2>

      <h3>核心表一览</h3>
      <table>
        <thead><tr><th>表名</th><th>说明</th><th>关键字段</th></tr></thead>
        <tbody>
          {[
            ['users', '用户管理', 'uuid, email, role, password_hash, totp_secret'],
            ['storage_zones', '存储区域', 'uuid, name, storage_type, driver_config'],
            ['cards', '云端智能卡', 'uuid, user_uuid, zone_uuid, card_keys'],
            ['certificates', '证书存储', 'uuid, card_uuid, cert_type, private_data_enc'],
            ['cas', 'CA 管理', 'uuid, cert_pem, priv_key_enc, chain_pem'],
            ['cert_templates', '颁发模板', 'uuid, name, subject_tmpl, ext_tmpl, ku_tmpl'],
            ['subject_templates', '主体模板', 'uuid, fields_config'],
            ['extension_templates', '扩展信息模板', 'uuid, san_config, validation_rules'],
            ['key_usage_templates', '密钥用途模板', 'uuid, key_usages, ext_key_usages'],
            ['cert_ext_templates', '证书拓展模板', 'uuid, crl_points, ocsp_urls, aia'],
            ['key_storage_templates', '密钥存储模板', 'uuid, storage_modes, security_level'],
            ['cert_apply_templates', '证书申请模板', 'uuid, cert_tmpl_uuid, ca_uuid'],
            ['orders', '证书订单', 'uuid, user_uuid, status, amount'],
            ['cert_applications', '证书申请', 'uuid, order_uuid, status, subject_json'],
            ['subject_infos', '主体信息', 'uuid, user_uuid, field_values, status'],
            ['extension_infos', '扩展信息', 'uuid, user_uuid, san_entries, status'],
            ['oids', 'OID 管理', 'uuid, oid_value, name, category'],
            ['revocation_services', '吊销服务', 'uuid, ca_uuid, crl_path, ocsp_path'],
            ['acme_configs', 'ACME 配置', 'uuid, path, ca_uuid, cert_tmpl_uuid'],
            ['ct_entries', 'CT 记录', 'uuid, cert_uuid, ct_server, sct'],
            ['totp_entries', 'TOTP 条目', 'uuid, user_uuid, secret_enc, algorithm'],
            ['payment_plugins', '支付插件', 'uuid, name, provider, config_enc'],
            ['audit_logs', '审计日志', 'id, user_uuid, action, resource, details'],
          ].map(([t, d, f]) => <tr key={t}><td><code>{t}</code></td><td>{d}</td><td style={{ fontSize: '0.75rem' }}>{f}</td></tr>)}
        </tbody>
      </table>

      <h3>关键索引设计</h3>
      <pre>{`-- 用户表
CREATE UNIQUE INDEX idx_users_email ON users(email);

-- 卡片表
CREATE INDEX idx_cards_user ON cards(user_uuid);
CREATE INDEX idx_cards_zone ON cards(zone_uuid);

-- 证书表
CREATE INDEX idx_certs_card ON certificates(card_uuid);
CREATE INDEX idx_certs_type ON certificates(cert_type);
CREATE INDEX idx_certs_serial ON certificates(serial_number);

-- 订单表
CREATE INDEX idx_orders_user ON orders(user_uuid);
CREATE INDEX idx_orders_status ON orders(status);

-- 证书申请
CREATE INDEX idx_applications_user ON cert_applications(user_uuid);
CREATE INDEX idx_applications_status ON cert_applications(status);

-- 审计日志
CREATE INDEX idx_audit_user ON audit_logs(user_uuid);
CREATE INDEX idx_audit_time ON audit_logs(created_at);
CREATE INDEX idx_audit_action ON audit_logs(action);`}</pre>

      <h2>🔐 数据安全设计</h2>

      <div className="callout callout-warning">
        <strong>敏感数据加密存储</strong>
        <p>所有私钥、密码、Token 等敏感数据均加密存储，数据库中不存在任何明文敏感信息。</p>
      </div>

      <table>
        <thead><tr><th>数据类型</th><th>加密方式</th><th>说明</th></tr></thead>
        <tbody>
          {[
            ['卡片主密钥', 'AES-256-GCM（密码派生密钥）', 'CardKeyEntry.enc_master_key'],
            ['证书私钥', 'AES-256-GCM（临时密钥）', 'certificates.private_data'],
            ['临时密钥', 'AES-256-GCM（主密钥派生）', 'certificates.temp_key_enc'],
            ['CA 私钥', 'AES-256-GCM（系统主密钥）', 'cas.priv_key_enc'],
            ['TOTP 密钥', 'AES-256-GCM（用户密钥）', 'totp_entries.secret_enc'],
            ['支付配置', 'AES-256-GCM（系统密钥）', 'payment_plugins.config_enc'],
            ['用户密码', 'bcrypt / Argon2id 哈希', '不可逆，仅验证'],
          ].map(([d, e, f]) => <tr key={d}><td><strong>{d}</strong></td><td>{e}</td><td><code style={{ fontSize: '0.75rem' }}>{f}</code></td></tr>)}
        </tbody>
      </table>

      <h2>📊 数据迁移</h2>
      <p>使用版本化迁移脚本管理数据库 Schema 变更：</p>
      <pre>{`migrations/
├── 001_init.sql           # 初始表结构
├── 002_add_pki.sql        # PKI 相关表
├── 003_add_security.sql   # 安全字段扩展
├── 004_add_totp.sql       # TOTP 表
├── 005_add_credentials.sql # 通用凭据支持
├── 006_add_audit.sql      # 审计日志表
├── 007_add_tpm_fields.sql # TPM 字段扩展
└── 008_add_cloud_fields.sql # Cloud Slot 字段`}</pre>
    </DocPage>
  )
}

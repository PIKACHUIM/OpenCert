// Package mailer 提供 SMTP 邮件发送能力。
// 当 SMTP 未启用时，Send 方法直接把内容写入日志，不发邮件（便于本地/测试环境）。
package mailer

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/globaltrusts/server-card/configs"
)

// Mailer 是邮件发送器接口。
type Mailer interface {
	// Send 向 to 发送主题为 subject、正文为 body（text/plain）的邮件。
	Send(to, subject, body string) error
}

// New 根据配置创建 Mailer 实例。
// - 若 cfg.Enabled=false，返回 nopMailer（仅写日志）；
// - 否则返回 smtpMailer。
func New(cfg configs.SMTPConfig) Mailer {
	if !cfg.Enabled || cfg.Host == "" {
		return &nopMailer{}
	}
	return &smtpMailer{cfg: cfg}
}

// nopMailer 不真实发送，仅 info 级别日志。
type nopMailer struct{}

func (m *nopMailer) Send(to, subject, body string) error {
	slog.Info("mailer: SMTP 未启用，仅记录日志",
		"to", to, "subject", subject, "body", body)
	return nil
}

// smtpMailer 使用 net/smtp 发送，支持 STARTTLS 与隐式 SSL 两种加密方式。
type smtpMailer struct {
	cfg configs.SMTPConfig
}

// tlsMode 返回实际使用的加密方式，兼容只配置了 UseTLS 的历史数据。
func (m *smtpMailer) tlsMode() string {
	mode := strings.ToLower(strings.TrimSpace(m.cfg.TLSMode))
	if mode == "" {
		if m.cfg.UseTLS {
			return "starttls"
		}
		if m.cfg.Port == 465 {
			return "ssl"
		}
		return "starttls"
	}
	return mode
}

func (m *smtpMailer) timeout() time.Duration {
	if m.cfg.TimeoutSeconds > 0 {
		return time.Duration(m.cfg.TimeoutSeconds) * time.Second
	}
	return 15 * time.Second
}

func (m *smtpMailer) Send(to, subject, body string) error {
	if to == "" {
		return fmt.Errorf("收件人为空")
	}
	addr := fmt.Sprintf("%s:%d", m.cfg.Host, m.cfg.Port)
	if m.cfg.Port == 0 {
		addr = net.JoinHostPort(m.cfg.Host, "587")
	}

	from := m.cfg.From
	if from == "" {
		from = m.cfg.Username
	}
	if from == "" {
		return fmt.Errorf("未配置发件地址")
	}
	fromHeader := from
	if m.cfg.FromName != "" {
		fromHeader = fmt.Sprintf("%s <%s>", m.cfg.FromName, from)
	}
	msg := buildMessage(fromHeader, to, subject, body)

	var auth smtp.Auth
	if m.cfg.Username != "" {
		auth = smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
	}

	if err := m.deliver(addr, auth, from, to, msg); err != nil {
		return fmt.Errorf("SMTP 发送失败: %w", err)
	}
	return nil
}

// deliver 按加密方式投递：ssl 直接建 TLS 连接，starttls / none 走 Dial。
func (m *smtpMailer) deliver(addr string, auth smtp.Auth, from, to string, msg []byte) error {
	mode := m.tlsMode()
	if mode != "ssl" {
		// net/smtp 自带 STARTTLS 协商与超时控制，加密方式为 none 时会自动降级
		return smtp.SendMail(addr, auth, from, []string{to}, msg)
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	dialer := &net.Dialer{Timeout: m.timeout()}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(m.timeout())); err != nil {
		return err
	}

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer client.Close() //nolint:errcheck
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return err
		}
	}
	if err := client.Mail(from); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return client.Quit()
}

// buildMessage 拼接最小可用的邮件消息（UTF-8 + 纯文本）。
func buildMessage(from, to, subject, body string) []byte {
	headers := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=\"UTF-8\"\r\n\r\n",
		from, to, subject,
	)
	return []byte(headers + body)
}

package auth

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Message is a plain-text email.
type Message struct {
	To      string
	Subject string
	Text    string
}

// Mailer sends email.
type Mailer interface {
	Send(ctx context.Context, m Message) error
}

func validateHeaders(m Message) error {
	if strings.ContainsAny(m.To, "\r\n") || strings.ContainsAny(m.Subject, "\r\n") {
		return errors.New("mailer: header injection attempt")
	}
	if _, err := mail.ParseAddress(m.To); err != nil {
		return fmt.Errorf("mailer: invalid recipient: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------

// SMTPConfig configures SMTPMailer.
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string // "WireMesh <noreply@example.com>"
	TLS      string // starttls | tls | none
}

// SMTPMailer sends via an SMTP relay (e.g. Postmark, SES, Mailgun, your own MTA).
type SMTPMailer struct{ cfg SMTPConfig }

// NewSMTPMailer validates cfg and returns a mailer.
func NewSMTPMailer(cfg SMTPConfig) (*SMTPMailer, error) {
	if _, err := mail.ParseAddress(cfg.From); err != nil {
		return nil, fmt.Errorf("invalid SMTP from address %q: %w", cfg.From, err)
	}
	return &SMTPMailer{cfg: cfg}, nil
}

// Send delivers m, honouring ctx's deadline for the whole SMTP exchange.
func (s *SMTPMailer) Send(ctx context.Context, m Message) error {
	if err := validateHeaders(m); err != nil {
		return err
	}
	from, _ := mail.ParseAddress(s.cfg.From)
	to, _ := mail.ParseAddress(m.To)

	addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
	tlsCfg := &tls.Config{ServerName: s.cfg.Host, MinVersion: tls.VersionTLS12}
	d := net.Dialer{Timeout: 15 * time.Second}

	var conn net.Conn
	var err error
	if s.cfg.TLS == "tls" {
		conn, err = (&tls.Dialer{NetDialer: &d, Config: tlsCfg}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	}
	c, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp handshake: %w", err)
	}
	defer c.Close()

	if s.cfg.TLS == "starttls" {
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
	}
	if s.cfg.Username != "" {
		// PlainAuth refuses to send credentials over an unencrypted connection
		// to a non-localhost server.
		if err := c.Auth(smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(from.Address); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	if err := c.Rcpt(to.Address); err != nil {
		return fmt.Errorf("smtp RCPT TO: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := w.Write(buildMessage(s.cfg.From, from.Address, m)); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp end data: %w", err)
	}
	return c.Quit()
}

func buildMessage(fromHeader, fromAddr string, m Message) []byte {
	var id [12]byte
	_, _ = rand.Read(id[:])
	domain := "wiremesh"
	if _, d, ok := strings.Cut(fromAddr, "@"); ok {
		domain = d
	}
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", fromHeader)
	fmt.Fprintf(&b, "To: %s\r\n", m.To)
	fmt.Fprintf(&b, "Subject: %s\r\n", mimeEncode(m.Subject))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%s@%s>\r\n", hex.EncodeToString(id[:]), domain)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	b.WriteString("Auto-Submitted: auto-generated\r\n\r\n")
	// Normalize line endings and dot-stuffing is handled by smtp's DATA writer.
	b.WriteString(strings.ReplaceAll(strings.ReplaceAll(m.Text, "\r\n", "\n"), "\n", "\r\n"))
	return []byte(b.String())
}

func mimeEncode(s string) string {
	for _, r := range s {
		if r > 127 {
			return "=?UTF-8?B?" + base64Std(s) + "?="
		}
	}
	return s
}

// ---------------------------------------------------------------------------

// LogMailer writes emails to the log instead of sending them. Development only:
// it logs verification and reset links, which are secrets.
type LogMailer struct{ Log *slog.Logger }

func (l LogMailer) Send(_ context.Context, m Message) error {
	if err := validateHeaders(m); err != nil {
		return err
	}
	l.Log.Info("email (not sent: development log mailer)", "to", m.To, "subject", m.Subject, "body", m.Text)
	return nil
}

// DiscardMailer drops email (production with email features disabled).
type DiscardMailer struct{ Log *slog.Logger }

func (d DiscardMailer) Send(_ context.Context, m Message) error {
	d.Log.Warn("email dropped: no SMTP server configured", "subject", m.Subject)
	return nil
}

// ---------------------------------------------------------------------------

// AsyncMailer queues messages and sends them from a background worker, so
// HTTP handlers don't block on SMTP and response timing doesn't reveal
// whether an email was sent (account enumeration).
type AsyncMailer struct {
	next  Mailer
	log   *slog.Logger
	queue chan Message
	wg    sync.WaitGroup
	once  sync.Once
}

// NewAsyncMailer starts a worker with a bounded queue.
func NewAsyncMailer(next Mailer, log *slog.Logger, queueSize int) *AsyncMailer {
	a := &AsyncMailer{next: next, log: log, queue: make(chan Message, queueSize)}
	a.wg.Add(1)
	go a.run()
	return a
}

// Send enqueues m. It returns an error only if the queue is full.
func (a *AsyncMailer) Send(_ context.Context, m Message) error {
	if err := validateHeaders(m); err != nil {
		return err
	}
	select {
	case a.queue <- m:
		return nil
	default:
		a.log.Error("email queue full; dropping message", "subject", m.Subject)
		return errors.New("mailer: queue full")
	}
}

func (a *AsyncMailer) run() {
	defer a.wg.Done()
	for m := range a.queue {
		var err error
		for attempt := 0; attempt < 3; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err = a.next.Send(ctx, m)
			cancel()
			if err == nil {
				break
			}
			time.Sleep(time.Duration(attempt+1) * 2 * time.Second)
		}
		if err != nil {
			a.log.Error("sending email failed", "subject", m.Subject, "error", err)
		}
	}
}

// Close stops accepting messages and waits for the queue to drain.
func (a *AsyncMailer) Close() {
	a.once.Do(func() { close(a.queue) })
	a.wg.Wait()
}

// ---------------------------------------------------------------------------

// CaptureMailer records messages; used by tests.
type CaptureMailer struct {
	mu   sync.Mutex
	Sent []Message
}

func (c *CaptureMailer) Send(_ context.Context, m Message) error {
	if err := validateHeaders(m); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Sent = append(c.Sent, m)
	return nil
}

// Last returns the most recent message sent to addr.
func (c *CaptureMailer) Last(addr string) (Message, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := len(c.Sent) - 1; i >= 0; i-- {
		if c.Sent[i].To == addr {
			return c.Sent[i], true
		}
	}
	return Message{}, false
}

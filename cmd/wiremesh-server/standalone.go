package main

// Standalone mode: one process, no Docker. It runs an embedded PostgreSQL
// (binaries shipped next to the executable), the control server, the
// dashboard, the packet relay and STUN, all configured automatically.
//
//	wiremesh-server standalone                 run in the foreground
//	wiremesh-server standalone install         Windows: install + start as a service
//	wiremesh-server standalone uninstall       Windows: remove the service (data is kept)

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"

	"github.com/siv151992-lang/network-connector/internal/config"
	"github.com/siv151992-lang/network-connector/internal/db"
	"github.com/siv151992-lang/network-connector/internal/logging"
	"github.com/siv151992-lang/network-connector/pkg/relayproto"
	"github.com/siv151992-lang/network-connector/pkg/stun"
	"github.com/siv151992-lang/network-connector/relay"
)

// PostgreSQL version of the bundled binaries (zonky embedded-postgres-binaries).
const bundledPostgres = "16.4.0"

type standaloneOpts struct {
	Data, Addr, URL, Web, Postgres, STUNAddr string
	PGPort                                   uint
}

func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	return filepath.Dir(exe)
}

func defaultDataDir() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "WireMesh Server")
	}
	return "/var/lib/wiremesh-server"
}

func runStandalone(args []string) error {
	fs := flag.NewFlagSet("standalone", flag.ExitOnError)
	o := standaloneOpts{}
	fs.StringVar(&o.Data, "data", defaultDataDir(), "data directory (database, keys, logs)")
	fs.StringVar(&o.Addr, "addr", ":80", "HTTP listen address (dashboard, API, relay)")
	fs.StringVar(&o.URL, "url", "", "address devices use to reach this server (default http://<this machine's LAN IP>)")
	fs.StringVar(&o.Web, "web", filepath.Join(exeDir(), "web"), "dashboard files")
	fs.StringVar(&o.Postgres, "postgres", filepath.Join(exeDir(), "postgres-"+runtime.GOOS+"-"+runtime.GOARCH+".txz"), "bundled PostgreSQL archive")
	fs.StringVar(&o.STUNAddr, "stun-addr", ":3478", "STUN listen address (UDP)")
	fs.UintVar(&o.PGPort, "pg-port", 54329, "embedded PostgreSQL port (localhost only)")
	sub := ""
	if len(args) > 0 && (args[0] == "install" || args[0] == "uninstall") {
		sub, args = args[0], args[1:]
	}
	_ = fs.Parse(args)
	switch sub {
	case "install":
		return installServerService(args)
	case "uninstall":
		return uninstallServerService()
	}
	start := func(ctx context.Context) error { return standalone(ctx, o) }
	if ok, err := runServerService(start); ok {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return start(ctx)
}

// readOrCreate returns the file's trimmed contents, creating it with gen() first.
func readOrCreate(p string, gen func() (string, error)) (string, error) {
	if b, err := os.ReadFile(p); err == nil {
		return strings.TrimSpace(string(b)), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	v, err := gen()
	if err != nil {
		return "", err
	}
	return v, os.WriteFile(p, []byte(v+"\n"), 0o600)
}

func randomString(n int, enc func([]byte) string) func() (string, error) {
	return func() (string, error) {
		b := make([]byte, n)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		return enc(b), nil
	}
}

// lanIP is the address of the interface used for outbound traffic (no packet is sent).
func lanIP() string {
	c, err := net.Dial("udp4", "192.0.2.1:9")
	if err != nil {
		return "127.0.0.1"
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String()
}

func setDefault(k, v string) {
	if os.Getenv(k) == "" {
		_ = os.Setenv(k, v)
	}
}

func standalone(ctx context.Context, o standaloneOpts) error {
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		return errors.New("PostgreSQL refuses to run as root: run standalone mode as a regular user (e.g. a 'wiremesh' system user)")
	}
	if err := os.MkdirAll(o.Data, 0o700); err != nil {
		return err
	}
	if err := secureDataDir(o.Data); err != nil {
		return fmt.Errorf("secure %s: %w", o.Data, err)
	}
	logFile, err := os.OpenFile(filepath.Join(o.Data, "server.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer logFile.Close()
	logOut := io.MultiWriter(os.Stderr, logFile)

	secret, err := readOrCreate(filepath.Join(o.Data, "secret.key"), randomString(32, base64.StdEncoding.EncodeToString))
	if err != nil {
		return err
	}
	dbPass, err := readOrCreate(filepath.Join(o.Data, "db.pass"), randomString(24, hex.EncodeToString))
	if err != nil {
		return err
	}

	pg, err := startEmbeddedPostgres(o, dbPass, logOut)
	if err != nil {
		return err
	}
	defer func() {
		if err := pg.Stop(); err != nil {
			fmt.Fprintln(logOut, "stop postgres:", err)
		}
	}()

	pub := o.URL
	if pub == "" {
		pub = "http://" + lanIP()
		if _, port, _ := net.SplitHostPort(o.Addr); port != "" && port != "80" {
			pub = "http://" + net.JoinHostPort(lanIP(), port)
		}
	} else if !strings.Contains(pub, "://") {
		pub = "http://" + pub
	}
	pub = strings.TrimRight(pub, "/")
	pu, err := url.Parse(pub)
	if err != nil || pu.Host == "" {
		return fmt.Errorf("invalid --url %q", o.URL)
	}
	_, stunPort, _ := net.SplitHostPort(o.STUNAddr)
	env := "development" // plain HTTP on a LAN
	if pu.Scheme == "https" {
		env = "production"
	}
	setDefault("WIREMESH_ENV", env)
	setDefault("WIREMESH_HTTP_ADDR", o.Addr)
	setDefault("WIREMESH_PUBLIC_URL", pub)
	setDefault("WIREMESH_DATABASE_URL", fmt.Sprintf("postgres://wiremesh:%s@127.0.0.1:%d/wiremesh?sslmode=disable", dbPass, o.PGPort))
	setDefault("WIREMESH_SECRET_KEY", secret)
	setDefault("WIREMESH_REQUIRE_EMAIL_VERIFICATION", "false")
	setDefault("WIREMESH_FIRST_USER_SETUP", "true")
	setDefault("WIREMESH_STUN_SERVERS", net.JoinHostPort(pu.Hostname(), stunPort))
	setDefault("WIREMESH_RELAY_URLS", pub+"/relay")
	setDefault("WIREMESH_LOG_FORMAT", "text")

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("invalid configuration:\n%w", err)
	}
	log := logging.New(logOut, cfg.LogLevel, cfg.LogFormat)
	slog.SetDefault(log)

	pool, err := db.Open(ctx, cfg.DatabaseURL, db.Options{
		MaxConns: cfg.DBMaxConns, MaxConnLifetime: time.Hour, ConnectTimeout: 10 * time.Second,
	})
	if err != nil {
		return err
	}
	defer pool.Close()

	stunSrv := &stun.Server{Log: log}
	if err := stunSrv.Listen(o.STUNAddr); err != nil {
		return fmt.Errorf("STUN on %s: %w", o.STUNAddr, err)
	}
	go func() { _ = stunSrv.Serve(ctx) }()

	sk, err := relayproto.SigningKey(cfg.SecretKey)
	if err != nil {
		return err
	}
	rs := &relay.Server{ControlKey: sk.Public().(ed25519.PublicKey), Log: log}

	var web http.Handler
	if fi, err := os.Stat(filepath.Join(o.Web, "index.html")); err == nil && !fi.IsDir() {
		web = spaHandler(o.Web)
	} else {
		log.Warn("dashboard files not found; serving the API only", "dir", o.Web)
	}
	wrap := func(apiH http.Handler) http.Handler {
		mux := http.NewServeMux()
		mux.Handle("/relay", rs)
		mux.Handle("/api/", apiH)
		mux.Handle("/healthz", apiH)
		mux.Handle("/readyz", apiH)
		if web != nil {
			mux.Handle("/", web)
		} else {
			mux.Handle("/", apiH)
		}
		return mux
	}
	log.Info("WireMesh standalone server ready: open the dashboard in a browser", "url", pub, "data", o.Data)
	return serve(ctx, cfg, log, pool, wrap)
}

func startEmbeddedPostgres(o standaloneOpts, password string, logOut io.Writer) (*embeddedpostgres.EmbeddedPostgres, error) {
	if _, err := os.Stat(o.Postgres); err != nil {
		return nil, fmt.Errorf("bundled PostgreSQL not found at %s (keep the files from the zip together)", o.Postgres)
	}
	// The library looks for its cache file by this name; point it at the bundled archive.
	osName, arch := runtime.GOOS, runtime.GOARCH
	if osName == "linux" && arch == "arm64" {
		arch = "arm64v8"
	}
	// The library writes temp files; keep them in our private data directory.
	tmp := filepath.Join(o.Data, "tmp")
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return nil, err
	}
	for _, k := range []string{"TMPDIR", "TMP", "TEMP"} {
		_ = os.Setenv(k, tmp)
	}
	cache := filepath.Join(o.Data, "pg-cache")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		return nil, err
	}
	cached := filepath.Join(cache, fmt.Sprintf("embedded-postgres-binaries-%s-%s-%s.txz", osName, arch, bundledPostgres))
	if fi, err := os.Stat(cached); err != nil || fi.Size() == 0 {
		if err := copyFile(o.Postgres, cached); err != nil {
			return nil, err
		}
	}
	runtimeDir := filepath.Join(o.Data, "pg-runtime")
	dataDir := filepath.Join(o.Data, "pg-data")
	// A previous run that crashed can leave PostgreSQL running; stop it first.
	if pgctl := filepath.Join(runtimeDir, "bin", "pg_ctl"); fileExists(pgctl) || fileExists(pgctl+".exe") {
		_ = exec.Command(pgctl, "stop", "-w", "-m", "fast", "-D", dataDir).Run()
	}
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().
		Version(embeddedpostgres.PostgresVersion(bundledPostgres)).
		Port(uint32(o.PGPort)).
		Username("wiremesh").Password(password).Database("wiremesh").
		CachePath(cache).RuntimePath(runtimeDir).DataPath(dataDir).
		StartParameters(map[string]string{"listen_addresses": "127.0.0.1", "unix_socket_directories": ""}).
		StartTimeout(2 * time.Minute).
		Logger(logOut))
	if err := pg.Start(); err != nil {
		return nil, fmt.Errorf("start embedded PostgreSQL: %w", err)
	}
	return pg, nil
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// spaHandler serves the dashboard: real files as-is, every other path gets
// index.html (client-side routes), with the same strict CSP as the Caddy setup.
func spaHandler(dir string) http.Handler {
	files := http.FileServer(http.Dir(dir))
	index := filepath.Join(dir, "index.html")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; connect-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		p := path.Clean("/" + r.URL.Path)
		if p != "/" {
			if fi, err := os.Stat(filepath.Join(dir, filepath.FromSlash(p))); err == nil && !fi.IsDir() {
				if strings.HasPrefix(p, "/assets/") {
					h.Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				files.ServeHTTP(w, r)
				return
			}
		}
		h.Set("Cache-Control", "no-cache")
		http.ServeFile(w, r, index)
	})
}

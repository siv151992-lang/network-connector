//go:build windows

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serverServiceName = "WireMeshServer"

func installServerService(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager (run as Administrator): %w", err)
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serverServiceName); err == nil {
		_, _ = s.Control(svc.Stop)
		time.Sleep(3 * time.Second)
		_ = s.Delete()
		s.Close()
		time.Sleep(time.Second)
	}
	// Fix the address devices use now: at boot the network may not be up yet.
	hasURL := false
	for _, a := range args {
		if a == "--url" || a == "-url" || strings.HasPrefix(a, "--url=") || strings.HasPrefix(a, "-url=") {
			hasURL = true
		}
	}
	if !hasURL {
		args = append(args, "--url", "http://"+lanIP())
	}
	s, err := m.CreateService(serverServiceName, exe, mgr.Config{
		DisplayName: "WireMesh Server",
		// Like PostgreSQL's own Windows service: a low-privilege built-in account.
		ServiceStartName: `NT AUTHORITY\NetworkService`,
		Description:      "WireMesh control server, dashboard and relay",
		StartType:        mgr.StartAutomatic,
	}, append([]string{"standalone"}, args...)...)
	if err != nil {
		return err
	}
	defer s.Close()
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 5 * time.Second}}, 60)
	// Firewall: dashboard/API/relay (TCP 80) and STUN (UDP 3478).
	for _, r := range [][]string{{"WireMesh Server HTTP", "TCP", "80"}, {"WireMesh Server STUN", "UDP", "3478"}} {
		_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+r[0]).Run()
		_ = exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name="+r[0], "dir=in", "action=allow", "protocol="+r[1], "localport="+r[2]).Run()
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("installed, but failed to start: %w", err)
	}
	fmt.Println("WireMesh Server installed and started")
	return nil
}

func uninstallServerService() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serverServiceName)
	if err != nil {
		return fmt.Errorf("service not installed: %w", err)
	}
	defer s.Close()
	_, _ = s.Control(svc.Stop)
	if err := s.Delete(); err != nil {
		return err
	}
	for _, n := range []string{"WireMesh Server HTTP", "WireMesh Server STUN"} {
		_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+n).Run()
	}
	fmt.Println("WireMesh Server removed (data kept in", defaultDataDir()+")")
	return nil
}

type serverHandler struct{ start func(context.Context) error }

func (h serverHandler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.start(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			cancel()
			if err != nil {
				return true, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: 30000}
				cancel()
				<-done
				return false, 0
			}
		}
	}
}

func runServerService(start func(context.Context) error) (bool, error) {
	is, err := svc.IsWindowsService()
	if err != nil || !is {
		return false, err
	}
	return true, svc.Run(serverServiceName, serverHandler{start: start})
}

// secureDataDir limits the data directory (secret key, database) to SYSTEM,
// Administrators and the account running the server. PostgreSQL runs with a
// restricted token that drops Administrators, so the account itself is listed.
func secureDataDir(dir string) error {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;%s)", u.User.Sid.String()))
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

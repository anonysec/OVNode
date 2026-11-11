// Copyright (c) 2026 anonysec
// SPDX-License-Identifier: MIT

package httpapi

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"ovnode/internal/ovpn"
	"ovnode/internal/pki"
	"ovnode/internal/store"
)

type providerResult struct {
	Code int    `json:"code"`
	Body string `json:"body"`
}

func TestProviderHandlerProcess(t *testing.T) {
	mode := os.Getenv("TestPROVIDER_HANDLER")
	if mode == "" {
		return
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ready, proceed := os.NewFile(3, "provider-ready"), os.NewFile(4, "provider-proceed")
	defer ready.Close()
	defer proceed.Close()
	if _, err := fmt.Fprintln(ready, syscall.Gettid()); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(proceed, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	s := NewServer()
	s.APIKey = testKey
	method, path := http.MethodGet, "/sync/download/ovpn/alice"
	switch mode {
	case "delete":
		method, path = http.MethodDelete, "/sync/user/alice"
	case "create":
		method, path = http.MethodPost, "/sync/user"
	case "push":
		method, path = http.MethodPut, "/sync/users/alice"
	case "policy":
		method, path = http.MethodPut, "/sync/user"
	case "limit":
		method, path = http.MethodPut, "/sync/user/limit"
	case "download":
	default:
		t.Fatalf("unknown owned handler fixture %q", mode)
	}
	response := do(t, s, method, path, os.Getenv("TestPROVIDER_BODY"))
	if err := json.NewEncoder(ready).Encode(providerResult{response.Code, response.Body.String()}); err != nil {
		t.Fatal(err)
	}
}

type providerTrace struct {
	cmd    *exec.Cmd
	tid    int
	reader *bufio.Reader
	output bytes.Buffer
}

func startProviderTrace(t *testing.T, mode, body string) *providerTrace {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ready, readyWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	proceed, proceedWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	p := &providerTrace{reader: bufio.NewReader(ready)}
	p.cmd = exec.CommandContext(ctx, exe, "-test.run=^TestProviderHandlerProcess$")
	p.cmd.Env = append(os.Environ(), "TestPROVIDER_HANDLER="+mode, "TestPROVIDER_BODY="+body, "GOMAXPROCS=1")
	p.cmd.ExtraFiles = []*os.File{readyWrite, proceed}
	p.cmd.Stdout, p.cmd.Stderr = &p.output, &p.output
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	readyWrite.Close()
	proceed.Close()
	t.Cleanup(func() {
		p.cmd.Process.Kill()
		ready.Close()
		proceedWrite.Close()
	})
	ready.SetReadDeadline(time.Now().Add(30 * time.Second))
	line, err := p.reader.ReadString('\n')
	if err != nil {
		t.Fatalf("owned handler did not become ready: %v", err)
	}
	p.tid, err = strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.PtraceAttach(p.tid); err != nil {
		t.Fatal(err)
	}
	var wait syscall.WaitStatus
	if _, err := syscall.Wait4(p.tid, &wait, 0x40000000, nil); err != nil {
		t.Fatal(err)
	}
	if err := syscall.PtraceSetOptions(p.tid, syscall.PTRACE_O_TRACESYSGOOD); err != nil {
		t.Fatal(err)
	}
	if _, err := proceedWrite.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	return p
}

func (p *providerTrace) next(t *testing.T) syscall.PtraceRegs {
	t.Helper()
	signal := 0
	for {
		if err := syscall.PtraceSyscall(p.tid, signal); err != nil {
			t.Fatal(err)
		}
		var wait syscall.WaitStatus
		if _, err := syscall.Wait4(p.tid, &wait, 0x40000000, nil); err != nil {
			t.Fatal(err)
		}
		if wait.Exited() || wait.Signaled() {
			t.Fatal("owned handler exited before the controlled syscall/result")
		}
		signal = 0
		if wait.StopSignal() != syscall.Signal(int(syscall.SIGTRAP)|0x80) {
			if wait.StopSignal() != syscall.SIGTRAP {
				signal = int(wait.StopSignal())
			}
			continue
		}
		var regs syscall.PtraceRegs
		if err := syscall.PtraceGetRegs(p.tid, &regs); err != nil {
			t.Fatal(err)
		}
		return regs
	}
}

func (p *providerTrace) until(t *testing.T, target func(syscall.PtraceRegs) bool) syscall.PtraceRegs {
	t.Helper()
	for {
		regs := p.next(t)
		if target(regs) {
			return regs
		}
	}
}

func (p *providerTrace) finish(t *testing.T) providerResult {
	t.Helper()
	p.until(t, func(regs syscall.PtraceRegs) bool {
		return syscallEntry(regs) && regs.Orig_rax == syscall.SYS_WRITE && regs.Rdi == 3
	})
	if err := syscall.PtraceDetach(p.tid); err != nil {
		t.Fatal(err)
	}
	var result providerResult
	if err := json.NewDecoder(p.reader).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if err := p.cmd.Wait(); err != nil {
		t.Fatalf("owned handler failed: %v\n%s", err, p.output.String())
	}
	return result
}

func syscallEntry(regs syscall.PtraceRegs) bool {
	return int64(regs.Rax) == -int64(syscall.ENOSYS)
}

func traceString(t *testing.T, tid int, address uint64) string {
	t.Helper()
	var out []byte
	for len(out) < 4096 {
		word := make([]byte, 8)
		if _, err := syscall.PtracePeekData(tid, uintptr(address)+uintptr(len(out)), word); err != nil {
			t.Fatal(err)
		}
		if index := bytes.IndexByte(word, 0); index >= 0 {
			return string(append(out, word[:index]...))
		}
		out = append(out, word...)
	}
	t.Fatal("controlled syscall path exceeded PATH_MAX")
	return ""
}

func renamePaths(t *testing.T, tid int, regs syscall.PtraceRegs) (string, string) {
	t.Helper()
	switch regs.Orig_rax {
	case syscall.SYS_RENAME:
		return traceString(t, tid, regs.Rdi), traceString(t, tid, regs.Rsi)
	case syscall.SYS_RENAMEAT, 316:
		return traceString(t, tid, regs.Rsi), traceString(t, tid, regs.R10)
	}
	return "", ""
}

func signedFixtureCRL(t *testing.T, path string) *x509.RevocationList {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("real CRL fixture has no PEM block")
	}
	list, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(pki.CACert())
	if err != nil {
		t.Fatal(err)
	}
	block, _ = pem.Decode(data)
	if block == nil {
		t.Fatal("real CA fixture has no PEM block")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := list.CheckSignatureFrom(ca); err != nil {
		t.Fatal(err)
	}
	return list
}

func crlContains(list *x509.RevocationList, cert *x509.Certificate) bool {
	for _, entry := range list.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return true
		}
	}
	return false
}

func TestUserLifecycleRejectsQueuedOperationsAfterDelete(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root required for owned syscall interleaving")
	}
	for _, test := range []struct {
		mode     string
		recreate bool
	}{{"download", false}, {"create", false}, {"push", false}, {"policy", false}, {"limit", false}, {"download", true}, {"policy", true}} {
		name := test.mode
		if test.recreate {
			name += "-replaced"
		}
		t.Run(name, func(t *testing.T) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			mode := test.mode
			s := providerServer(t)
			initRoutePKI(t)
			if err := ovpn.CreateUser("alice", "Alice", 3, nil); err != nil {
				t.Fatal(err)
			}
			certPEM, err := os.ReadFile(pki.IssuedCertPath("alice"))
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(certPEM)
			if block == nil {
				t.Fatal("issued fixture certificate has no PEM block")
			}
			original, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			body := `{"id":"alice","name":"Bob","max_logins":4,"status":"activate"}`
			if mode == "push" {
				key, err := os.ReadFile(pki.ClientKeyPath("alice"))
				if err != nil {
					t.Fatal(err)
				}
				ca, err := os.ReadFile(pki.CACert())
				if err != nil {
					t.Fatal(err)
				}
				data, err := json.Marshal(pushCredentialRequest{CertPEM: string(certPEM), KeyPEM: string(key), CAPEM: string(ca)})
				if err != nil {
					t.Fatal(err)
				}
				body = string(data)
			}
			profile := filepath.Join(pki.UsersDir(), "alice", "client.ovpn")
			if err := os.Remove(profile); err != nil {
				t.Fatal(err)
			}
			deletion := startProviderTrace(t, "delete", "")
			userDir := filepath.Join(pki.UsersDir(), "alice")
			deletion.until(t, func(regs syscall.PtraceRegs) bool {
				return syscallEntry(regs) && regs.Orig_rax == syscall.SYS_UNLINKAT && regs.Rdx&0x200 != 0 && traceString(t, deletion.tid, regs.Rsi) == userDir
			})
			if _, err := os.Stat(pki.IssuedCertPath("alice")); !os.IsNotExist(err) {
				t.Fatalf("fixture did not reach post-revocation material cleanup: %v", err)
			}
			if !crlContains(signedFixtureCRL(t, pki.CRLFile()), original) {
				t.Fatal("fixture did not reach actual durable revocation")
			}
			lockPath := filepath.Join(pki.UsersDir(), ".lifecycle.alice")
			lockBefore, lockErr := os.Stat(lockPath)
			queued := startProviderTrace(t, mode, body)
			blocked := false
			queued.until(t, func(regs syscall.PtraceRegs) bool {
				if !syscallEntry(regs) {
					return false
				}
				if regs.Orig_rax == syscall.SYS_FLOCK {
					path, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", queued.tid, regs.Rdi))
					if err == nil && path == filepath.Join(pki.UsersDir(), ".lifecycle.alice") {
						blocked = true
						return true
					}
				}
				_, target := renamePaths(t, queued.tid, regs)
				return target == profile || target == filepath.Join(userDir, "state")
			})
			var queuedResult, deletionResult providerResult
			var replacementCert, replacementKey []byte
			if blocked {
				deletionResult = deletion.finish(t)
				if test.recreate {
					response := do(t, s, http.MethodPost, "/sync/user", `{"id":"alice","name":"Next Alice","max_logins":0}`)
					if envelopeOf(t, response)["success"] != true {
						t.Fatalf("explicit replacement creation failed: %s", response.Body.String())
					}
					response = do(t, s, http.MethodPut, "/sync/user", `{"id":"alice","status":"deactivate"}`)
					if envelopeOf(t, response)["success"] != true {
						t.Fatalf("replacement policy failed: %s", response.Body.String())
					}
					var err error
					replacementCert, err = os.ReadFile(pki.IssuedCertPath("alice"))
					if err != nil {
						t.Fatal(err)
					}
					replacementKey, err = os.ReadFile(pki.ClientKeyPath("alice"))
					if err != nil {
						t.Fatal(err)
					}
				}
				queuedResult = queued.finish(t)
			} else {
				queuedResult = queued.finish(t)
				deletionResult = deletion.finish(t)
			}
			var envelope map[string]any
			if err := json.Unmarshal([]byte(deletionResult.Body), &envelope); err != nil || deletionResult.Code != http.StatusOK || envelope["success"] != true {
				t.Fatalf("controlled deletion did not succeed: %s (%v)", deletionResult.Body, err)
			}
			list := signedFixtureCRL(t, pki.CRLFile())
			if !crlContains(list, original) {
				t.Error("acknowledged deletion lost its signed CRL entry")
			}
			if strings.HasPrefix(queuedResult.Body, "client\n") {
				_, material, _ := strings.Cut(queuedResult.Body, "<cert>")
				material, _, _ = strings.Cut(material, "</cert>")
				block, _ := pem.Decode([]byte(material))
				if block == nil {
					t.Fatal("queued download did not carry actual certificate material")
				}
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Fatal(err)
				}
				if !crlContains(list, cert) {
					t.Errorf("queued download escaped deletion with unrevoked serial %X", cert.SerialNumber)
				}
			} else {
				if err := json.Unmarshal([]byte(queuedResult.Body), &envelope); err != nil {
					t.Fatal(err)
				}
				if envelope["success"] != false {
					t.Errorf("queued %s acknowledged a deleted generation: %s", mode, queuedResult.Body)
				}
			}
			state, err := store.ReadUserState(pki.UsersDir(), "alice")
			if test.recreate {
				if err != nil || !state.LimitSet || state.Limit != 0 || !state.Disabled || store.ReadName(pki.UsersDir(), "alice") != "Next Alice" {
					t.Errorf("queued operation changed replacement policy: %+v (%v)", state, err)
				}
				cert, certErr := os.ReadFile(pki.IssuedCertPath("alice"))
				key, keyErr := os.ReadFile(pki.ClientKeyPath("alice"))
				if certErr != nil || keyErr != nil || !bytes.Equal(cert, replacementCert) || !bytes.Equal(key, replacementKey) {
					t.Errorf("queued operation changed replacement credentials: %v (%v)", certErr, keyErr)
				}
			} else if err != nil || state.LimitSet || state.Disabled || store.UserExists(pki.UsersDir(), "alice") {
				t.Errorf("queued operation recreated policy after acknowledged deletion: %+v (%v)", state, err)
			}
			if _, err := os.Stat(pki.IssuedCertPath("alice")); !test.recreate && !os.IsNotExist(err) {
				t.Errorf("queued operation recreated issued material after deletion: %v", err)
			}
			lockAfter, err := os.Stat(lockPath)
			if lockErr != nil || err != nil || !os.SameFile(lockBefore, lockAfter) || lockAfter.Mode().Perm() != 0o600 {
				t.Errorf("lifecycle lock did not retain its private stable inode: before=%v after=%v", lockErr, err)
			}
			if !blocked {
				t.Error("provider operation bypassed stable lifecycle serialization")
			}
			t.Logf("queued %s: lifecycle blocked=%t; deletion envelope=%s; queued HTTP=%d, raw profile=%t", mode, blocked, strings.TrimSpace(deletionResult.Body), queuedResult.Code, strings.HasPrefix(queuedResult.Body, "client\n"))
		})
	}
}

func TestUserDeleteCRLPublicationFailure(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root required for owned publication syscall fixture")
	}
	for _, fault := range []bool{false, true} {
		t.Run(fmt.Sprintf("publication-error-%t", fault), func(t *testing.T) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			s := providerServer(t)
			initRoutePKI(t)
			if err := ovpn.CreateUser("alice", "Alice", 3, nil); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(pki.CRLFile())
			if err != nil {
				t.Fatal(err)
			}
			material := map[string][]byte{}
			for _, path := range []string{pki.IssuedCertPath("alice"), pki.ClientKeyPath("alice"), pki.InlineBundlePath("alice"), filepath.Join(pki.UsersDir(), "alice", "client.ovpn")} {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				material[path] = data
			}
			block, _ := pem.Decode(material[pki.IssuedCertPath("alice")])
			if block == nil {
				t.Fatal("issued fixture certificate has no PEM block")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			deletion := startProviderTrace(t, "delete", "")
			var publication string
			regs := deletion.until(t, func(regs syscall.PtraceRegs) bool {
				if !syscallEntry(regs) {
					return false
				}
				old, target := renamePaths(t, deletion.tid, regs)
				if target == pki.CRLFile() {
					publication = old
					return true
				}
				return false
			})
			if !crlContains(signedFixtureCRL(t, publication), cert) {
				t.Fatal("fixture did not reach a complete signed CRL awaiting publication")
			}
			current, err := os.ReadFile(pki.CRLFile())
			if err != nil || !bytes.Equal(before, current) {
				t.Fatalf("CRL changed before the controlled publication syscall: %v", err)
			}
			if fault {
				regs.Orig_rax = ^uint64(0)
				if err := syscall.PtraceSetRegs(deletion.tid, &regs); err != nil {
					t.Fatal(err)
				}
				regs = deletion.next(t)
				errno := int64(syscall.EACCES)
				regs.Rax = uint64(-errno)
				if err := syscall.PtraceSetRegs(deletion.tid, &regs); err != nil {
					t.Fatal(err)
				}
			}
			result := deletion.finish(t)
			t.Logf("observed complete signed CRL at publication syscall; injected EACCES=%t; DELETE envelope=%s", fault, strings.TrimSpace(result.Body))
			var envelope map[string]any
			if err := json.Unmarshal([]byte(result.Body), &envelope); err != nil || result.Code != http.StatusOK || envelope["success"] != !fault {
				t.Fatalf("publication outcome was not reflected by the real handler: %s (%v)", result.Body, err)
			}
			if !fault {
				if !crlContains(signedFixtureCRL(t, pki.CRLFile()), cert) || store.UserExists(pki.UsersDir(), "alice") {
					t.Fatal("successful publication control did not revoke and clean up")
				}
				return
			}
			if envelope["msg"] != "Failed to delete user" {
				t.Errorf("publication failure envelope changed: %s", result.Body)
			}
			for path, before := range material {
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before, after) {
					t.Errorf("publication failure destroyed recoverable material %s: %v", path, err)
				}
			}
			current, err = os.ReadFile(pki.CRLFile())
			if err != nil || !bytes.Equal(before, current) {
				t.Errorf("failed publication replaced the previous valid CRL: %v", err)
			}
			state, err := store.ReadUserState(pki.UsersDir(), "alice")
			if err != nil || !state.Disabled || state.Limit != 3 || store.ReadName(pki.UsersDir(), "alice") != "Alice" {
				t.Errorf("publication failure lost the disabled policy tombstone: %+v (%v)", state, err)
			}
			response := do(t, s, http.MethodDelete, "/sync/user/alice", "")
			if envelopeOf(t, response)["success"] != true || !crlContains(signedFixtureCRL(t, pki.CRLFile()), cert) || store.UserExists(pki.UsersDir(), "alice") {
				t.Fatalf("retry after publication repair did not durably revoke and delete: %s", response.Body.String())
			}
		})
	}
}

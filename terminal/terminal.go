package terminal

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/komari-monitor/komari-agent/core/capability"
)

// Terminal 接口定义平台特定的终端操作
type Terminal interface {
	Close() error
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Resize(cols, rows int) error
	Wait() error
}

// terminalImpl 封装终端和平台特定逻辑
type terminalImpl struct {
	shell      string
	workingDir string
	term       Terminal
}

// Session exposes the platform PTY to transport-neutral clients.
type Session struct {
	term      Terminal
	cancel    context.CancelFunc
	closeOnce sync.Once
}

func OpenSession(cols, rows int) (*Session, error) {
	return openSession(cols, rows, newTerminalImpl)
}

// OpenSessionAs requires the selected identity; failure never falls back to the Agent.
func OpenSessionAs(cols, rows int, username, shell, directory string) (*Session, error) {
	return openSession(cols, rows, func() (*terminalImpl, error) { return newTerminalAs(username, shell, directory) })
}

func openSession(cols, rows int, create func() (*terminalImpl, error)) (*Session, error) {
	if allowed, reason := capability.WebSSHAllowed(); !allowed {
		return nil, fmt.Errorf("remote control is unavailable: %s", reason)
	}
	impl, err := create()
	if err != nil {
		return nil, err
	}
	if cols > 0 && rows > 0 {
		if err := impl.term.Resize(cols, rows); err != nil {
			_ = impl.term.Close()
			return nil, err
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	session := &Session{term: impl.term, cancel: cancel}
	go func() {
		capability.CancelOnRevocation(ctx, cancel, capability.WebSSHAllowed)
		if ctx.Err() != nil {
			session.Close()
		}
	}()
	return session, nil
}

func (s *Session) Read(buffer []byte) (int, error) { return s.term.Read(buffer) }
func (s *Session) Write(data []byte) (int, error) {
	if ok, reason := capability.WebSSHAllowed(); !ok {
		return 0, fmt.Errorf("WebSSH revoked: %s", reason)
	}
	return s.term.Write(data)
}
func (s *Session) Resize(cols, rows int) error {
	if ok, reason := capability.WebSSHAllowed(); !ok {
		return fmt.Errorf("WebSSH revoked: %s", reason)
	}
	return s.term.Resize(cols, rows)
}
func (s *Session) Wait() error { return s.term.Wait() }
func (s *Session) Close() error {
	var err error
	s.closeOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		err = s.term.Close()
	})
	return err
}

// StartTerminal 启动终端并处理 WebSocket 通信
func StartTerminal(conn *websocket.Conn) {
	_ = conn.WriteMessage(websocket.TextMessage, []byte("Legacy terminal is disabled. Use the account-isolated Connect workspace."))
	_ = conn.Close()
}

// gracefulShutdown 尝试优雅地关闭终端
func gracefulShutdown(term Terminal) {
	//  Ctrl+C
	for i := 0; i < 3; i++ {
		if _, err := term.Write([]byte{3}); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}

	time.Sleep(200 * time.Millisecond)

	//  Ctrl+D (EOF)
	term.Write([]byte{4})
	time.Sleep(100 * time.Millisecond)

	term.Write([]byte("exit\n"))
	time.Sleep(100 * time.Millisecond)
}

// handleWebSocketInput 处理 WebSocket 输入
func handleWebSocketInput(conn *websocket.Conn, term Terminal, errChan chan<- error, done <-chan struct{}) {
	for {
		select {
		case <-done:
			return
		default:
		}

		t, p, err := conn.ReadMessage()
		if err != nil {
			select {
			case errChan <- err:
			default:
			}
			return
		}
		if t == websocket.TextMessage {
			var cmd struct {
				Type  string `json:"type"`
				Cols  int    `json:"cols,omitempty"`
				Rows  int    `json:"rows,omitempty"`
				Input string `json:"input,omitempty"`
			}
			if err := json.Unmarshal(p, &cmd); err == nil {
				switch cmd.Type {
				case "resize":
					if cmd.Cols > 0 && cmd.Rows > 0 {
						term.Resize(cmd.Cols, cmd.Rows)
					}
				case "input":
					if cmd.Input != "" {
						term.Write([]byte(cmd.Input))
					}
				}
			} else {
				term.Write(p)
			}
		}
		if t == websocket.BinaryMessage {
			term.Write(p)
		}
	}
}

// handleTerminalOutput 处理终端输出
func handleTerminalOutput(conn *websocket.Conn, term Terminal, errChan chan<- error, done <-chan struct{}) {
	buf := make([]byte, 4096)
	for {
		select {
		case <-done:
			return
		default:
		}

		n, err := term.Read(buf)
		if err != nil {
			select {
			case errChan <- err:
			default:
			}
			return
		}
		if err := conn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
			select {
			case errChan <- err:
			default:
			}
			return
		}
	}
}

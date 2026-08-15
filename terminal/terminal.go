package terminal

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/gorilla/websocket"

	"github.com/komari-monitor/komari-agent/core/capability"
	"github.com/komari-monitor/komari-agent/core/runtimeconfig"
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
	term Terminal
}

func OpenSession(cols, rows int) (*Session, error) {
	if allowed, reason := capability.RemoteControlAllowed(runtimeconfig.RemoteControlEnabled()); !allowed {
		return nil, fmt.Errorf("remote control is unavailable: %s", reason)
	}
	impl, err := newTerminalImpl()
	if err != nil {
		return nil, err
	}
	if cols > 0 && rows > 0 {
		if err := impl.term.Resize(cols, rows); err != nil {
			_ = impl.term.Close()
			return nil, err
		}
	}
	return &Session{term: impl.term}, nil
}

func (s *Session) Read(buffer []byte) (int, error) { return s.term.Read(buffer) }
func (s *Session) Write(data []byte) (int, error)  { return s.term.Write(data) }
func (s *Session) Resize(cols, rows int) error     { return s.term.Resize(cols, rows) }
func (s *Session) Wait() error                     { return s.term.Wait() }
func (s *Session) Close() error {
	gracefulShutdown(s.term)
	return s.term.Close()
}

// StartTerminal 启动终端并处理 WebSocket 通信
func StartTerminal(conn *websocket.Conn) {
	if allowed, reason := capability.RemoteControlAllowed(runtimeconfig.RemoteControlEnabled()); !allowed {
		conn.WriteMessage(websocket.TextMessage, []byte("\n\nRemote control is unavailable: "+reason))
		conn.Close()
		return
	}
	session, err := OpenSession(80, 24)
	if err != nil {
		conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("Error: %v\r\n", err)))
		return
	}

	errChan := make(chan error, 3) // 增加容量以容纳多个错误源
	done := make(chan struct{})

	defer func() {
		session.Close()
		conn.Close()
		close(done)
	}()

	// 从 WebSocket 读取消息并写入终端
	go handleWebSocketInput(conn, session.term, errChan, done)

	// 从终端读取输出并写入 WebSocket
	go handleTerminalOutput(conn, session.term, errChan, done)

	// 等待终端进程结束或出现错误
	select {
	case err := <-errChan:
		// WebSocket 连接断开或出现错误
		if err != nil {
			conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("\r\nConnection error: %v\r\n", err)))
		}
	case <-done:
		// 已经被其他地方关闭
	}
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

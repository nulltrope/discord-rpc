package transport

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/nulltrope/discord-rpc/rpc"
)

// OpCode is a Discord IPC Operation Code.
type OpCode = int32

const (
	// OpHandshake is used to initiate a new conn.
	OpHandshake OpCode = iota
	// OpFrame is used to send commands and receive events over an established conn.
	OpFrame
	// OpClose is used to voluntarily close the conn or received when the conn is closed.
	OpClose
	// OpPing is used to send a ping over the conn.
	OpPing
	// OpPong is used to receive a response to a ping over the conn.
	OpPong
	// OpError is an internal-only OpCode returned on errors
	OpError
)

var (
	ErrConnClosed = errors.New("connection closed")

	defaultIPCSocketTimeout   = time.Second * 2
	defaultIPCSocketBindRange = 10
)

// DefaultIPC is a usable Discord IPC transport with sensible defaults.
var DefaultIPC *IPC = &IPC{
	BindRange:   defaultIPCSocketBindRange,
	BindTimeout: defaultIPCSocketTimeout,
}

// IPC is a transport which connects to a Discord client's local IPC socket.
type IPC struct {
	// BindRange represents the highest socket number to try binding to, starting from 0.
	BindRange int
	// BindTimeout is the maximum time to wait when binding to a given socket.
	BindTimeout time.Duration
	conn        net.Conn
}

func (s *IPC) bindRange() int {
	if s.BindRange == 0 {
		return defaultIPCSocketBindRange
	}
	return s.BindRange
}

func (s *IPC) bindTimeout() time.Duration {
	if s.BindTimeout == 0 {
		return defaultIPCSocketTimeout
	}
	return s.BindTimeout
}

// Connect will try and bind to the first available Discord client's IPC socket
// and send the initial handshake payload.
// Returns the READY payload, or an error.
func (t *IPC) Connect(clientId string) (*rpc.Payload, error) {
	// Check if we're already connected
	if t.conn != nil {
		return nil, nil
	}

	err := t.tryBind()
	if err != nil {
		return nil, err
	}
	payload, err := t.handshake(clientId)
	if err != nil {
		return nil, fmt.Errorf("error making handshake: %v", err)
	}

	if payload.Evt != "READY" {
		return payload, fmt.Errorf("expected ready event, got: %s", payload.Evt)
	}

	return payload, nil
}

func (s *IPC) tryBind() error {
	for i := range make([]int, s.bindRange()) {
		conn, err := openSocket(i, s.bindTimeout())
		if err == nil {
			s.conn = conn
			return nil
		}
	}

	return errors.New("ipc: error binding to all sockets")
}

type handshake struct {
	V        string `json:"v"`
	ClientId string `json:"client_id"`
}

func (s *IPC) handshake(clientId string) (*rpc.Payload, error) {
	payload, err := json.Marshal(handshake{"1", clientId})
	if err != nil {
		return nil, fmt.Errorf("error marshalling handshake data: %w", err)
	}

	err = s.WriteOp(OpHandshake, payload)
	if err != nil {
		return nil, fmt.Errorf("error writing handshake data to conn: %w", err)
	}

	opCode, respRaw, err := s.ReadOp()
	if err != nil {
		return nil, fmt.Errorf("error reading handshake data from conn: %w", err)
	}

	if opCode == OpClose {
		var closeData rpc.ErrorEvtData
		err = json.Unmarshal(respRaw, &closeData)
		if err != nil {
			return nil, fmt.Errorf("received close op code but couldn't unmarshall data: %v", err)
		}
		return nil, fmt.Errorf("transport closed: code=%d, message=%s", closeData.Code, closeData.Message)
	}

	var respPayload rpc.Payload
	err = json.Unmarshal(respRaw, &respPayload)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling handshake response data: %v", err)
	}

	payloadErr := respPayload.Error()
	if payloadErr != nil {
		return nil, fmt.Errorf("received error payload: %v", payloadErr)
	}

	if respPayload.Evt != "READY" {
		return nil, fmt.Errorf("expected READY event, got %s", respPayload.Evt)
	}

	return &respPayload, nil
}

// Write sends data to the IPC socket with the FRAME OpCode.
func (s *IPC) Write(data []byte) error {
	return s.WriteOp(OpFrame, data)
}

// WriteOp sends data to the IPC socket with the given OpCode.
func (s *IPC) WriteOp(opCode OpCode, data []byte) error {
	if s.conn == nil {
		return ErrConnClosed
	}

	var buf bytes.Buffer
	err := binary.Write(&buf, binary.LittleEndian, int32(opCode))
	if err != nil {
		return fmt.Errorf("error writing opcode to buffer: %v", err)
	}

	err = binary.Write(&buf, binary.LittleEndian, int32(len(data)))
	if err != nil {
		return fmt.Errorf("error writing payload length to buffer: %v", err)
	}

	_, err = buf.Write(data)
	if err != nil {
		return fmt.Errorf("error writing payload to buffer: %v", err)
	}

	_, err = s.conn.Write(buf.Bytes())
	if err != nil {
		if errors.Is(err, io.EOF) {
			return ErrConnClosed
		}
		return fmt.Errorf("error writing buffer to socket: %v", err)
	}

	return nil
}

// Read receives data from the IPC socket with the FRAME OpCode.
// Returns an error if any other OpCode is received.
func (s *IPC) Read() ([]byte, error) {
	opCode, data, err := s.ReadOp()
	if opCode != OpFrame {
		return data, fmt.Errorf("unexpected OpCode received: opCode=%d, err=%w", opCode, err)
	}
	return data, err
}

// ReadOp reads data from the IPC socket and returns the OpCode.
func (s *IPC) ReadOp() (OpCode, []byte, error) {
	if s.conn == nil {
		return OpClose, nil, ErrConnClosed
	}

	var opCodeBuf bytes.Buffer
	_, err := io.CopyN(&opCodeBuf, s.conn, 4)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return OpClose, nil, ErrConnClosed
		}
		return OpError, nil, fmt.Errorf("error reading OpCode from conn: %v", err)
	}

	var opCode OpCode
	err = binary.Read(&opCodeBuf, binary.LittleEndian, &opCode)
	if err != nil {
		return OpError, nil, fmt.Errorf("error parsing OpCode bytes: %v", err)
	}

	var dataSizeBuf bytes.Buffer
	_, err = io.CopyN(&dataSizeBuf, s.conn, 4)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return OpClose, nil, ErrConnClosed
		}
		return OpError, nil, fmt.Errorf("error reading data size from conn: %v", err)
	}

	var dataSize int32
	err = binary.Read(&dataSizeBuf, binary.LittleEndian, &dataSize)
	if err != nil {
		return OpError, nil, fmt.Errorf("error parsing data size bytes: %v", err)
	}

	dataBuf := make([]byte, dataSize)
	dataRead, err := s.conn.Read(dataBuf)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return OpClose, nil, ErrConnClosed
		}
		return OpError, nil, fmt.Errorf("error reading payload data from conn: %v", err)
	}

	if int32(dataRead) != dataSize {
		return OpError, nil, fmt.Errorf("expected %d payload bytes, got %d", dataSize, dataRead)
	}

	return opCode, dataBuf, nil
}

func (s *IPC) Close() error {
	err := s.conn.Close()
	s.conn = nil
	return err
}

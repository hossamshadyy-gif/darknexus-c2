package transport

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

type Response struct {
	Data     []byte
	Duration time.Duration
	Error    error
	ConnErr  bool
}

type Transport interface {
	Send(data []byte) *Response
	Close()
	Protocol() string
}

func New(proto string, host string, port int, timeout time.Duration) (Transport, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	switch proto {
	case "tcp":
		return &TCPTransport{addr: addr, timeout: timeout}, nil
	case "udp":
		return &UDPTransport{addr: addr, timeout: timeout}, nil
	case "tls":
		return &TLSTransport{addr: addr, timeout: timeout}, nil
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", proto)
	}
}

type TCPTransport struct {
	addr    string
	timeout time.Duration
}

func (t *TCPTransport) Send(data []byte) *Response {
	start := time.Now()

	conn, err := net.DialTimeout("tcp", t.addr, t.timeout)
	if err != nil {
		return &Response{Error: err, ConnErr: true, Duration: time.Since(start)}
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(t.timeout))

	_, err = conn.Write(data)
	if err != nil {
		return &Response{Error: err, Duration: time.Since(start)}
	}

	buf := make([]byte, 65536)
	n, err := conn.Read(buf)
	elapsed := time.Since(start)

	if err != nil {
		if nErr, ok := err.(net.Error); ok && nErr.Timeout() {
			return &Response{Duration: elapsed}
		}
		return &Response{Error: err, Duration: elapsed}
	}

	resp := make([]byte, n)
	copy(resp, buf[:n])
	return &Response{Data: resp, Duration: elapsed}
}

func (t *TCPTransport) Close()          {}
func (t *TCPTransport) Protocol() string { return "tcp" }

type UDPTransport struct {
	addr    string
	timeout time.Duration
}

func (t *UDPTransport) Send(data []byte) *Response {
	start := time.Now()

	raddr, err := net.ResolveUDPAddr("udp", t.addr)
	if err != nil {
		return &Response{Error: err, ConnErr: true, Duration: time.Since(start)}
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return &Response{Error: err, ConnErr: true, Duration: time.Since(start)}
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(t.timeout))

	_, err = conn.Write(data)
	if err != nil {
		return &Response{Error: err, Duration: time.Since(start)}
	}

	buf := make([]byte, 65536)
	n, err := conn.Read(buf)
	elapsed := time.Since(start)

	if err != nil {
		if nErr, ok := err.(net.Error); ok && nErr.Timeout() {
			return &Response{Duration: elapsed}
		}
		return &Response{Error: err, Duration: elapsed}
	}

	resp := make([]byte, n)
	copy(resp, buf[:n])
	return &Response{Data: resp, Duration: elapsed}
}

func (t *UDPTransport) Close()          {}
func (t *UDPTransport) Protocol() string { return "udp" }

type TLSTransport struct {
	addr    string
	timeout time.Duration
}

func (t *TLSTransport) Send(data []byte) *Response {
	start := time.Now()

	dialer := &net.Dialer{Timeout: t.timeout}
	tlsCfg := &tls.Config{InsecureSkipVerify: true}

	conn, err := tls.DialWithDialer(dialer, "tcp", t.addr, tlsCfg)
	if err != nil {
		return &Response{Error: err, ConnErr: true, Duration: time.Since(start)}
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(t.timeout))

	_, err = conn.Write(data)
	if err != nil {
		return &Response{Error: err, Duration: time.Since(start)}
	}

	buf := make([]byte, 65536)
	n, err := conn.Read(buf)
	elapsed := time.Since(start)

	if err != nil {
		if nErr, ok := err.(net.Error); ok && nErr.Timeout() {
			return &Response{Duration: elapsed}
		}
		return &Response{Error: err, Duration: elapsed}
	}

	resp := make([]byte, n)
	copy(resp, buf[:n])
	return &Response{Data: resp, Duration: elapsed}
}

func (t *TLSTransport) Close()          {}
func (t *TLSTransport) Protocol() string { return "tls" }

package pool

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"
)

type Conn struct {
	net.Conn
	created time.Time
	inUse   bool
}

type Pool struct {
	addr      string
	proto     string
	timeout   time.Duration
	maxConns  int
	maxAge    time.Duration
	conns     []*Conn
	mu        sync.Mutex
}

func New(proto, addr string, timeout time.Duration, maxConns int) *Pool {
	if maxConns <= 0 {
		maxConns = 8
	}
	return &Pool{
		addr:     addr,
		proto:    proto,
		timeout:  timeout,
		maxConns: maxConns,
		maxAge:   30 * time.Second,
	}
}

func (p *Pool) Get() (net.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	for i := len(p.conns) - 1; i >= 0; i-- {
		c := p.conns[i]
		if !c.inUse && now.Sub(c.created) < p.maxAge {
			c.inUse = true
			c.Conn.SetDeadline(now.Add(p.timeout))
			return c.Conn, nil
		}
		if now.Sub(c.created) >= p.maxAge {
			c.Conn.Close()
			p.conns = append(p.conns[:i], p.conns[i+1:]...)
		}
	}

	conn, err := p.dial()
	if err != nil {
		return nil, err
	}

	wrapped := &Conn{
		Conn:    conn,
		created: now,
		inUse:   true,
	}

	if len(p.conns) < p.maxConns {
		p.conns = append(p.conns, wrapped)
	}

	return conn, nil
}

func (p *Pool) Put(conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, c := range p.conns {
		if c.Conn == conn {
			c.inUse = false
			return
		}
	}
	conn.Close()
}

func (p *Pool) Discard(conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	conn.Close()
	for i, c := range p.conns {
		if c.Conn == conn {
			p.conns = append(p.conns[:i], p.conns[i+1:]...)
			return
		}
	}
}

func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, c := range p.conns {
		c.Conn.Close()
	}
	p.conns = nil
}

func (p *Pool) Stats() (total, idle, active int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	total = len(p.conns)
	for _, c := range p.conns {
		if c.inUse {
			active++
		} else {
			idle++
		}
	}
	return
}

func (p *Pool) dial() (net.Conn, error) {
	switch p.proto {
	case "tcp":
		return net.DialTimeout("tcp", p.addr, p.timeout)
	case "tls":
		dialer := &net.Dialer{Timeout: p.timeout}
		return tls.DialWithDialer(dialer, "tcp", p.addr, &tls.Config{InsecureSkipVerify: true})
	case "udp":
		raddr, err := net.ResolveUDPAddr("udp", p.addr)
		if err != nil {
			return nil, err
		}
		return net.DialUDP("udp", nil, raddr)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", p.proto)
	}
}

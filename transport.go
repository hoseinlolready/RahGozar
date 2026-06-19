package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Transport interface {
	Listen(addr string, opt TransportOpt) (net.Listener, error)
	Dial(addr string, opt TransportOpt) (net.Conn, error)
}

type TransportOpt struct {
	Secret string // pre-shared key; authenticates the link and derives AES keys
	Host   string // SNI / Host header for tls and ws modes (cosmetic camouflage)
}

func getTransport(mode string) (Transport, error) {
	switch mode {
	case "", "tcp":
		return tcpTransport{}, nil
	case "aes":
		return aesTransport{}, nil
	case "tls":
		return tlsTransport{}, nil
	case "ws":
		return wsTransport{}, nil
	case "icmp":
		return icmpTransport{}, nil
	}
	return nil, fmt.Errorf("unknown tunnel mode %q", mode)
}

func validMode(m string) bool {
	switch m {
	case "", "tcp", "aes", "tls", "ws", "icmp", "sit":
		return true
	}
	return false
}

func deriveKey(secret string) []byte {
	sum := sha256.Sum256([]byte("rahgozar-v1|" + secret))
	return sum[:]
}

func dialTimeout(addr string) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err == nil {
		if t, ok := c.(*net.TCPConn); ok {
			t.SetNoDelay(true)
		}
	}
	return c, err
}

type tcpTransport struct{}

func (tcpTransport) Listen(addr string, _ TransportOpt) (net.Listener, error) {
	return net.Listen("tcp", addr)
}
func (tcpTransport) Dial(addr string, _ TransportOpt) (net.Conn, error) {
	return dialTimeout(addr)
}

type aesTransport struct{}

func (aesTransport) Listen(addr string, opt TransportOpt) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &aesListener{ln, deriveKey(opt.Secret)}, nil
}

func (aesTransport) Dial(addr string, opt TransportOpt) (net.Conn, error) {
	raw, err := dialTimeout(addr)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(deriveKey(opt.Secret))
	if err != nil {
		raw.Close()
		return nil, err
	}
	return &aesConn{Conn: raw, gcm: gcm}, nil
}

type aesListener struct {
	net.Listener
	key []byte
}

func (l *aesListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if t, ok := c.(*net.TCPConn); ok {
		t.SetNoDelay(true)
	}
	gcm, err := newGCM(l.key)
	if err != nil {
		c.Close()
		return nil, err
	}
	return &aesConn{Conn: c, gcm: gcm}, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

type aesConn struct {
	net.Conn
	gcm    cipher.AEAD
	rbuf   []byte // leftover decrypted plaintext not yet handed to Read
	reader *bufio.Reader
}

func (c *aesConn) ensureReader() *bufio.Reader {
	if c.reader == nil {
		c.reader = bufio.NewReader(c.Conn)
	}
	return c.reader
}

func (c *aesConn) Read(p []byte) (int, error) {
	if len(c.rbuf) > 0 {
		n := copy(p, c.rbuf)
		c.rbuf = c.rbuf[n:]
		return n, nil
	}
	r := c.ensureReader()

	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return 0, err
	}
	recLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if recLen < c.gcm.NonceSize()+c.gcm.Overhead() {
		return 0, errors.New("aes: short record")
	}
	rec := make([]byte, recLen)
	if _, err := io.ReadFull(r, rec); err != nil {
		return 0, err
	}
	nonce := rec[:c.gcm.NonceSize()]
	ct := rec[c.gcm.NonceSize():]
	pt, err := c.gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return 0, errors.New("aes: auth failed")
	}
	if len(pt) < 2 {
		return 0, errors.New("aes: malformed plaintext")
	}
	payLen := int(binary.BigEndian.Uint16(pt[:2]))
	if 2+payLen > len(pt) {
		return 0, errors.New("aes: bad payload length")
	}
	payload := pt[2 : 2+payLen]

	n := copy(p, payload)
	if n < len(payload) {
		c.rbuf = append(c.rbuf, payload[n:]...)
	}
	return n, nil
}

func (c *aesConn) Write(p []byte) (int, error) {
	const maxChunk = 16 * 1024
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxChunk {
			chunk = chunk[:maxChunk]
		}
		if err := c.writeRecord(chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (c *aesConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

func (c *aesConn) writeRecord(payload []byte) error {
	var padByte [1]byte
	rand.Read(padByte[:])
	padLen := int(padByte[0])
	pad := make([]byte, padLen)
	rand.Read(pad)

	pt := make([]byte, 2+len(payload)+padLen)
	binary.BigEndian.PutUint16(pt[:2], uint16(len(payload)))
	copy(pt[2:], payload)
	copy(pt[2+len(payload):], pad)

	nonce := make([]byte, c.gcm.NonceSize())
	rand.Read(nonce)
	ct := c.gcm.Seal(nil, nonce, pt, nil)

	rec := make([]byte, 2+len(nonce)+len(ct))
	binary.BigEndian.PutUint16(rec[:2], uint16(len(nonce)+len(ct)))
	copy(rec[2:], nonce)
	copy(rec[2+len(nonce):], ct)

	_, err := c.Conn.Write(rec)
	return err
}

type tlsTransport struct{}

func (tlsTransport) Listen(addr string, opt TransportOpt) (net.Listener, error) {
	cert, err := selfSignedCert(hostOr(opt.Host))
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	ln, err := tls.Listen("tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	return newAuthListener(ln, opt.Secret), nil
}

func (tlsTransport) Dial(addr string, opt TransportOpt) (net.Conn, error) {
	cfg := &tls.Config{
		ServerName:         hostOr(opt.Host),
		InsecureSkipVerify: true, // self-signed exit; PSK below provides auth
		MinVersion:         tls.VersionTLS12,
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	if err := writeAuth(conn, opt.Secret); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func hostOr(h string) string {
	if strings.TrimSpace(h) == "" {
		return "www.cloudflare.com"
	}
	return h
}

type authListener struct {
	inner  net.Listener
	secret string
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newAuthListener(inner net.Listener, secret string) *authListener {
	l := &authListener{
		inner:  inner,
		secret: secret,
		conns:  make(chan net.Conn, 128),
		closed: make(chan struct{}),
	}
	go l.acceptLoop()
	return l
}

func (l *authListener) acceptLoop() {
	for {
		c, err := l.inner.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			c.SetReadDeadline(time.Now().Add(10 * time.Second))
			if err := readAuth(c, l.secret); err != nil {
				c.Close()
				return
			}
			c.SetReadDeadline(time.Time{})
			select {
			case l.conns <- c:
			case <-l.closed:
				c.Close()
			}
		}(c)
	}
}

func (l *authListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, errors.New("listener closed")
	}
}

func (l *authListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return l.inner.Close()
}

func (l *authListener) Addr() net.Addr { return l.inner.Addr() }

const authMagicLen = 32

func writeAuth(c net.Conn, secret string) error {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("rahgozar-auth"))
	_, err := c.Write(mac.Sum(nil))
	return err
}

func readAuth(c net.Conn, secret string) error {
	buf := make([]byte, authMagicLen)
	if _, err := io.ReadFull(c, buf); err != nil {
		return err
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("rahgozar-auth"))
	if subtle.ConstantTimeCompare(buf, mac.Sum(nil)) != 1 {
		return errors.New("auth failed")
	}
	return nil
}

func selfSignedCert(host string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

type wsTransport struct{}

func (wsTransport) Listen(addr string, opt TransportOpt) (net.Listener, error) {
	var base net.Listener
	var err error
	if opt.Host != "" && strings.HasPrefix(opt.Host, "tls:") {
		cert, e := selfSignedCert(strings.TrimPrefix(opt.Host, "tls:"))
		if e != nil {
			return nil, e
		}
		base, err = tls.Listen("tcp", addr, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	} else {
		base, err = net.Listen("tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	return newWSListener(base, opt.Secret), nil
}

func (wsTransport) Dial(addr string, opt TransportOpt) (net.Conn, error) {
	var conn net.Conn
	var err error
	host := opt.Host
	if strings.HasPrefix(host, "tls:") {
		name := strings.TrimPrefix(host, "tls:")
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr,
			&tls.Config{ServerName: name, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
		host = name
	} else {
		conn, err = dialTimeout(addr)
	}
	if err != nil {
		return nil, err
	}
	if host == "" {
		host = "cdn.jsdelivr.net"
	}

	key := make([]byte, 16)
	rand.Read(key)
	secKey := base64.StdEncoding.EncodeToString(key)
	token := authToken(opt.Secret)
	req := "GET /tunnel HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + secKey + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"X-Auth: " + token + "\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, fmt.Errorf("ws: unexpected status %d", resp.StatusCode)
	}
	return &wsConn{Conn: conn, r: br, client: true}, nil
}

func authToken(secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("rahgozar-ws"))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

type wsListener struct {
	inner  net.Listener
	secret string
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newWSListener(inner net.Listener, secret string) *wsListener {
	l := &wsListener{
		inner:  inner,
		secret: secret,
		conns:  make(chan net.Conn, 128),
		closed: make(chan struct{}),
	}
	go l.acceptLoop()
	return l
}

func (l *wsListener) acceptLoop() {
	for {
		c, err := l.inner.Accept()
		if err != nil {
			return
		}
		go l.handshake(c)
	}
}

func (l *wsListener) handshake(c net.Conn) {
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		c.Close()
		return
	}
	if subtle.ConstantTimeCompare([]byte(req.Header.Get("X-Auth")), []byte(authToken(l.secret))) != 1 {
		c.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
		c.Close()
		return
	}
	accept := wsAcceptKey(req.Header.Get("Sec-WebSocket-Key"))
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	if _, err := c.Write([]byte(resp)); err != nil {
		c.Close()
		return
	}
	c.SetReadDeadline(time.Time{})
	wc := &wsConn{Conn: c, r: br, client: false}
	select {
	case l.conns <- wc:
	case <-l.closed:
		c.Close()
	}
}

func (l *wsListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, errors.New("listener closed")
	}
}

func (l *wsListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return l.inner.Close()
}

func (l *wsListener) Addr() net.Addr { return l.inner.Addr() }

func wsAcceptKey(key string) string {
	const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	sum := sha1.Sum([]byte(key + magic))
	return base64.StdEncoding.EncodeToString(sum[:])
}

type wsConn struct {
	net.Conn
	r       *bufio.Reader
	client  bool
	readBuf []byte
}

func (c *wsConn) Read(p []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}
	payload, err := c.readFrame()
	if err != nil {
		return 0, err
	}
	n := copy(p, payload)
	if n < len(payload) {
		c.readBuf = append(c.readBuf, payload[n:]...)
	}
	return n, nil
}

func (c *wsConn) readFrame() ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c.r, hdr[:]); err != nil {
		return nil, err
	}
	masked := hdr[1]&0x80 != 0
	length := int(hdr[1] & 0x7f)
	switch length {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(c.r, ext[:]); err != nil {
			return nil, err
		}
		length = int(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(c.r, ext[:]); err != nil {
			return nil, err
		}
		length = int(binary.BigEndian.Uint64(ext[:]))
	}
	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(c.r, maskKey[:]); err != nil {
			return nil, err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(c.r, payload); err != nil {
		return nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}
	return payload, nil
}

func (c *wsConn) Write(p []byte) (int, error) {
	const maxFrame = 32 * 1024
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxFrame {
			chunk = chunk[:maxFrame]
		}
		if err := c.writeFrame(chunk); err != nil {
			return total, err
		}
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (c *wsConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

func (c *wsConn) writeFrame(payload []byte) error {
	var buf []byte
	buf = append(buf, 0x82) // FIN + binary opcode
	n := len(payload)
	maskBit := byte(0)
	if c.client {
		maskBit = 0x80
	}
	switch {
	case n < 126:
		buf = append(buf, maskBit|byte(n))
	case n < 65536:
		buf = append(buf, maskBit|126)
		var ext [2]byte
		binary.BigEndian.PutUint16(ext[:], uint16(n))
		buf = append(buf, ext[:]...)
	default:
		buf = append(buf, maskBit|127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(n))
		buf = append(buf, ext[:]...)
	}
	if c.client {
		var mask [4]byte
		rand.Read(mask[:])
		buf = append(buf, mask[:]...)
		masked := make([]byte, n)
		for i := range payload {
			masked[i] = payload[i] ^ mask[i%4]
		}
		buf = append(buf, masked...)
	} else {
		buf = append(buf, payload...)
	}
	_, err := c.Conn.Write(buf)
	return err
}

package main

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"syscall"
	"time"
)

const (
	icmpMaxData     = 1024            // bytes of stream data per packet
	icmpWindow      = 256             // max in-flight segments per direction
	icmpRTOBase     = 280 * time.Millisecond
	icmpRTOMax      = 4 * time.Second
	icmpTick        = 40 * time.Millisecond
	icmpMaxRetries  = 14
	icmpKeepalive   = 1200 * time.Millisecond // also keeps NAT mapping open
	icmpMinPlain    = 24                       // pad small frames up to this
	icmpInnerHeader = 16
)

const (
	dirC2S byte = 0x11 // entry -> exit
	dirS2C byte = 0x22 // exit  -> entry
)

const (
	ftSYN  byte = 1 // open a session (occupies seq 0 of the client stream)
	ftDATA byte = 2
	ftACK  byte = 3 // pure cumulative ack, not sequenced
	ftFIN  byte = 4
	ftPING byte = 5 // keepalive, carries an ack
)

type frame struct {
	dir     byte
	session uint32
	ftype   byte
	seq     uint32
	ack     uint32
	data    []byte
}

func encodeInner(dir byte, session uint32, ftype byte, seq, ack uint32, data []byte) []byte {
	dlen := len(data)
	total := icmpInnerHeader + dlen
	if total < icmpMinPlain {
		total = icmpMinPlain
	}
	var j [1]byte
	rand.Read(j[:])
	total += int(j[0] % 48)

	b := make([]byte, total)
	b[0] = dir
	binary.BigEndian.PutUint32(b[1:5], session)
	b[5] = ftype
	binary.BigEndian.PutUint32(b[6:10], seq)
	binary.BigEndian.PutUint32(b[10:14], ack)
	binary.BigEndian.PutUint16(b[14:16], uint16(dlen))
	copy(b[16:], data)
	if rem := b[16+dlen:]; len(rem) > 0 {
		rand.Read(rem) // random padding
	}
	return b
}

func parseInner(b []byte) (frame, bool) {
	if len(b) < icmpInnerHeader {
		return frame{}, false
	}
	dlen := int(binary.BigEndian.Uint16(b[14:16]))
	if icmpInnerHeader+dlen > len(b) {
		return frame{}, false
	}
	f := frame{
		dir:     b[0],
		session: binary.BigEndian.Uint32(b[1:5]),
		ftype:   b[5],
		seq:     binary.BigEndian.Uint32(b[6:10]),
		ack:     binary.BigEndian.Uint32(b[10:14]),
	}
	if dlen > 0 {
		f.data = append([]byte(nil), b[16:16+dlen]...)
	}
	return f, true
}

func sealFrame(gcm cipher.AEAD, plaintext []byte) []byte {
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, len(nonce)+len(ct))
	copy(out, nonce)
	copy(out[len(nonce):], ct)
	return out
}

func openFrame(gcm cipher.AEAD, blob []byte) (frame, bool) {
	ns := gcm.NonceSize()
	if len(blob) < ns+gcm.Overhead() {
		return frame{}, false
	}
	pt, err := gcm.Open(nil, blob[:ns], blob[ns:], nil)
	if err != nil {
		return frame{}, false
	}
	return parseInner(pt)
}

type packetConn interface {
	WriteTo(payload []byte, dst [4]byte, asReply bool) error
	ReadFrom(buf []byte) (n int, src [4]byte, wasReply bool, err error)
	Close() error
}

var errShortPacket = errors.New("icmp: short packet")

func icmpChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func buildEcho(asReply bool, id, seq uint16, payload []byte) []byte {
	pkt := make([]byte, 8+len(payload))
	if asReply {
		pkt[0] = 0
	} else {
		pkt[0] = 8
	}
	binary.BigEndian.PutUint16(pkt[4:6], id)
	binary.BigEndian.PutUint16(pkt[6:8], seq)
	copy(pkt[8:], payload)
	cs := icmpChecksum(pkt)
	binary.BigEndian.PutUint16(pkt[2:4], cs)
	return pkt
}

type rawICMPConn struct {
	fd    int
	id    uint16
	seqMu sync.Mutex
	seq   uint16
}

func newRawICMPConn() (*rawICMPConn, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		return nil, err
	}
	var pid [2]byte
	rand.Read(pid[:])
	return &rawICMPConn{fd: fd, id: binary.BigEndian.Uint16(pid[:])}, nil
}

func (c *rawICMPConn) WriteTo(payload []byte, dst [4]byte, asReply bool) error {
	c.seqMu.Lock()
	c.seq++
	seq := c.seq
	c.seqMu.Unlock()
	pkt := buildEcho(asReply, c.id, seq, payload)
	return syscall.Sendto(c.fd, pkt, 0, &syscall.SockaddrInet4{Addr: dst})
}

func (c *rawICMPConn) ReadFrom(buf []byte) (int, [4]byte, bool, error) {
	raw := make([]byte, 65535)
	n, from, err := syscall.Recvfrom(c.fd, raw, 0)
	if err != nil {
		return 0, [4]byte{}, false, err
	}
	var src [4]byte
	if sa, ok := from.(*syscall.SockaddrInet4); ok {
		src = sa.Addr
	}
	if n < 20 {
		return 0, src, false, errShortPacket
	}
	ihl := int(raw[0]&0x0f) * 4
	if n < ihl+8 {
		return 0, src, false, errShortPacket
	}
	icmpType := raw[ihl]
	payload := raw[ihl+8 : n]
	m := copy(buf, payload)
	return m, src, icmpType == 0, nil
}

func (c *rawICMPConn) Close() error { return syscall.Close(c.fd) }

type icmpHub struct {
	mu        sync.Mutex
	pc        packetConn
	started   bool
	endpoints []*icmpEndpoint
}

var icmpGlobal = &icmpHub{}

func (h *icmpHub) useConn(pc packetConn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pc = pc
	if !h.started {
		h.started = true
		go h.readPump()
	}
}

func (h *icmpHub) ensure() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.pc != nil {
		return nil
	}
	pc, err := newRawICMPConn()
	if err != nil {
		return err
	}
	h.pc = pc
	h.started = true
	go h.readPump()
	return nil
}

func (h *icmpHub) register(ep *icmpEndpoint) {
	h.mu.Lock()
	h.endpoints = append(h.endpoints, ep)
	h.mu.Unlock()
}

func (h *icmpHub) snapshot() []*icmpEndpoint {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]*icmpEndpoint, len(h.endpoints))
	copy(out, h.endpoints)
	return out
}

func (h *icmpHub) readPump() {
	buf := make([]byte, 65535)
	for {
		n, src, wasReply, err := h.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		payload := buf[:n]
		for _, ep := range h.snapshot() {
			if ep.consume(payload, src, wasReply) {
				break
			}
		}
	}
}

type icmpEndpoint struct {
	hub      *icmpHub
	gcm      cipher.AEAD
	isClient bool
	peer     [4]byte // client: the exit IP
	tag      string  // registry key

	mu       sync.Mutex
	sessions map[uint32]*reliableConn
	acceptCh chan *reliableConn // server only
	closed   bool
}

func (ep *icmpEndpoint) consume(payload []byte, src [4]byte, wasReply bool) bool {
	if ep.isClient != wasReply {
		return false
	}
	fr, ok := openFrame(ep.gcm, payload)
	if !ok {
		return false
	}
	if ep.isClient && fr.dir != dirS2C {
		return false
	}
	if !ep.isClient && fr.dir != dirC2S {
		return false
	}
	ep.route(fr, src)
	return true
}

func (ep *icmpEndpoint) route(fr frame, src [4]byte) {
	ep.mu.Lock()
	s := ep.sessions[fr.session]
	if s == nil {
		if ep.isClient || ep.closed {
			ep.mu.Unlock()
			return // client: unknown session; ignore
		}
		s = newReliableConn(ep, fr.session, src)
		ep.sessions[fr.session] = s
		ep.mu.Unlock()
		select {
		case ep.acceptCh <- s:
		default:
			ep.mu.Lock()
			delete(ep.sessions, fr.session)
			ep.mu.Unlock()
			return
		}
	} else {
		ep.mu.Unlock()
	}
	s.onFrame(fr)
}

func (ep *icmpEndpoint) openSession() *reliableConn {
	var sid [4]byte
	rand.Read(sid[:])
	id := binary.BigEndian.Uint32(sid[:])
	s := newReliableConn(ep, id, ep.peer)
	ep.mu.Lock()
	ep.sessions[id] = s
	ep.mu.Unlock()
	s.sendControlSeq(ftSYN, nil)
	return s
}

func (ep *icmpEndpoint) remove(id uint32) {
	ep.mu.Lock()
	delete(ep.sessions, id)
	ep.mu.Unlock()
}

type segment struct {
	ftype   byte
	seq     uint32
	data    []byte
	sent    time.Time
	retries int
}

type reliableConn struct {
	ep   *icmpEndpoint
	id   uint32
	peer [4]byte

	sndMu     sync.Mutex
	sndCond   *sync.Cond
	outSeq    uint32
	unacked   map[uint32]*segment
	sndClosed bool

	rcvMu    sync.Mutex
	rcvCond  *sync.Cond
	inNext   uint32
	reorder  map[uint32]frame
	rcvData  []byte
	eof      bool
	rcvReset bool

	done     chan struct{}
	doneOnce sync.Once
	lastTx   time.Time
	lastRx   time.Time
}

func newReliableConn(ep *icmpEndpoint, id uint32, peer [4]byte) *reliableConn {
	s := &reliableConn{
		ep:      ep,
		id:      id,
		peer:    peer,
		unacked: make(map[uint32]*segment),
		reorder: make(map[uint32]frame),
		done:    make(chan struct{}),
		lastTx:  time.Now(),
		lastRx:  time.Now(),
	}
	s.sndCond = sync.NewCond(&s.sndMu)
	s.rcvCond = sync.NewCond(&s.rcvMu)
	go s.timerLoop()
	return s
}

func (s *reliableConn) dir() byte {
	if s.ep.isClient {
		return dirC2S
	}
	return dirS2C
}

func (s *reliableConn) sendFrame(ftype byte, seq, ack uint32, data []byte) {
	pt := encodeInner(s.dir(), s.id, ftype, seq, ack, data)
	blob := sealFrame(s.ep.gcm, pt)
	s.ep.hub.mu.Lock()
	pc := s.ep.hub.pc
	s.ep.hub.mu.Unlock()
	if pc != nil {
		pc.WriteTo(blob, s.peer, !s.ep.isClient)
	}
	s.lastTx = time.Now()
}

func (s *reliableConn) sendControlSeq(ftype byte, data []byte) {
	s.sndMu.Lock()
	seq := s.outSeq
	s.outSeq++
	s.unacked[seq] = &segment{ftype: ftype, seq: seq, data: data, sent: time.Now()}
	s.sndMu.Unlock()
	s.sendFrame(ftype, seq, s.curAck(), data)
}

func (s *reliableConn) curAck() uint32 {
	s.rcvMu.Lock()
	a := s.inNext
	s.rcvMu.Unlock()
	return a
}

func (s *reliableConn) sendAck() {
	s.sendFrame(ftACK, 0, s.curAck(), nil)
}

func (s *reliableConn) onFrame(fr frame) {
	s.lastRx = time.Now()
	switch fr.ftype {
	case ftACK:
		s.handleAck(fr.ack)
	case ftPING:
		s.handleAck(fr.ack)
		s.sendAck()
	case ftSYN, ftDATA, ftFIN:
		s.handleAck(fr.ack)
		s.recvSegment(fr)
	}
}

func (s *reliableConn) handleAck(ack uint32) {
	s.sndMu.Lock()
	for seq := range s.unacked {
		if seqLT(seq, ack) {
			delete(s.unacked, seq)
		}
	}
	s.sndCond.Broadcast()
	s.sndMu.Unlock()
}

func (s *reliableConn) recvSegment(fr frame) {
	s.rcvMu.Lock()
	if seqLT(fr.seq, s.inNext) {
		s.rcvMu.Unlock()
		s.sendAck() // duplicate; re-ack
		return
	}
	if seqLT(fr.seq, s.inNext+icmpWindow) {
		if _, dup := s.reorder[fr.seq]; !dup {
			s.reorder[fr.seq] = fr
		}
		for {
			nf, ok := s.reorder[s.inNext]
			if !ok {
				break
			}
			delete(s.reorder, s.inNext)
			switch nf.ftype {
			case ftDATA:
				if len(nf.data) > 0 {
					s.rcvData = append(s.rcvData, nf.data...)
				}
			case ftFIN:
				s.eof = true
			}
			s.inNext++
		}
		s.rcvCond.Broadcast()
	}
	s.rcvMu.Unlock()
	s.sendAck()
}

func (s *reliableConn) Read(p []byte) (int, error) {
	s.rcvMu.Lock()
	for len(s.rcvData) == 0 && !s.eof && !s.rcvReset {
		s.rcvCond.Wait()
	}
	if len(s.rcvData) > 0 {
		n := copy(p, s.rcvData)
		s.rcvData = s.rcvData[n:]
		s.rcvMu.Unlock()
		return n, nil
	}
	s.rcvMu.Unlock()
	if s.rcvReset {
		return 0, io.ErrClosedPipe
	}
	return 0, io.EOF
}

func (s *reliableConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > icmpMaxData {
			chunk = chunk[:icmpMaxData]
		}
		s.sndMu.Lock()
		for len(s.unacked) >= icmpWindow && !s.sndClosed {
			s.sndCond.Wait()
		}
		if s.sndClosed {
			s.sndMu.Unlock()
			return total, io.ErrClosedPipe
		}
		seq := s.outSeq
		s.outSeq++
		buf := append([]byte(nil), chunk...)
		s.unacked[seq] = &segment{ftype: ftDATA, seq: seq, data: buf, sent: time.Now()}
		s.sndMu.Unlock()

		s.sendFrame(ftDATA, seq, s.curAck(), buf)
		total += len(chunk)
		p = p[len(chunk):]
	}
	return total, nil
}

func (s *reliableConn) CloseWrite() error {
	s.sndMu.Lock()
	if s.sndClosed {
		s.sndMu.Unlock()
		return nil
	}
	s.sndClosed = true
	seq := s.outSeq
	s.outSeq++
	s.unacked[seq] = &segment{ftype: ftFIN, seq: seq, sent: time.Now()}
	s.sndCond.Broadcast()
	s.sndMu.Unlock()
	s.sendFrame(ftFIN, seq, s.curAck(), nil)
	return nil
}

func (s *reliableConn) Close() error {
	s.CloseWrite()
	go func() {
		time.Sleep(1 * time.Second) // let final ACKs/FIN flush
		s.shutdown()
	}()
	return nil
}

func (s *reliableConn) shutdown() {
	s.doneOnce.Do(func() {
		close(s.done)
		s.ep.remove(s.id)
		s.rcvMu.Lock()
		s.rcvReset = true
		s.rcvCond.Broadcast()
		s.rcvMu.Unlock()
		s.sndMu.Lock()
		s.sndCond.Broadcast()
		s.sndMu.Unlock()
	})
}

func (s *reliableConn) timerLoop() {
	t := time.NewTicker(icmpTick)
	defer t.Stop()
	const idleTimeout = 90 * time.Second
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
		}
		now := time.Now()

		s.sndMu.Lock()
		var resend []*segment
		dead := false
		for _, seg := range s.unacked {
			rto := icmpRTOBase << uint(seg.retries)
			if rto > icmpRTOMax {
				rto = icmpRTOMax
			}
			if now.Sub(seg.sent) >= rto {
				seg.retries++
				if seg.retries > icmpMaxRetries {
					dead = true
					break
				}
				seg.sent = now
				resend = append(resend, &segment{ftype: seg.ftype, seq: seg.seq, data: seg.data})
			}
		}
		s.sndMu.Unlock()

		if dead {
			s.shutdown()
			return
		}
		ack := s.curAck()
		for _, seg := range resend {
			s.sendFrame(seg.ftype, seg.seq, ack, seg.data)
		}

		if s.ep.isClient && now.Sub(s.lastTx) >= icmpKeepalive {
			s.sendFrame(ftPING, 0, ack, nil)
		}

		if now.Sub(s.lastRx) >= idleTimeout {
			s.shutdown()
			return
		}
	}
}

type icmpAddr struct{ ip [4]byte }

func (a icmpAddr) Network() string { return "icmp" }
func (a icmpAddr) String() string  { return net.IP(a.ip[:]).String() }

func (s *reliableConn) LocalAddr() net.Addr                { return icmpAddr{} }
func (s *reliableConn) RemoteAddr() net.Addr               { return icmpAddr{s.peer} }
func (s *reliableConn) SetDeadline(t time.Time) error      { return nil }
func (s *reliableConn) SetReadDeadline(t time.Time) error  { return nil }
func (s *reliableConn) SetWriteDeadline(t time.Time) error { return nil }

func seqLT(a, b uint32) bool { return int32(a-b) < 0 }

func keyHex(b []byte) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexd[c>>4]
		out[i*2+1] = hexd[c&0x0f]
	}
	return string(out)
}

func (h *icmpHub) serverEndpoint(key []byte) (*icmpEndpoint, error) {
	if err := h.ensure(); err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	id := "s|" + keyHex(key)
	h.mu.Lock()
	for _, ep := range h.endpoints {
		if ep.tag == id {
			h.mu.Unlock()
			return ep, nil
		}
	}
	ep := &icmpEndpoint{hub: h, gcm: gcm, isClient: false, sessions: map[uint32]*reliableConn{},
		acceptCh: make(chan *reliableConn, 128), tag: id}
	h.endpoints = append(h.endpoints, ep)
	h.mu.Unlock()
	return ep, nil
}

func (h *icmpHub) clientEndpoint(peer [4]byte, key []byte) (*icmpEndpoint, error) {
	if err := h.ensure(); err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	id := "c|" + net.IP(peer[:]).String() + "|" + keyHex(key)
	h.mu.Lock()
	for _, ep := range h.endpoints {
		if ep.tag == id {
			h.mu.Unlock()
			return ep, nil
		}
	}
	ep := &icmpEndpoint{hub: h, gcm: gcm, isClient: true, peer: peer, sessions: map[uint32]*reliableConn{}, tag: id}
	h.endpoints = append(h.endpoints, ep)
	h.mu.Unlock()
	return ep, nil
}

type icmpTransport struct{}

func (icmpTransport) Listen(addr string, opt TransportOpt) (net.Listener, error) {
	ep, err := icmpGlobal.serverEndpoint(deriveKey(opt.Secret))
	if err != nil {
		return nil, err
	}
	return &icmpListener{ep: ep}, nil
}

func (icmpTransport) Dial(addr string, opt TransportOpt) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip, err := resolve4(host)
	if err != nil {
		return nil, err
	}
	ep, err := icmpGlobal.clientEndpoint(ip, deriveKey(opt.Secret))
	if err != nil {
		return nil, err
	}
	return ep.openSession(), nil
}

type icmpListener struct {
	ep     *icmpEndpoint
	closed bool
}

func (l *icmpListener) Accept() (net.Conn, error) {
	s, ok := <-l.ep.acceptCh
	if !ok {
		return nil, errors.New("icmp listener closed")
	}
	return s, nil
}

func (l *icmpListener) Close() error {
	l.ep.mu.Lock()
	if !l.ep.closed {
		l.ep.closed = true
	}
	l.ep.mu.Unlock()
	return nil
}

func (l *icmpListener) Addr() net.Addr { return icmpAddr{} }

func resolve4(host string) ([4]byte, error) {
	var out [4]byte
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			copy(out[:], v4)
			return out, nil
		}
	}
	addrs, err := net.LookupIP(host)
	if err != nil {
		return out, err
	}
	for _, a := range addrs {
		if v4 := a.To4(); v4 != nil {
			copy(out[:], v4)
			return out, nil
		}
	}
	return out, errors.New("no IPv4 address for " + host)
}

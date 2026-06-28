package main

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"log"
	mrand "math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	icmpMaxData     = 1024            // bytes of stream data per packet
	icmpWindow      = 256             // max in-flight segments per direction
	icmpRTOBase     = 500 * time.Millisecond
	icmpRTOStep     = 150 * time.Millisecond
	icmpRTOMax      = 1500 * time.Millisecond
	icmpTick        = 50 * time.Millisecond
	icmpMaxRetries  = 30
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
	// WriteTo sends an ICMP echo carrying payload. If src is non-zero the packet
	// is sent with that source IP (via IP_HDRINCL); otherwise the kernel picks it.
	WriteTo(payload []byte, src, dst [4]byte, asReply bool, replyID uint16) error
	// ReadFrom returns the ICMP payload along with the packet's IP source and
	// destination, whether it was an echo reply, and the ICMP id.
	ReadFrom(buf []byte) (n int, src, dst [4]byte, wasReply bool, id uint16, err error)
	Close() error
}

var errShortPacket = errors.New("icmp: short packet")

// zeroIP4 is the "unset" sentinel for the multi-IP fields.
var zeroIP4 [4]byte

// buildIPv4 builds a 20-byte IPv4 header for an ICMP packet of payloadLen bytes,
// used on the IP_HDRINCL transmit path so we can choose the source address.
func buildIPv4(src, dst [4]byte, payloadLen int) []byte {
	h := make([]byte, 20)
	h[0] = 0x45 // version 4, IHL 5 (no options)
	binary.BigEndian.PutUint16(h[2:4], uint16(20+payloadLen))
	var id [2]byte
	rand.Read(id[:])
	copy(h[4:6], id[:])
	h[6] = 0x40 // Don't Fragment
	h[8] = 64   // TTL
	h[9] = 1    // protocol = ICMP
	copy(h[12:16], src[:])
	copy(h[16:20], dst[:])
	binary.BigEndian.PutUint16(h[10:12], icmpChecksum(h)) // kernel may recompute; set it anyway
	return h
}

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
	fd    int // SOCK_RAW IPPROTO_ICMP: kernel-sourced sends + all receives
	id    uint16
	seqMu sync.Mutex
	seq   uint16

	txMu sync.Mutex
	txfd int // lazy SOCK_RAW IPPROTO_RAW (IP_HDRINCL) for source-chosen sends; -1 until used
}

func newRawICMPConn() (*rawICMPConn, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		log.Printf("icmp: could not open raw socket: %v (raw ICMP needs root / CAP_NET_RAW)", err)
		return nil, err
	}
	var pid [2]byte
	rand.Read(pid[:])
	id := binary.BigEndian.Uint16(pid[:])
	dbg("icmp: raw socket opened (fd=%d, id=%d)", fd, id)
	return &rawICMPConn{fd: fd, id: id, txfd: -1}, nil
}

// txConn lazily opens the IP_HDRINCL transmit socket used when a packet needs a
// specific source IP. IPPROTO_RAW implies IP_HDRINCL on Linux.
func (c *rawICMPConn) txConn() (int, error) {
	c.txMu.Lock()
	defer c.txMu.Unlock()
	if c.txfd >= 0 {
		return c.txfd, nil
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Printf("icmp: could not open IP_HDRINCL socket: %v (multi-IP needs root / CAP_NET_RAW)", err)
		return -1, err
	}
	c.txfd = fd
	dbg("icmp: HDRINCL tx socket opened (fd=%d)", fd)
	return fd, nil
}

var icmpLossProb, icmpExtraDelay = parseICMPChaos()

func parseICMPChaos() (float64, time.Duration) {
	p := 0.0
	if v := os.Getenv("RAHGOZAR_ICMP_LOSS"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			p = f
		}
	}
	var d time.Duration
	if v := os.Getenv("RAHGOZAR_ICMP_DELAY"); v != "" {
		if pd, err := time.ParseDuration(v); err == nil {
			d = pd
		}
	}
	return p, d
}

func (c *rawICMPConn) WriteTo(payload []byte, src, dst [4]byte, asReply bool, replyID uint16) error {
	c.seqMu.Lock()
	c.seq++
	seq := c.seq
	c.seqMu.Unlock()
	id := c.id
	if asReply {
		id = replyID // match the entry's request id so NAT lets the reply back
	}
	out := buildEcho(asReply, id, seq, payload)

	fd := c.fd
	if src != zeroIP4 {
		// Stamp our chosen source IP: prepend an IP header and send via HDRINCL.
		txfd, err := c.txConn()
		if err != nil {
			return err
		}
		fd = txfd
		out = append(buildIPv4(src, dst, len(out)), out...)
	}

	if icmpLossProb > 0 && mrand.Float64() < icmpLossProb {
		return nil
	}
	if icmpExtraDelay > 0 {
		go func() {
			time.Sleep(icmpExtraDelay)
			syscall.Sendto(fd, out, 0, &syscall.SockaddrInet4{Addr: dst})
		}()
		return nil
	}
	return syscall.Sendto(fd, out, 0, &syscall.SockaddrInet4{Addr: dst})
}

func (c *rawICMPConn) ReadFrom(buf []byte) (int, [4]byte, [4]byte, bool, uint16, error) {
	raw := make([]byte, 65535)
	n, _, err := syscall.Recvfrom(c.fd, raw, 0)
	if err != nil {
		return 0, zeroIP4, zeroIP4, false, 0, err
	}
	if n < 20 {
		return 0, zeroIP4, zeroIP4, false, 0, errShortPacket
	}
	// Raw IPv4 receives include the IP header; read src/dst straight from it.
	var src, dst [4]byte
	copy(src[:], raw[12:16])
	copy(dst[:], raw[16:20])
	ihl := int(raw[0]&0x0f) * 4
	if n < ihl+8 {
		return 0, src, dst, false, 0, errShortPacket
	}
	icmpType := raw[ihl]
	id := binary.BigEndian.Uint16(raw[ihl+4 : ihl+6])
	payload := raw[ihl+8 : n]
	m := copy(buf, payload)
	return m, src, dst, icmpType == 0, id, nil
}

func (c *rawICMPConn) Close() error {
	c.txMu.Lock()
	if c.txfd >= 0 {
		syscall.Close(c.txfd)
		c.txfd = -1
	}
	c.txMu.Unlock()
	return syscall.Close(c.fd)
}

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
		n, src, dst, wasReply, icmpID, err := h.pc.ReadFrom(buf)
		if err != nil {
			dbg("icmp: read error: %v", err)
			return
		}
		payload := buf[:n]
		matched := false
		for _, ep := range h.snapshot() {
			if ep.consume(payload, src, dst, wasReply, icmpID) {
				matched = true
				break
			}
		}
		if !matched {
			dbg("icmp: rx %d bytes %s->%s (reply=%v id=%d) -> no endpoint matched/decrypted", n, net.IP(src[:]).String(), net.IP(dst[:]).String(), wasReply, icmpID)
		}
	}
}

type icmpEndpoint struct {
	hub      *icmpHub
	gcm      cipher.AEAD
	isClient bool
	peer     [4]byte
	tag      string

	// Multi-IP ICMP routing (zero = default behavior). srcIP is stamped on
	// outgoing packets; listenIP filters incoming by IP destination; peerIP is
	// where a server sends its replies (overriding the request's source).
	srcIP    [4]byte
	listenIP [4]byte
	peerIP   [4]byte

	mu       sync.Mutex
	sessions map[uint32]*reliableConn
	acceptCh chan *reliableConn
	closed   bool
}

func (ep *icmpEndpoint) consume(payload []byte, src, dst [4]byte, wasReply bool, icmpID uint16) bool {
	if ep.isClient != wasReply {
		return false
	}
	if ep.listenIP != zeroIP4 && dst != ep.listenIP {
		return false // not addressed to this endpoint's configured local IP
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
	dbg("icmp: rx ok from %s session=%d type=%d seq=%d ack=%d dlen=%d", net.IP(src[:]).String(), fr.session, fr.ftype, fr.seq, fr.ack, len(fr.data))
	ep.route(fr, src, icmpID)
	return true
}

func (ep *icmpEndpoint) route(fr frame, src [4]byte, icmpID uint16) {
	ep.mu.Lock()
	s := ep.sessions[fr.session]
	if s == nil {
		if ep.isClient || ep.closed {
			ep.mu.Unlock()
			return
		}
		replyTo := src
		if ep.peerIP != zeroIP4 {
			replyTo = ep.peerIP // asymmetric routing: send replies to a different entry IP
		}
		s = newReliableConn(ep, fr.session, replyTo)
		s.peerID.Store(uint32(icmpID)) // reply with the id the entry used
		ep.sessions[fr.session] = s
		ep.mu.Unlock()
		dbg("icmp: new inbound session %d from %s (reply id=%d)", fr.session, net.IP(src[:]).String(), icmpID)
		select {
		case ep.acceptCh <- s:
		default:
			ep.mu.Lock()
			delete(ep.sessions, fr.session)
			ep.mu.Unlock()
			return
		}
	} else {
		s.peerID.Store(uint32(icmpID))
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
	dbg("icmp: opened outbound session %d to %s", id, net.IP(ep.peer[:]).String())
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
	ep     *icmpEndpoint
	id     uint32
	peer   [4]byte
	peerID atomic.Uint32

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

	done       chan struct{}
	doneOnce   sync.Once
	lastTxNano atomic.Int64
	lastRxNano atomic.Int64
}

func newReliableConn(ep *icmpEndpoint, id uint32, peer [4]byte) *reliableConn {
	s := &reliableConn{
		ep:      ep,
		id:      id,
		peer:    peer,
		unacked: make(map[uint32]*segment),
		reorder: make(map[uint32]frame),
		done:    make(chan struct{}),
	}
	s.lastTxNano.Store(time.Now().UnixNano())
	s.lastRxNano.Store(time.Now().UnixNano())
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
		pc.WriteTo(blob, s.ep.srcIP, s.peer, !s.ep.isClient, uint16(s.peerID.Load()))
	}
	s.lastTxNano.Store(time.Now().UnixNano())
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
	s.lastRxNano.Store(time.Now().UnixNano())
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
			rto := icmpRTOBase + time.Duration(seg.retries)*icmpRTOStep
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

		if s.ep.isClient && time.Duration(now.UnixNano()-s.lastTxNano.Load()) >= icmpKeepalive {
			s.sendFrame(ftPING, 0, ack, nil)
		}

		if time.Duration(now.UnixNano()-s.lastRxNano.Load()) >= idleTimeout {
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

func (h *icmpHub) serverEndpoint(key []byte, srcIP, listenIP, peerIP [4]byte) (*icmpEndpoint, error) {
	if err := h.ensure(); err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	id := "s|" + keyHex(key) + "|" + ipTag(srcIP, listenIP, peerIP)
	h.mu.Lock()
	for _, ep := range h.endpoints {
		if ep.tag == id {
			h.mu.Unlock()
			return ep, nil
		}
	}
	ep := &icmpEndpoint{hub: h, gcm: gcm, isClient: false, sessions: map[uint32]*reliableConn{},
		acceptCh: make(chan *reliableConn, 128), tag: id, srcIP: srcIP, listenIP: listenIP, peerIP: peerIP}
	h.endpoints = append(h.endpoints, ep)
	h.mu.Unlock()
	dbg("icmp: server endpoint ready (src=%s listen=%s peer=%s)", net.IP(srcIP[:]), net.IP(listenIP[:]), net.IP(peerIP[:]))
	return ep, nil
}

func (h *icmpHub) clientEndpoint(peer [4]byte, key []byte, srcIP, listenIP [4]byte) (*icmpEndpoint, error) {
	if err := h.ensure(); err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	id := "c|" + net.IP(peer[:]).String() + "|" + ipTag(srcIP, listenIP, peer) + "|" + keyHex(key)
	h.mu.Lock()
	for _, ep := range h.endpoints {
		if ep.tag == id {
			h.mu.Unlock()
			return ep, nil
		}
	}
	ep := &icmpEndpoint{hub: h, gcm: gcm, isClient: true, peer: peer, sessions: map[uint32]*reliableConn{},
		tag: id, srcIP: srcIP, listenIP: listenIP, peerIP: peer}
	h.endpoints = append(h.endpoints, ep)
	h.mu.Unlock()
	return ep, nil
}

func ipTag(ips ...[4]byte) string {
	parts := make([]string, len(ips))
	for i, ip := range ips {
		parts[i] = net.IP(ip[:]).String()
	}
	return strings.Join(parts, "|")
}

type icmpTransport struct{}

func (icmpTransport) Listen(addr string, opt TransportOpt) (net.Listener, error) {
	ep, err := icmpGlobal.serverEndpoint(deriveKey(opt.Secret),
		parseIP4(opt.ICMPSrcIP), parseIP4(opt.ICMPListenIP), parseIP4(opt.ICMPPeerIP))
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
	// The peer (destination) IP defaults to the dial target, but icmp_peer_ip
	// lets the entry send requests to a different exit IP than it forwards to.
	dst := parseIP4(opt.ICMPPeerIP)
	if dst == zeroIP4 {
		ip, err := resolve4(host)
		if err != nil {
			return nil, err
		}
		dst = ip
	}
	ep, err := icmpGlobal.clientEndpoint(dst, deriveKey(opt.Secret),
		parseIP4(opt.ICMPSrcIP), parseIP4(opt.ICMPListenIP))
	if err != nil {
		return nil, err
	}
	return ep.openSession(), nil
}

// parseIP4 parses an IPv4 string into a [4]byte, returning the zero value for
// empty/invalid input (which the transport treats as "use the default").
func parseIP4(s string) [4]byte {
	var out [4]byte
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return out
	}
	if v4 := ip.To4(); v4 != nil {
		copy(out[:], v4)
	}
	return out
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

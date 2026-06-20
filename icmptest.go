package main

import (
	"fmt"
	"log"
	"net"
	"time"
)

func icmpEchoServer(secret string) {
	if secret == "" {
		log.Fatalf("provide a shared secret with -secret (must match the client)")
	}
	ln, err := icmpTransport{}.Listen(":0", TransportOpt{Secret: secret})
	if err != nil {
		log.Fatalf("icmp listen failed: %v", err)
	}
	log.Printf("ICMP echo server ready. It will echo back anything a client sends.")
	log.Printf("Tip: set  sysctl -w net.ipv4.icmp_echo_ignore_all=1  so the kernel's own ping replies don't add noise.")
	log.Printf("Run the client on the other server:  ./rahgozar -icmp-client <THIS_SERVER_IP> -secret <secret>")
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			time.Sleep(time.Second)
			continue
		}
		log.Printf("session accepted from %s", c.RemoteAddr())
		go func(c net.Conn) {
			defer c.Close()
			buf := make([]byte, 32*1024)
			for {
				n, err := c.Read(buf)
				if n > 0 {
					log.Printf("echoing %d bytes back", n)
					c.Write(buf[:n])
				}
				if err != nil {
					return
				}
			}
		}(c)
	}
}

func icmpPingClient(target, secret string) {
	if secret == "" {
		log.Fatalf("provide a shared secret with -secret (must match the server)")
	}
	log.Printf("dialing ICMP exit %s ...", target)
	c, err := icmpTransport{}.Dial(target+":0", TransportOpt{Secret: secret})
	if err != nil {
		log.Fatalf("icmp dial failed: %v", err)
	}
	defer c.Close()

	msg := []byte(fmt.Sprintf("RAHGOZAR-PING-%d", time.Now().UnixNano()))
	start := time.Now()
	if _, err := c.Write(msg); err != nil {
		log.Fatalf("write failed: %v", err)
	}
	log.Printf("sent %d bytes, waiting up to 10s for the echo...", len(msg))

	done := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 32*1024)
		got := []byte{}
		for len(got) < len(msg) {
			n, err := c.Read(buf)
			if n > 0 {
				got = append(got, buf[:n]...)
			}
			if err != nil {
				break
			}
		}
		done <- got
	}()

	select {
	case got := <-done:
		if string(got) == string(msg) {
			log.Printf("SUCCESS: ICMP round-trip works. RTT = %v", time.Since(start))
			log.Printf("The ICMP transport is fine; if your tunnel still fails the issue is the Xray/forward wiring.")
		} else {
			log.Printf("PARTIAL: got %d of %d bytes back (%q). The link is up but unreliable.", len(got), len(msg), string(got))
		}
	case <-time.After(10 * time.Second):
		log.Printf("TIMEOUT: no echo in 10s. The exit never answered.")
		log.Printf("Re-run BOTH sides with RAHGOZAR_DEBUG=1 and check the exit's log:")
		log.Printf("  - if the exit shows 'rx ok ... session=...'  -> packets arrive and decrypt; reply path is the problem (NAT/firewall on the way back)")
		log.Printf("  - if the exit shows 'no endpoint matched/decrypted' -> the secret differs between the two sides")
		log.Printf("  - if the exit shows nothing at all -> ICMP isn't reaching it (firewall, or not running as root)")
	}
}

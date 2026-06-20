package main

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
)

func sitPrivateIPs(port int, isServer bool) (localIP, peerIP, subnet string) {
	hi := (port >> 8) & 0xff
	lo := port & 0xff
	base := fmt.Sprintf("10.200.%d.%d", hi, (lo%64)*4)
	parts := strings.Split(base, ".")
	last := parts[3]
	_ = last
	netPrefix := fmt.Sprintf("10.200.%d", hi)
	b := (lo % 64) * 4
	exitIP := fmt.Sprintf("%s.%d", netPrefix, b+1)
	entryIP := fmt.Sprintf("%s.%d", netPrefix, b+2)
	subnet = fmt.Sprintf("%s.%d/30", netPrefix, b)
	if isServer {
		return exitIP, entryIP, subnet
	}
	return entryIP, exitIP, subnet
}

func sitDevName(port int) string { return fmt.Sprintf("rgsit%d", port%10000) }

var sitMu sync.Mutex
var sitUp = map[string]bool{}

func run(cmd string, args ...string) error {
	out, err := exec.Command(cmd, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", cmd, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func ensureSIT(port int, remotePublic string, isServer bool) (peerPrivate string, err error) {
	localIP, peerIP, subnet := sitPrivateIPs(port, isServer)
	dev := sitDevName(port)

	sitMu.Lock()
	defer sitMu.Unlock()
	if sitUp[dev] {
		return peerIP, nil
	}

	if _, e := exec.LookPath("ip"); e != nil {
		return "", fmt.Errorf("the 'ip' command (iproute2) is required for sit mode")
	}

	exec.Command("ip", "link", "del", dev).Run()

	if err := run("ip", "tunnel", "add", dev, "mode", "sit",
		"remote", remotePublic, "local", "any", "ttl", "255"); err != nil {
		return "", err
	}
	if err := run("ip", "addr", "add", subnet, "dev", dev); err != nil {
		exec.Command("ip", "tunnel", "del", dev).Run()
		return "", err
	}
	if err := run("ip", "link", "set", dev, "up"); err != nil {
		exec.Command("ip", "tunnel", "del", dev).Run()
		return "", err
	}
	exec.Command("iptables", "-t", "mangle", "-A", "FORWARD", "-o", dev,
		"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS", "--clamp-mss-to-pmtu").Run()

	sitUp[dev] = true
	log.Printf("sit tunnel %s up: local %s <-> peer %s (remote public %s)", dev, localIP, peerIP, remotePublic)
	return peerIP, nil
}

func teardownSIT(port int) {
	dev := sitDevName(port)
	sitMu.Lock()
	defer sitMu.Unlock()
	if !sitUp[dev] {
		return
	}
	exec.Command("ip", "link", "del", dev).Run()
	delete(sitUp, dev)
	log.Printf("sit tunnel %s down", dev)
}

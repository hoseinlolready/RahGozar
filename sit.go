package main

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
)

// Each SIT tunnel gets its own device and its own /30, both derived from the
// link port, so the two ends agree (entry.target_port == exit.listen_port ==
// link port) while different tunnels never collide on a device or a subnet.
// This lets one server run several SIT tunnels at once.

func sitDevName(linkPort int) string { return fmt.Sprintf("rgsit%d", linkPort) }

func sitNet(linkPort int) (subnet, exitIP, entryIP string) {
	idx := linkPort % 16384      // 16384 distinct /30 blocks in 10.200.0.0/16
	base := idx * 4              // network offset within the /16
	c := (base >> 8) & 0xff
	d := base & 0xff
	subnet = fmt.Sprintf("10.200.%d.%d/30", c, d)
	exitIP = fmt.Sprintf("10.200.%d.%d", c, d+1)
	entryIP = fmt.Sprintf("10.200.%d.%d", c, d+2)
	return
}

func sitPrivateIPs(linkPort int, isServer bool) (localIP, peerIP string) {
	_, exitIP, entryIP := sitNet(linkPort)
	if isServer {
		return exitIP, entryIP
	}
	return entryIP, exitIP
}

var sitMu sync.Mutex
var sitUp = map[string]bool{}

func run(cmd string, args ...string) error {
	out, err := exec.Command(cmd, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", cmd, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func ensureSIT(linkPort int, remotePublic string, isServer bool) (peerPrivate string, err error) {
	localIP, peerIP := sitPrivateIPs(linkPort, isServer)
	subnet, _, _ := sitNet(linkPort)
	dev := sitDevName(linkPort)

	sitMu.Lock()
	defer sitMu.Unlock()
	if sitUp[dev] {
		return peerIP, nil
	}

	if _, e := exec.LookPath("ip"); e != nil {
		return "", fmt.Errorf("the 'ip' command (iproute2) is required for sit mode")
	}

	exec.Command("ip", "link", "del", dev).Run()

	dbg("sit: ip tunnel add %s mode sit remote %s local any ttl 255", dev, remotePublic)
	if err := run("ip", "tunnel", "add", dev, "mode", "sit",
		"remote", remotePublic, "local", "any", "ttl", "255"); err != nil {
		log.Printf("sit: failed to create tunnel %s: %v", dev, err)
		return "", err
	}
	dbg("sit: ip addr add %s dev %s", subnet, dev)
	if err := run("ip", "addr", "add", subnet, "dev", dev); err != nil {
		log.Printf("sit: failed to assign %s to %s: %v", subnet, dev, err)
		exec.Command("ip", "tunnel", "del", dev).Run()
		return "", err
	}
	if err := run("ip", "link", "set", dev, "up"); err != nil {
		log.Printf("sit: failed to bring %s up: %v", dev, err)
		exec.Command("ip", "tunnel", "del", dev).Run()
		return "", err
	}
	exec.Command("iptables", "-t", "mangle", "-A", "FORWARD", "-o", dev,
		"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS", "--clamp-mss-to-pmtu").Run()
	exec.Command("iptables", "-t", "mangle", "-A", "OUTPUT", "-o", dev,
		"-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
		"-j", "TCPMSS", "--set-mss", "1280").Run()

	sitUp[dev] = true
	log.Printf("sit tunnel %s up: local %s <-> peer %s (remote public %s). forward target will be %s", dev, localIP, peerIP, remotePublic, peerIP)
	return peerIP, nil
}

func teardownSIT(linkPort int) {
	dev := sitDevName(linkPort)
	sitMu.Lock()
	defer sitMu.Unlock()
	if !sitUp[dev] {
		return
	}
	exec.Command("ip", "link", "del", dev).Run()
	delete(sitUp, dev)
	log.Printf("sit tunnel %s down", dev)
}

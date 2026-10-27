// wg-isolated-check sends only this process's HTTP requests through WireGuard.
// It uses netstack.CreateNetTUN (an in-memory device), never tun.CreateTUN,
// OS routes, DNS settings, adapters, drivers, or a system-wide VPN service.
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type profile struct {
	local, dns netip.Addr
	mtu        int
	ipc        string // Secret: never print or persist this string.
}

func keyHex(value string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(b) != 32 {
		return "", errors.New("invalid WireGuard key encoding")
	}
	return hex.EncodeToString(b), nil
}

func parseProfile(text string) (profile, error) {
	sections := map[string]map[string]string{}
	section := ""
	scanner := bufio.NewScanner(strings.NewReader(text))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			if _, found := sections[section]; found {
				return profile{}, errors.New("only one interface and peer are supported")
			}
			sections[section] = map[string]string{}
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 || sections[section] == nil {
			return profile{}, errors.New("invalid profile structure")
		}
		sections[section][strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	if scanner.Err() != nil {
		return profile{}, errors.New("cannot read profile")
	}
	iface, peer := sections["Interface"], sections["Peer"]
	private, err := keyHex(iface["PrivateKey"])
	if err != nil {
		return profile{}, err
	}
	public, err := keyHex(peer["PublicKey"])
	if err != nil {
		return profile{}, err
	}
	address, err := netip.ParsePrefix(strings.TrimSpace(strings.Split(iface["Address"], ",")[0]))
	if err != nil || !address.Addr().Is4() {
		return profile{}, errors.New("an IPv4 client address is required")
	}
	dns, err := netip.ParseAddr(strings.TrimSpace(strings.Split(iface["DNS"], ",")[0]))
	if err != nil || !dns.Is4() {
		return profile{}, errors.New("an IPv4 DNS address is required")
	}
	// An IP endpoint avoids resolving the outer tunnel through an OS resolver.
	if _, err := netip.ParseAddrPort(peer["Endpoint"]); err != nil {
		return profile{}, errors.New("an IP:port endpoint is required")
	}
	mtu := 1280
	if iface["MTU"] != "" {
		mtu, err = strconv.Atoi(iface["MTU"])
		if err != nil || mtu < 576 || mtu > 1500 {
			return profile{}, errors.New("invalid MTU")
		}
	}
	ipc := "private_key=" + private + "\nreplace_peers=true\npublic_key=" + public + "\n"
	if peer["PresharedKey"] != "" {
		psk, err := keyHex(peer["PresharedKey"])
		if err != nil {
			return profile{}, err
		}
		ipc += "preshared_key=" + psk + "\n"
	}
	ipc += "endpoint=" + peer["Endpoint"] + "\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=25\n"
	return profile{address.Addr(), dns, mtu, ipc}, nil
}

func run() error {
	config := flag.String("config", "", "local WireGuard profile; contents never printed")
	url := flag.String("url", "https://example.com/", "HTTP(S) request made only inside the tunnel")
	flag.Parse()
	if *config == "" {
		return errors.New("-config is required")
	}
	b, err := os.ReadFile(*config)
	if err != nil {
		return errors.New("cannot read the selected profile")
	}
	p, err := parseProfile(string(b))
	if err != nil {
		return err
	}
	tun, network, err := netstack.CreateNetTUN([]netip.Addr{p.local}, []netip.Addr{p.dns}, p.mtu)
	if err != nil {
		return errors.New("cannot create in-memory network")
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()
	if err := dev.IpcSet(p.ipc); err != nil {
		return errors.New("cannot configure isolated WireGuard device")
	}
	if err := dev.Up(); err != nil {
		return errors.New("cannot start isolated WireGuard device")
	}
	// Report only counters, never IpcGet's secret-containing raw response.
	defer func() {
		state, err := dev.IpcGet()
		if err != nil {
			return
		}
		stats := map[string]string{}
		for _, line := range strings.Split(state, "\n") {
			pair := strings.SplitN(line, "=", 2)
			if len(pair) == 2 && (pair[0] == "rx_bytes" || pair[0] == "tx_bytes" || pair[0] == "last_handshake_time_sec") {
				stats[pair[0]] = pair[1]
			}
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"wireguard": stats})
	}()
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return network.DialContext(ctx, "tcp4", addr)
		},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	start := time.Now()
	response, err := client.Get(*url)
	if err != nil {
		return fmt.Errorf("isolated request failed: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 128*1024))
	if err != nil {
		return errors.New("cannot read tunneled HTTP response")
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
		"http_status": response.StatusCode, "body_bytes": len(body),
		"elapsed_ms": time.Since(start).Milliseconds(), "os_network_modified": false,
	})
	if response.StatusCode != 200 {
		return errors.New("unexpected HTTP status")
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

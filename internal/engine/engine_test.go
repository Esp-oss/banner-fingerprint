package engine

import (
	"testing"

	"github.com/Esp-oss/banner-fingerprint/internal/model"
	"github.com/Esp-oss/banner-fingerprint/internal/rules"
)

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	loaded, err := rules.Load("../../rules")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	return New(loaded)
}

func TestIdentifySampleDataset(t *testing.T) {
	eng := newTestEngine(t)
	cases := []struct {
		name          string
		input         model.Input
		protocol      string
		product       string
		version       string
		osHint        string
		minConfidence float64
		maxConfidence float64
	}{
		{"openssh-ubuntu", model.Input{IP: "1.2.3.4", Port: 22, Banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}, "SSH", "OpenSSH", "8.9p1", "Ubuntu", 0.95, 0.95},
		{"nginx", model.Input{IP: "1.2.3.5", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: text/html"}, "HTTP", "nginx", "1.24.0", "", 0.90, 0.90},
		{"apache", model.Input{IP: "1.2.3.6", Port: 443, Banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57"}, "HTTP", "Apache", "2.4.57", "", 0.90, 0.90},
		{"mysql-8", model.Input{IP: "1.2.3.7", Port: 3306, Banner: "J\\x00\\x00\\x00\\n8.0.32\\x00"}, "MySQL", "MySQL", "8.0.32", "", 0.90, 0.95},
		{"redis-err", model.Input{IP: "1.2.3.8", Port: 6379, Banner: "-ERR wrong number of arguments for 'get' command"}, "Redis", "Redis", "", "", 0.70, 0.80},
		{"proftpd", model.Input{IP: "1.2.3.9", Port: 21, Banner: "220 ProFTPD 1.3.7 Server (ProFTPD)"}, "FTP", "ProFTPD", "1.3.7", "", 0.90, 0.95},
		{"jetty", model.Input{IP: "1.2.3.10", Port: 8080, Banner: "HTTP/1.1 404 Not Found\r\nServer: Jetty/9.4.51"}, "HTTP", "Jetty", "9.4.51", "", 0.85, 0.85},
		{"openssh-debian", model.Input{IP: "1.2.3.11", Port: 22, Banner: "SSH-2.0-OpenSSH_9.3 Debian-1"}, "SSH", "OpenSSH", "9.3", "Debian", 0.95, 0.95},
		{"nginx-ubuntu", model.Input{IP: "1.2.3.12", Port: 80, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)"}, "HTTP", "nginx", "1.18.0", "Ubuntu", 0.90, 0.90},
		{"apache-ubuntu", model.Input{IP: "1.2.3.13", Port: 443, Banner: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)"}, "HTTP", "Apache", "2.4.41", "Ubuntu", 0.90, 0.90},
		{"mysql-57", model.Input{IP: "1.2.3.14", Port: 3306, Banner: "J\\x00\\x00\\x00\\n5.7.42\\x00"}, "MySQL", "MySQL", "5.7.42", "", 0.90, 0.95},
		{"redis-pong", model.Input{IP: "1.2.3.15", Port: 6379, Banner: "+PONG"}, "Redis", "Redis", "", "", 0.70, 0.80},
		{"vsftpd", model.Input{IP: "1.2.3.16", Port: 21, Banner: "220 (vsFTPd 3.0.5)"}, "FTP", "vsftpd", "3.0.5", "", 0.90, 0.95},
		{"nginx-8443", model.Input{IP: "1.2.3.17", Port: 8443, Banner: "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3"}, "HTTP", "nginx", "1.25.3", "", 0.90, 0.90},
		{"openssh-199", model.Input{IP: "1.2.3.18", Port: 22, Banner: "SSH-1.99-OpenSSH_4.3"}, "SSH", "OpenSSH", "4.3", "", 0.95, 0.95},
		{"tls-record", model.Input{IP: "1.2.3.19", Port: 9999, Banner: "\\x16\\x03\\x01\\x00\\xa5\\x01\\x00\\x00\\xa1"}, "TLS", "", "", "", 0.60, 0.60},
		{"iis", model.Input{IP: "1.2.3.20", Port: 8888, Banner: "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0"}, "HTTP", "Microsoft-IIS", "10.0", "", 0.90, 0.90},
		{"redis-noauth", model.Input{IP: "1.2.3.21", Port: 6379, Banner: "-NOAUTH Authentication required."}, "Redis", "Redis", "", "", 0.85, 0.90},
		{"pure-ftpd", model.Input{IP: "1.2.3.22", Port: 21, Banner: "220 Welcome to Pure-FTPd"}, "FTP", "Pure-FTPd", "", "", 0.80, 0.85},
		{"unknown", model.Input{IP: "1.2.3.23", Port: 12345, Banner: "QUIT\r\n"}, "unknown", "", "", "", 0, 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := eng.Identify(tc.input)
			if got.Protocol != tc.protocol {
				t.Fatalf("protocol = %q, want %q", got.Protocol, tc.protocol)
			}
			if got.Product != tc.product {
				t.Fatalf("product = %q, want %q", got.Product, tc.product)
			}
			if got.Version != tc.version {
				t.Fatalf("version = %q, want %q", got.Version, tc.version)
			}
			if got.OSHint != tc.osHint {
				t.Fatalf("os_hint = %q, want %q", got.OSHint, tc.osHint)
			}
			if got.Confidence < tc.minConfidence || got.Confidence > tc.maxConfidence {
				t.Fatalf("confidence = %.2f, want within [%.2f, %.2f]", got.Confidence, tc.minConfidence, tc.maxConfidence)
			}
			if got.IP != tc.input.IP || got.Port != int(tc.input.Port) {
				t.Fatalf("identity fields mismatch: %+v", got)
			}
		})
	}
}

func TestIdentifyNeverPanics(t *testing.T) {
	eng := newTestEngine(t)
	inputs := []model.Input{
		{IP: "x", Port: 0, Banner: ""},
		{IP: "x", Port: -1, Banner: "\x00\x01\x02\xff"},
		{IP: "x", Port: 65536, Banner: string(make([]byte, 1024))},
		{IP: "x", Port: 22, BannerBase64: "!!!not-base64!!!"},
		{IP: "x", Port: 22, Banner: "SSH-2.0-"},
	}
	for _, input := range inputs {
		_ = eng.Identify(input)
	}
}

func TestBase64Banner(t *testing.T) {
	eng := newTestEngine(t)
	// "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"
	got := eng.Identify(model.Input{
		IP:           "10.0.0.1",
		Port:         22,
		BannerBase64: "U1NILTIuMC1PcGVuU1NIXzguOXAxIFVidW50dS0z",
	})
	if got.Protocol != "SSH" || got.Product != "OpenSSH" || got.Version != "8.9p1" {
		t.Fatalf("unexpected result: %+v", got)
	}
}

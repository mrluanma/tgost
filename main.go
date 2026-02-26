package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"
)

const version = "1.0.0"

type config struct {
	listenHost  string
	listenPort  uint16
	relayHost   string
	relayPort   uint16
	username    string
	password    string
	debug       bool
	listenProto int
}

var gConfig config
var activeConnections int32 // atomic

func atomicLoadConnections() int32 {
	return atomic.LoadInt32(&activeConnections)
}

func atomicAddConnections(delta int32) int32 {
	return atomic.AddInt32(&activeConnections, delta)
}

// parsePort parses a port string and returns the port number (1-65535) or an error.
func parsePort(s string) (uint16, error) {
	val, err := strconv.ParseUint(s, 10, 16)
	if err != nil || val == 0 {
		return 0, fmt.Errorf("invalid port: %s", s)
	}
	return uint16(val), nil
}

// parseListen parses the listen address argument.
// Formats: http://[host]:port, socks5://[host]:port, [host]:port, :port, port
func parseListen(arg string) error {
	p := arg

	// Parse scheme prefix
	if strings.HasPrefix(p, "socks5://") {
		gConfig.listenProto = listenProtoSOCKS5
		p = p[9:]
	} else if strings.HasPrefix(p, "http://") {
		gConfig.listenProto = listenProtoHTTP
		p = p[7:]
	} else {
		gConfig.listenProto = listenProtoAuto
	}

	// Parse [host]:port or host:port or :port or bare port
	if len(p) > 0 && unicode.IsDigit(rune(p[0])) && !strings.ContainsAny(p, ".:") {
		// Bare port number (no dots or colons, so not host:port or IP)
		port, err := parsePort(p)
		if err != nil {
			return fmt.Errorf("invalid listen port: %s", p)
		}
		gConfig.listenHost = "::"
		gConfig.listenPort = port
	} else {
		host, portStr, err := parseHostPort(p)
		if err != nil {
			return err
		}
		if host == "" {
			gConfig.listenHost = "::"
		} else {
			gConfig.listenHost = host
		}
		if portStr != "" {
			port, err := parsePort(portStr)
			if err != nil {
				return fmt.Errorf("invalid listen port: %s", portStr)
			}
			gConfig.listenPort = port
		} else {
			gConfig.listenPort = 8080
		}
	}

	return nil
}

// parseForward parses the forward URL argument.
// Format: relay+tls://[user:pass@]host:port[/...]
func parseForward(arg string) error {
	p := arg

	if strings.HasPrefix(p, "relay+tls://") {
		p = p[12:]
	} else if strings.HasPrefix(p, "relay://") {
		return fmt.Errorf("plain relay:// not supported, use relay+tls://")
	} else {
		return fmt.Errorf("invalid protocol, expected relay+tls://")
	}

	// Check for user:pass@ or user@
	if at := strings.IndexByte(p, '@'); at >= 0 {
		userpass := p[:at]
		before, after, ok := strings.Cut(userpass, ":")
		if ok {
			gConfig.username = before
			gConfig.password = after
		} else {
			gConfig.username = userpass
		}
		p = p[at+1:]
	}

	// Truncate at trailing path
	if slash := strings.IndexByte(p, '/'); slash >= 0 {
		p = p[:slash]
	}

	// Parse host:port
	host, portStr, err := parseHostPort(p)
	if err != nil {
		return err
	}
	gConfig.relayHost = host
	if portStr != "" {
		port, err := parsePort(portStr)
		if err != nil {
			return fmt.Errorf("invalid relay port: %s", portStr)
		}
		gConfig.relayPort = port
	} else {
		gConfig.relayPort = 443
	}

	if gConfig.relayHost == "" {
		return fmt.Errorf("empty relay host")
	}

	return nil
}

// Logging helpers — all output goes to stderr.
func logDebug(format string, args ...any) {
	if gConfig.debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] "+format+"\n", args...)
	}
}

func logInfo(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[INFO] "+format+"\n", args...)
}

func logError(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[ERROR] "+format+"\n", args...)
}

// normalizeArgs converts --long flags to their -short equivalents
// so that Go's flag package can parse them.
func normalizeArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if strings.HasPrefix(a, "--") {
			// Handle --flag=value
			key := a[2:]
			val := ""
			if eq := strings.IndexByte(key, '='); eq >= 0 {
				val = key[eq+1:]
				key = key[:eq]
			}

			short := ""
			switch key {
			case "listen":
				short = "-L"
			case "forward":
				short = "-F"
			case "debug":
				short = "-d"
			case "version":
				short = "-v"
			case "help":
				short = "-h"
			default:
				out = append(out, a)
				continue
			}

			if val != "" {
				out = append(out, short, val)
			} else {
				out = append(out, short)
			}
		} else {
			out = append(out, a)
		}
	}
	return out
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: tgost [OPTIONS] -L <listen> -F <forward>

A minimal GOST relay client with HTTP CONNECT and SOCKS5 proxy.

Options:
  -L, --listen <addr>     Listen address
                          Schemes: http://, socks5://, or none (auto-detect)
  -F, --forward <url>     Relay server URL
                          Format: relay+tls://[user:pass@]host:port
  -d, --debug             Enable debug logging
  -v, --version           Show version
  -h, --help              Show this help

Note: Credentials in -F are visible in the process list.
Use GOST_F environment variable to pass them securely.

Examples:
  tgost -L http://[::]:8080 -F relay+tls://relay.example.com:443
  tgost -L socks5://[::]:1080 -F relay+tls://relay.example.com:443
  tgost -L :8080 -F relay+tls://relay.example.com:443 -d
  (no scheme = auto-detect HTTP CONNECT or SOCKS5 per connection)
`)
}

func main() {
	// Defaults
	gConfig.listenHost = "::"
	gConfig.listenPort = 8080
	gConfig.listenProto = listenProtoAuto

	// Normalize args for flag parsing
	normalized := normalizeArgs(os.Args[1:])

	fs := flag.NewFlagSet("tgost", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var listenArg, forwardArg string
	var showVersion, showHelp bool

	fs.StringVar(&listenArg, "L", "", "Listen address")
	fs.StringVar(&forwardArg, "F", "", "Forward URL")
	fs.BoolVar(&gConfig.debug, "d", false, "Enable debug logging")
	fs.BoolVar(&showVersion, "v", false, "Show version")
	fs.BoolVar(&showHelp, "h", false, "Show help")

	if err := fs.Parse(normalized); err != nil {
		os.Exit(1)
	}

	if showVersion {
		fmt.Printf("tgost %s\n", version)
		os.Exit(0)
	}

	if showHelp {
		printUsage()
		os.Exit(0)
	}

	// Env fallback
	if listenArg == "" {
		listenArg = os.Getenv("GOST_L")
	}
	if forwardArg == "" {
		forwardArg = os.Getenv("GOST_F")
	}

	// Parse listen
	if listenArg != "" {
		if err := parseListen(listenArg); err != nil {
			logError("Invalid listen address: %v", err)
			printUsage()
			os.Exit(1)
		}
	}

	// Parse forward (required)
	if forwardArg == "" {
		logError("Forward URL (-F) is required")
		printUsage()
		os.Exit(1)
	}
	if err := parseForward(forwardArg); err != nil {
		logError("Invalid forward URL: %v", err)
		printUsage()
		os.Exit(1)
	}

	// Initialize shared TLS config with session cache
	initTLSConfig(gConfig.relayHost)

	// Setup context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		logInfo("Received signal %v, shutting down...", sig)
		cancel()
	}()

	// Run server
	if err := runServer(ctx); err != nil {
		logError("Server error: %v", err)
	}

	// Drain: wait for active connections to finish
	active := atomicLoadConnections()
	if active > 0 {
		logInfo("Waiting for %d active connection(s) to finish...", active)
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if atomicLoadConnections() == 0 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		active = atomicLoadConnections()
		if active > 0 {
			logInfo("Shutdown with %d connection(s) still active", active)
		}
	}
}

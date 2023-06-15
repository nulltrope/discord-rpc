//go:build !windows

package transport

import (
	"fmt"
	"net"
	"time"
	"os"
	"path/filepath"
)

const unixSocketBaseAddress = `discord-ipc`

// getTempDir is a helper function for finding the appropriate temp directory on unix systems.
func getTempDir() string {
	tempDir := "/tmp"
	for _, envVar := range []string{"XDG_RUNTIME_DIR", "TMPDIR", "TMP", "TEMP"} {
		if path := os.Getenv(envVar); path != "" {
			tempDir = path
			break
		}
	}
	return tempDir
}

// openSocket will open a numbered discord socket on unix-like systems with timeout.
func openSocket(number int, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(
		"unix", 
		filepath.Join(getTempDir(), fmt.Sprintf("%s-%d", unixSocketBaseAddress, number)),
		timeout,
	)
}

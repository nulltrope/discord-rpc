//go:build !windows

package transport

const unixSocketBaseAddress = `discord-ipc`

// helper for fetching temp dir on various systems
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

// open numbered discord socket on unix-like systems with timeout
func openSocket(number int, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(
		"unix", 
		filepath.Join(getTempDir(), fmt.Sprintf("%s-%s", unixSocketBaseAddress, number))
		timeout,
	)
}

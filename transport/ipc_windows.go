//go:build windows

package transport

import (
	"fmt"
	"net"
	"time"

	npipe "gopkg.in/natefinch/npipe.v2"
)

const windowsSocketBaseAddress = `\\.\pipe\discord-ipc`

// openSocket will open a numbered discord socket on windows systems with timeout.
func openSocket(number int, timeout time.Duration) (net.Conn, error) {
	return npipe.DialTimeout(fmt.Sprintf("%s-%d", windowsSocketBaseAddress, number), timeout)
}

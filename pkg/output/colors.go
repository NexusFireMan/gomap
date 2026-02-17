package output

import "fmt"

// ANSI color codes
const (
	// Standard colors
	ColorReset   = "\033[0m"
	ColorBold    = "\033[1m"
	ColorDim     = "\033[2m"
	ColorRed     = "\033[31m"
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorBlue    = "\033[34m"
	ColorMagenta = "\033[35m"
	ColorCyan    = "\033[36m"
	ColorWhite   = "\033[37m"

	// Bright colors
	ColorBrightRed     = "\033[91m"
	ColorBrightGreen   = "\033[92m"
	ColorBrightYellow  = "\033[93m"
	ColorBrightBlue    = "\033[94m"
	ColorBrightMagenta = "\033[95m"
	ColorBrightCyan    = "\033[96m"
	ColorBrightWhite   = "\033[97m"

	// Background colors
	BgRed   = "\033[41m"
	BgGreen = "\033[42m"
	BgBlue  = "\033[44m"
)

// Color functions that return colored strings

// Success returns a green colored string
func Success(text string) string {
	return fmt.Sprintf("%s%s%s", ColorGreen, text, ColorReset)
}

// Error returns a red colored string
func Error(text string) string {
	return fmt.Sprintf("%s%s%s", ColorRed, text, ColorReset)
}

// Warning returns a yellow colored string
func Warning(text string) string {
	return fmt.Sprintf("%s%s%s", ColorYellow, text, ColorReset)
}

// Info returns a blue colored string
func Info(text string) string {
	return fmt.Sprintf("%s%s%s", ColorBlue, text, ColorReset)
}

// Highlight returns a bright cyan colored string
func Highlight(text string) string {
	return fmt.Sprintf("%s%s%s", ColorBrightCyan, text, ColorReset)
}

// Bold returns a bold white string
func Bold(text string) string {
	return fmt.Sprintf("%s%s%s", ColorBold, text, ColorReset)
}

// Port returns a bright magenta colored port number
func Port(port int) string {
	return fmt.Sprintf("%s%d%s", ColorBrightMagenta, port, ColorReset)
}

// Service returns a bright green colored service name
func Service(name string) string {
	if name == "" {
		return ""
	}
	return fmt.Sprintf("%s%s%s", ColorGreen, name, ColorReset)
}

// Version returns a bright yellow colored version
func Version(version string) string {
	if version == "" {
		return ""
	}
	return fmt.Sprintf("%s%s%s", ColorBrightYellow, version, ColorReset)
}

// State returns a green colored "open" state
func State(state string) string {
	return fmt.Sprintf("%s%s%s", ColorGreen, state, ColorReset)
}

// Host returns a bright blue colored hostname/IP
func Host(hostname string) string {
	return fmt.Sprintf("%s%s%s", ColorBrightBlue, hostname, ColorReset)
}

// Count returns a bright white colored count number
func Count(count int) string {
	return fmt.Sprintf("%s%d%s", ColorBrightWhite, count, ColorReset)
}

// Banner returns colored banner text
func Banner(text string) string {
	return fmt.Sprintf("%s%s%s", ColorBrightCyan, text, ColorReset)
}

// Status returns a status message with green success indicator
func StatusOK(message string) string {
	return fmt.Sprintf("%s✓%s %s", ColorGreen, ColorReset, message)
}

// StatusWarn returns a status message with yellow warning indicator
func StatusWarn(message string) string {
	return fmt.Sprintf("%s⚠%s %s", ColorYellow, ColorReset, message)
}

// StatusError returns a status message with red error indicator
func StatusError(message string) string {
	return fmt.Sprintf("%s✗%s %s", ColorRed, ColorReset, message)
}

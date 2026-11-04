package scanner

import (
	"regexp"
	"strings"
)

var ircResponseRE = regexp.MustCompile(`(?i)^:\S+ (?:NOTICE AUTH\b|00[1-5] )`)
var ircProductRE = regexp.MustCompile(`(?i)unreal(?:ircd)?[\s/-]*([\d.]+(?:[-\w.]*)?)`)

func ircDisclosure(banner string) (version, evidence string) {
	for _, line := range strings.Split(banner, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if len(line) > 510 || !ircResponseRE.MatchString(line) || !validIRCLine(line) {
			continue
		}
		if evidence == "" {
			evidence = line
		}
		if match := ircProductRE.FindStringSubmatch(line); match != nil {
			return "UnrealIRCd " + match[1], line
		}
	}
	if evidence != "" {
		return "IRC service", evidence
	}
	return "", ""
}

func ircCommand(line string) string {
	if strings.ContainsAny(line, "\x00\r\n") {
		return ""
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	if strings.HasPrefix(fields[0], ":") {
		if len(fields) < 2 || len(fields[0]) == 1 {
			return ""
		}
		return strings.ToUpper(fields[1])
	}
	return strings.ToUpper(fields[0])
}

func validIRCLine(line string) bool {
	command := ircCommand(line)
	if len(command) == 3 && command[0] >= '0' && command[0] <= '9' && command[1] >= '0' && command[1] <= '9' && command[2] >= '0' && command[2] <= '9' {
		return strings.HasPrefix(line, ":")
	}
	switch command {
	case "NOTICE", "PING", "ERROR", "CAP":
		return true
	}
	return false
}

func ircRegistrationEnd(line string) bool {
	command := ircCommand(line)
	return command == "004" || command == "005" || command == "ERROR" || len(command) == 3 && (command[0] == '4' || command[0] == '5')
}

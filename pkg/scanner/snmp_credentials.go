package scanner

import (
	"errors"
	"strings"
	"unicode"

	"github.com/gosnmp/gosnmp"
)

// SNMPCredentials is immutable and deliberately excludes secrets from formatting and JSON.
type SNMPCredentials struct {
	username, authentication, privacy string
	authProtocol                      gosnmp.SnmpV3AuthProtocol
	privProtocol                      gosnmp.SnmpV3PrivProtocol
}

func (c SNMPCredentials) String() string   { return "SNMPCredentials[redacted]" }
func (c SNMPCredentials) GoString() string { return c.String() }

// NewSNMPCredentials accepts only the explicitly supported strong algorithm subset.
func NewSNMPCredentials(username, authProtocol, authPassword, privacyProtocol, privacyPassword string) (*SNMPCredentials, error) {
	bad := errors.New("invalid SNMP credentials or unsupported algorithm")
	if len(username) == 0 || len(username) > 32 || strings.ContainsFunc(username, unicode.IsControl) || len(authPassword) < 8 || len(authPassword) > 256 {
		return nil, bad
	}
	c := &SNMPCredentials{username: username, authentication: authPassword, privacy: privacyPassword}
	switch authProtocol {
	case "sha256":
		c.authProtocol = gosnmp.SHA256
	case "sha512":
		c.authProtocol = gosnmp.SHA512
	default:
		return nil, bad
	}
	switch privacyProtocol {
	case "none":
		if privacyPassword != "" {
			return nil, bad
		}
		c.privProtocol = gosnmp.NoPriv
	case "aes128":
		if len(privacyPassword) < 8 || len(privacyPassword) > 256 {
			return nil, bad
		}
		c.privProtocol = gosnmp.AES
	default:
		return nil, bad
	}
	return c, nil
}

func (c *SNMPCredentials) parameters() *gosnmp.UsmSecurityParameters {
	return &gosnmp.UsmSecurityParameters{UserName: c.username,
		AuthenticationProtocol: c.authProtocol, AuthenticationPassphrase: c.authentication,
		PrivacyProtocol: c.privProtocol, PrivacyPassphrase: c.privacy}
}

func (c *SNMPCredentials) flags() gosnmp.SnmpV3MsgFlags {
	if c.privProtocol == gosnmp.AES {
		return gosnmp.AuthPriv
	}
	return gosnmp.AuthNoPriv
}

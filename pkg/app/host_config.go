package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"
)

const maxHostConfigBytes = 64 * 1024

type hostOverride struct {
	timeoutMS       *int
	maxTimeoutMS    *int
	retries         *int
	adaptiveTimeout *bool
}

func loadHostConfig(path string) (map[string]hostOverride, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open --host-config: %w", err)
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxHostConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read --host-config: %w", err)
	}
	return parseHostConfig(data)
}

func parseHostConfig(data []byte) (map[string]hostOverride, error) {
	if len(data) > maxHostConfigBytes {
		return nil, errors.New("--host-config exceeds 64 KiB")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	start, err := dec.Token()
	if err != nil || start != json.Delim('{') {
		return nil, errors.New("--host-config must be a JSON object keyed by IP address")
	}
	result := make(map[string]hostOverride)
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, ok := key.(string)
		if !ok {
			return nil, errors.New("invalid host-config key")
		}
		addr, err := netip.ParseAddr(name)
		if err != nil || addr.Zone() != "" {
			return nil, errors.New("host-config keys must be unzoned literal IP addresses")
		}
		canonical := addr.Unmap().String()
		if _, exists := result[canonical]; exists {
			return nil, fmt.Errorf("duplicate host-config IP: %s", canonical)
		}
		override, err := decodeHostOverride(dec)
		if err != nil {
			return nil, fmt.Errorf("invalid host-config for %s: %w", canonical, err)
		}
		result[canonical] = override
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("host-config has trailing JSON or data")
	}
	return result, nil
}

func decodeHostOverride(dec *json.Decoder) (hostOverride, error) {
	var o hostOverride
	start, err := dec.Token()
	if err != nil || start != json.Delim('{') {
		return o, errors.New("host settings must be an object")
	}
	seen := make(map[string]bool)
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return o, err
		}
		name, ok := key.(string)
		if !ok || seen[name] {
			return o, errors.New("invalid or duplicate host setting")
		}
		seen[name] = true
		if name == "adaptive_timeout" {
			var value *bool
			if err := dec.Decode(&value); err != nil || value == nil {
				return o, errors.New("adaptive_timeout must be a boolean")
			}
			o.adaptiveTimeout = value
			continue
		}
		var value *int
		if err := dec.Decode(&value); err != nil || value == nil || *value < 0 {
			return o, errors.New("host settings require non-negative integers")
		}
		switch name {
		case "timeout_ms", "max_timeout_ms":
			if int64(*value) > int64((1<<63-1)/time.Millisecond) {
				return o, errors.New("host timeout exceeds supported duration")
			}
			if name == "timeout_ms" {
				o.timeoutMS = value
			} else {
				o.maxTimeoutMS = value
			}
		case "retries":
			if *value > 10 {
				return o, errors.New("host retries must be between 0 and 10")
			}
			o.retries = value
		default:
			return o, fmt.Errorf("unknown host setting %q", name)
		}
	}
	_, err = dec.Token()
	return o, err
}

func applyHostOverride(req ScanRequest, o hostOverride) ScanRequest {
	if o.timeoutMS != nil {
		req.TimeoutMS = *o.timeoutMS
	}
	if o.maxTimeoutMS != nil {
		req.MaxTimeoutMS = *o.maxTimeoutMS
	}
	if o.retries != nil {
		req.Retries = *o.retries
	}
	if o.adaptiveTimeout != nil {
		req.AdaptiveTimeout = *o.adaptiveTimeout
	}
	return req
}

func validateHostConfigScope(config map[string]hostOverride, targets []string, req ScanRequest) error {
	if len(config) == 0 {
		return nil
	}
	wanted := make(map[string]bool, len(targets))
	for _, target := range targets {
		if addr, err := netip.ParseAddr(target); err == nil {
			wanted[addr.Unmap().String()] = true
		}
	}
	for host, o := range config {
		if !wanted[host] {
			return fmt.Errorf("host-config IP %s is outside the expanded target scope", host)
		}
		effective := applyHostOverride(req, o)
		if effective.TimeoutMS > 0 && effective.MaxTimeoutMS > 0 && effective.MaxTimeoutMS < effective.TimeoutMS {
			return fmt.Errorf("host-config max_timeout_ms is below timeout_ms for %s", host)
		}
	}
	return nil
}

package config

import (
	"fmt"
	"regexp"
)

var tagRegex = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// Validate checks the entire config for errors.
func (c *Config) Validate() error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	tags := make(map[string]bool)
	domains := make(map[string]bool)

	for _, t := range c.Tunnels {
		if err := validateTag(t.Tag); err != nil {
			return fmt.Errorf("tunnel %q: %w", t.Tag, err)
		}
		if tags[t.Tag] {
			return fmt.Errorf("duplicate tunnel tag: %s", t.Tag)
		}
		tags[t.Tag] = true

		if t.Domain == "" && t.Transport != TransportSSH && t.Transport != TransportSOCKS && t.Transport != TransportStunTLS {
			return fmt.Errorf("tunnel %q: domain is required", t.Tag)
		}
		if t.Domain != "" {
			if domains[t.Domain] {
				return fmt.Errorf("duplicate domain: %s", t.Domain)
			}
			domains[t.Domain] = true
		}

		if err := validateTransport(t.Transport); err != nil {
			return fmt.Errorf("tunnel %q: %w", t.Tag, err)
		}

		if err := validateBackend(t.Backend); err != nil {
			return fmt.Errorf("tunnel %q: %w", t.Tag, err)
		}

		if err := validateTransportBackend(t.Transport, t.Backend); err != nil {
			return fmt.Errorf("tunnel %q: %w", t.Tag, err)
		}
	}

	if c.Route.Mode != "" && c.Route.Mode != "single" && c.Route.Mode != "multi" {
		return fmt.Errorf("invalid route mode: %s", c.Route.Mode)
	}

	return nil
}

// ValidateNewTunnel checks a tunnel against the existing config.
func (c *Config) ValidateNewTunnel(t *TunnelConfig) error {
	if err := validateTag(t.Tag); err != nil {
		return err
	}
	if c.GetTunnel(t.Tag) != nil {
		return fmt.Errorf("tunnel tag %q already exists", t.Tag)
	}
	if t.Domain == "" && t.Transport != TransportSSH && t.Transport != TransportSOCKS && t.Transport != TransportStunTLS {
		return fmt.Errorf("domain is required")
	}
	c.mu.RLock()
	for _, existing := range c.Tunnels {
		if t.Domain != "" && existing.Domain == t.Domain && existing.Backend == t.Backend {
			c.mu.RUnlock()
			return fmt.Errorf("domain %q with backend %q already in use by tunnel %q", t.Domain, t.Backend, existing.Tag)
		}
	}
	c.mu.RUnlock()
	return validateTransportBackend(t.Transport, t.Backend)
}

// ValidateTagName checks if a tag name is valid.
func ValidateTagName(tag string) error {
	return validateTag(tag)
}

func validateTag(tag string) error {
	if tag == "" {
		return fmt.Errorf("tag is required")
	}
	if !tagRegex.MatchString(tag) {
		return fmt.Errorf("tag must start with a letter and contain only lowercase letters, numbers, and hyphens")
	}
	return nil
}

func validateTransport(transport string) error {
	switch transport {
	case TransportDNSTT, TransportSlipstream, TransportVayDNS, TransportNaive, TransportStunTLS, TransportSSH, TransportSOCKS:
		return nil
	}
	return fmt.Errorf("unknown transport: %s", transport)
}

func validateBackend(backend string) error {
	switch backend {
	case BackendSOCKS, BackendSSH:
		return nil
	}
	return fmt.Errorf("unknown backend: %s", backend)
}

func validateTransportBackend(transport, backend string) error {
	// All combinations are valid
	return nil
}

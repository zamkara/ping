package tlsinfo

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"ping/pkg/models"
)

// Extract parses the TLS connection state from an http.Request
func Extract(r *http.Request) *models.TLSData {
	if r.TLS == nil {
		return nil
	}

	state := r.TLS
	info := &models.TLSData{
		Version:            tlsVersionName(state.Version),
		CipherSuite:        tlsCipherSuiteName(state.CipherSuite),
		SNI:                state.ServerName,
		ALPN:               state.NegotiatedProtocol,
	}

	if len(state.PeerCertificates) > 0 {
		certs := make([]string, 0, len(state.PeerCertificates))
		for _, cert := range state.PeerCertificates {
			certs = append(certs, fmt.Sprintf("Subject: %s (Issuer: %s)", cert.Subject.CommonName, cert.Issuer.CommonName))
		}
		info.PeerCertificates = certs
	}

	return info
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

func tlsCipherSuiteName(id uint16) string {
	name := tls.CipherSuiteName(id)
	if name != "" {
		return name
	}
	return fmt.Sprintf("0x%04x", id)
}

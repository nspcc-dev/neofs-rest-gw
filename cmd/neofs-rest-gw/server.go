package main

import (
	"crypto/x509"
	"os"
	"time"
)

type (
	EndpointInfo struct {
		Address         string
		ExternalAddress string
		TLS             ServerTLSInfo
		KeepAlive       time.Duration
		ReadTimeout     time.Duration
		WriteTimeout    time.Duration
	}

	ServerTLSInfo struct {
		Enabled    bool
		CertFile   string
		KeyFile    string
		CertCAFile string
	}
)

// Helper function to load CA certificate.
func loadCA(path string) (*x509.CertPool, error) {
	caCertPool := x509.NewCertPool()
	caCert, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	caCertPool.AppendCertsFromPEM(caCert)
	return caCertPool, nil
}

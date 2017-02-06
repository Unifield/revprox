package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// This is an implementation of GetCertificate that works
// by talking to certomat, which gets the certificate from
// LetsEncrypt by proxy for us.

type remoteAutocertManager struct {
	fqdn string // only seek certificates for this domain
	mu   sync.Mutex
	cert *tls.Certificate
	err  error
}

var errHostname = errors.New("hostname not allowed")

func (r *remoteAutocertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	fqdn := hello.ServerName
	fqdn = strings.Trim(fqdn, ".")
	if !strings.EqualFold(fqdn, r.fqdn) {
		return nil, errHostname
	}

	// r.mu allows only one goroutine to try getting a cert
	// at once.
	r.mu.Lock()
	defer r.mu.Unlock()

	// If we have not yet already gotten an error or a certificate,
	// then try to get a certificate.
	if r.err == nil && r.cert == nil {
		r.cert, r.err = r.getCertFromCertomat(fqdn)
	}

	// If we've already gotten a cert, either it's the one they
	// want (give it to them), or we refuse (errHostname).
	if r.cert != nil {
		if r.cert.Leaf.Subject.CommonName == fqdn {
			return r.cert, nil
		} else {
			return nil, errHostname
		}
	}

	// No cert available: here's why
	return nil, r.err
}

// We are called with m.mu locked.
func (r *remoteAutocertManager) getCertFromCertomat(fqdn string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	csr, err := certRequest(key, fqdn)
	if err != nil {
		return nil, err
	}

	url := "https://certomat.prod.unifield.org/get-cert-from-csr"

	resp, err := http.Post(url, "text/plain", bytes.NewReader(csr))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("certomat status code: %v", resp.StatusCode)
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading body: %v", err)
	}
	log.Print("cert:", string(data))

	priv, pub := pem.Decode(data)
	if priv != nil {
		return nil, errors.New("unexpected private key")
	}

	// public
	var pubDER [][]byte
	for len(pub) > 0 {
		var b *pem.Block
		b, pub = pem.Decode(pub)
		if b == nil {
			break
		}
		pubDER = append(pubDER, b.Bytes)
	}
	if len(pub) > 0 {
		return nil, errors.New("invalid public key")
	}

	// verify and create TLS cert
	leaf, err := validCert(fqdn, pubDER, key)
	if err != nil {
		return nil, err
	}
	tlscert := &tls.Certificate{
		Certificate: pubDER,
		PrivateKey:  key,
		Leaf:        leaf,
	}
	return tlscert, nil
}

// validCert parses a cert chain provided as der argument and verifies the leaf, der[0],
// corresponds to the private key, as well as the domain match and expiration dates.
// It doesn't do any revocation checking.
//
// The returned value is the verified leaf cert.
func validCert(domain string, der [][]byte, key crypto.Signer) (leaf *x509.Certificate, err error) {
	// parse public part(s)
	var n int
	for _, b := range der {
		n += len(b)
	}
	pub := make([]byte, n)
	n = 0
	for _, b := range der {
		n += copy(pub[n:], b)
	}
	x509Cert, err := x509.ParseCertificates(pub)
	if len(x509Cert) == 0 {
		return nil, errors.New("acme/autocert: no public key found")
	}
	// verify the leaf is not expired and matches the domain name
	leaf = x509Cert[0]
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return nil, errors.New("acme/autocert: certificate is not valid yet")
	}
	if now.After(leaf.NotAfter) {
		return nil, errors.New("acme/autocert: expired certificate")
	}
	if err := leaf.VerifyHostname(domain); err != nil {
		return nil, err
	}

	// In csr only case, do not check the public/private key
	if key == nil {
		return leaf, nil
	}
	// ensure the leaf corresponds to the private key
	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		prv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("acme/autocert: private key type does not match public key type")
		}
		if pub.N.Cmp(prv.N) != 0 {
			return nil, errors.New("acme/autocert: private key does not match public key")
		}
	case *ecdsa.PublicKey:
		prv, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("acme/autocert: private key type does not match public key type")
		}
		if pub.X.Cmp(prv.X) != 0 || pub.Y.Cmp(prv.Y) != 0 {
			return nil, errors.New("acme/autocert: private key does not match public key")
		}
	default:
		return nil, errors.New("acme/autocert: unknown public key algorithm")
	}
	return leaf, nil
}

// certRequest creates a certificate request for the given common name cn
// and optional SANs.
func certRequest(key crypto.Signer, cn string, san ...string) ([]byte, error) {
	req := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: san,
	}
	return x509.CreateCertificateRequest(rand.Reader, req, key)
}

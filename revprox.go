package main

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// A locationFixer is a transport that wraps a http.Transport
// and which rewrites the Location headers on the replies.
type locationFixer struct {
	t *http.Transport
}

func (lf *locationFixer) RoundTrip(req *http.Request) (*http.Response, error) {
	if lf.t == nil {
		// Same defaults as http.DefaultTransport, except
		// IdleConnTimeout is lower than CherryPy's in order to
		// avoid "Unsolicited response received" errors.
		lf.t = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       1 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}

	resp, err := lf.t.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	// Find the public name for this server from the Certificate
	pub := ""
	if req.TLS != nil {
		pub = req.TLS.ServerName
	}

	loc := resp.Header.Get("Location")
	if pub != "" && loc != "" {
		l, err := url.Parse(loc)

		if err != nil {
			log.Print(err)
		} else {
			l.Host = pub
			resp.Header.Set("Location", l.String())
		}
	}

	return resp, err
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// This is httputil.NewSingleHostReverseProxy, but modified to
// rewrite Referer and Location headers.
func rp() *httputil.ReverseProxy {
	target, err := url.Parse("http://127.0.0.1:18061")
	if err != nil {
		log.Fatal(err)
	}
	targetQuery := target.RawQuery

	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			// explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}

		// Rewrite the referer to get through CSRF check in
		// OpenERP Web's _tools.py
		ref := req.Header.Get("Referer")
		if ref != "" {
			u, err := url.Parse(ref)
			if err == nil {
				u.Host = target.Host
				req.Header.Set("Referer", u.String())
			}
		}
		req.Header.Set("X-Forwarded-Host", target.Host)
		req.Header.Set("X-Forwarded-Proto", "https")
	}
	return &httputil.ReverseProxy{
		Director: director,
		// Rewrite Location headers in the transport
		Transport: &locationFixer{},
	}
}

func getCertViaLE(fqdn string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	// Load the LetsEncrypt root
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(lePem))
	if !ok {
		log.Fatal("failed to load certs")
	}
	t := &tls.Config{
		RootCAs: roots,
	}
	hc := &http.Client{
		// Use the same defaults as http.DefaultTransport
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			// But add our own TLS config to trust
			// the LetsEncrypt certificates.
			TLSClientConfig: t,
		},
	}
	ac := &acme.Client{
		HTTPClient: hc,
	}
	m := &autocert.Manager{
		Client:     ac,
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(fqdn),
		Cache:      autocert.DirCache(filepath.Join(os.TempDir(), "autocert")),
	}
	return m.GetCertificate
}

func reverseProxy(key, cer, fqdn string) {
	// On Windows, another process (damn you, Skype) can open
	// port 443 in a way so that revprox still starts, but does not
	// work. Prevent that from happening.
	_, err := net.Dial("tcp", "127.0.0.1:443")
	if err == nil {
		log.Fatal("A server is already running on port 443. Is it Skype?")
	}

	log.Print("Starting reverse proxy for ", fqdn)

	// Config proposed by:
	// https://blog.gopheracademy.com/advent-2016/exposing-go-on-the-internet/
	tc := &tls.Config{
		// Causes servers to use Go's default ciphersuite preferences,
		// which are tuned to avoid attacks. Does nothing on clients.
		PreferServerCipherSuites: true,
		// Only use curves which have assembly implementations
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,

			// Best disabled, as they don't provide Forward Secrecy,
			// but might be necessary for some clients
			// tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			// tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
	if key == "" {
		tc.GetCertificate = getCertViaLE(fqdn)
	}

	// Timeouts proposed by
	// https://blog.gopheracademy.com/advent-2016/exposing-go-on-the-internet/
	s := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		Addr:         ":https",
		TLSConfig:    tc,
		Handler:      rp(),
	}

	err = s.ListenAndServeTLS(cer, key)
	if err != nil {
		log.Fatal("reverse proxy could not listen: ", err)
	}
	return
}

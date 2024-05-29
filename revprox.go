package main

import (
    "crypto/tls"
    "log"
    "net"
    "net/http"
    "net/http/httputil"
    "net/url"
    "os"
    "path/filepath"
    "runtime"
    "strings"
    "time"
    "fmt"
    "golang.org/x/crypto/acme/autocert"
)

// A locationFixer is a transport that wraps a http.Transport
// and which rewrites the Location headers on the replies.
type locationFixer struct {
    t *http.Transport
    p string
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
            if lf.p == "443" {
                l.Host = fmt.Sprintf("%v", pub)
            } else {
                l.Host = fmt.Sprintf("%v:%v", pub, lf.p)

            }
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
func rp(listenPort string) *httputil.ReverseProxy {
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
        Transport: &locationFixer{p: listenPort},
    }
}

func getHttpClient() *http.Client {

    return &http.Client{
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
        },
    }
}

func getCertViaLE(fqdn string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
    cache := cacheDir()
    m := &autocert.Manager{
        Prompt:     autocert.AcceptTOS,
        HostPolicy: autocert.HostWhitelist(fqdn),
        Cache:      autocert.DirCache(cache),
    }
    log.Print("Cache dir ", cache)
    go http.ListenAndServe(":80", m.HTTPHandler(nil))
    return m.GetCertificate
}

func cacheDir() string {
    if runtime.GOOS == "windows" {
        home := os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
        return filepath.Join(home, "autocert")
    }
    return filepath.Join(os.Getenv("HOME"), ".autocert")
}

func reverseProxy(keyFile, cerFile, fqdn string, listenPort string) {
    // On Windows, another process (damn you, Skype) can open
    // port 443 in a way so that revprox still starts, but does not
    // work. Prevent that from happening.
    _, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%s", listenPort))
    if err == nil {
        log.Fatal("A server is already running on port", listenPort, "Is it Skype?")
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
    if keyFile == "" {
        tc.GetCertificate = getCertViaLE(fqdn)
    }

    // Set up a mux to catch /ok requests, and pass the rest to the
    // reverse proxy.
    mux := http.NewServeMux()
    mux.Handle("/ok", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("ok"))
    }))
    mux.Handle("/", rp(listenPort))

    // Timeouts proposed by
    // https://blog.gopheracademy.com/advent-2016/exposing-go-on-the-internet/
    s := &http.Server{
        ReadTimeout: 5 * time.Second,
        // Removing this timeout because of US-3357: With Go 1.9
        // this timeout now fires even when there has not been any
        // write yet, so it ends up causing a timeout when what
        // we want to do is continue waiting on Unifield.
        //WriteTimeout: 10 * time.Second,
        IdleTimeout: 120 * time.Second,
        Addr:        fmt.Sprintf(":%v", listenPort),
        TLSConfig:   tc,
        Handler:     mux,
    }

    err = s.ListenAndServeTLS(cerFile, keyFile)
    if err != nil {
        log.Fatal("reverse proxy could not listen: ", err)
    }
    return
}

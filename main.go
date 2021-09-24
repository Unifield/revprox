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
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type portList []uint16

func (p *portList) String() string {
	pstr := make([]string, len(*p))
	for i, port := range *p {
		pstr[i] = fmt.Sprintf("%d", port)
	}
	return strings.Join(pstr, ", ")
}

func (p *portList) Set(s string) error {
	port, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("could not parse int: %v", err)
	}
	if port < 0 || port > 65536 {
		return fmt.Errorf("port %d out of range", port)
	}
	*p = append(*p, uint16(port))
	return nil
}

var domain = flag.String("domain", "prod.unifield.org", "The domain name for this server (not used if dot appears in server name).")
var server = flag.String("server", "", "The server name.")
var version = flag.Bool("version", false, "Show the version and exit.")
var redirPorts = &portList{}
var listenPort = flag.String("listen-port", "443", "Https port")

var gitRevision = "(dev)"

func isCertomat(fqdn string) bool {
	domain := getDomain(fqdn)
	return domain == "dev.unifield.org" ||
		domain == "prod.unifield.org" ||
		domain == "dev.unifield.biz" ||
		domain == "prod.unifield.biz"
}

func isStaging(fqdn string) bool {
	domain := getDomain(fqdn)
	return domain == "dev.unifield.org" ||
		domain == "dev.unifield.biz"
}

func main() {
	flag.Var(redirPorts, "redir", "ports to run a redirector on")
	flag.Parse()
	if *version {
		fmt.Println(gitRevision)
		return
	}
	if *server == "" {
		fmt.Println("Server name is required.")
		os.Exit(1)
	}
	fqdn := *server
	if strings.Index(fqdn, ".") == -1 {
		fqdn = fmt.Sprintf("%v.%v", *server, *domain)
	}

	if len(*redirPorts) == 0 {
		redirPorts.Set("8061")
	}

	log.Println("Finding a certificate for", fqdn)
	keyFile := fmt.Sprintf("%v.key", fqdn)
	cerFile := fmt.Sprintf("%v.cer", fqdn)

	lePem = leProdPem
	if isStaging(fqdn) {
		lePem = leStagingPem
	}

	if ok, cer := checkCerKey(fqdn, cerFile, keyFile); ok {
		log.Print("Using certificate in ", cerFile)
		if isLE(cer) {
			go renew(fqdn, cer)
		}
	} else if isCertomat(fqdn) {
		log.Print("Getting a certificate from certomat")
		err := getCertFromCertomat(fqdn)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		log.Print("Getting certificate directly from LetsEncrypt.")
		keyFile = ""
		cerFile = ""
	}

	go reverseProxy(keyFile, cerFile, fqdn, *listenPort)

	for _, port := range *redirPorts {
		go redir(port, fqdn, *listenPort)
	}

	// Fetch from ourselves once to confirm we are up, so that we
	// can tell OpenERP Web it should use us.
	ok := make(chan bool)
	go checkSelf(fqdn, *listenPort, ok)
	select {
	case <-time.After(10 * time.Second):
		log.Println("Timeout during start up. Exiting.")
		return
	case res := <-ok:
		if res {
			log.Println("Startup OK.")
		} else {
			log.Println("Startup not OK.")
			return
		}
	}

	// Make this thread go to sleep so that the other threads
	// can do their jobs. Without this, main would return
	// and the runtime would kill the process and exit.
	<-make(chan bool)
}

func isLE(cer *x509.Certificate) bool {
	// Found these by running the certificates here:
	// https://letsencrypt.org/certificates/
	// through "openssl x509 -text".
	leX3 := [...]byte{
		0xA8, 0x4A, 0x6A, 0x63, 0x04, 0x7D, 0xDD,
		0xBA, 0xE6, 0xD1, 0x39, 0xB7, 0xA6, 0x45,
		0x65, 0xEF, 0xF3, 0xA8, 0xEC, 0xA1,
	}
	leX4 := [...]byte{
		0xC5, 0xB1, 0xAB, 0x4E, 0x4C, 0xB1, 0xCD,
		0x64, 0x30, 0x93, 0x7E, 0xC1, 0x84, 0x99,
		0x05, 0xAB, 0xE6, 0x03, 0xE2, 0x25,
	}
    leR3 := [...]byte{
        0x14, 0x2E, 0xB3, 0x17, 0xB7, 0x58, 0x56,
        0xCB, 0xAE, 0x50, 0x09, 0x40, 0xE6, 0x1F,
        0xAF, 0x9D, 0x8B, 0x14, 0xC2, 0xC6,
    }
	return bytes.Equal(leR3[:], cer.AuthorityKeyId) ||
		bytes.Equal(leX3[:], cer.AuthorityKeyId) ||
		bytes.Equal(leX4[:], cer.AuthorityKeyId)
}

func exists(fn string) bool {
	_, err := os.Stat(fn)
	return err == nil
}

func checkCerKey(fqdn, cerFile, keyFile string) (bool, *x509.Certificate) {
	if !exists(keyFile) {
		// Do not log anything here, because this is the normal,
		// expected path when they are not providing the key/cer
		// to us.
		return false, nil
	}

	if !exists(cerFile) {
		log.Printf("Key file %v exists but certificate file %v does not exist.", keyFile, cerFile)
		return false, nil
	}

	cer, err := tls.LoadX509KeyPair(cerFile, keyFile)
	if err != nil {
		log.Printf("Cannot load certificate: %v", err)
		return false, nil
	}
	x509Cert, err := x509.ParseCertificate(cer.Certificate[0])
	if err != nil {
		log.Printf("Cannot parse certificate: %v", err)
		return false, nil
	}

	opt := x509.VerifyOptions{
		DNSName: fqdn,
	}
	_, err = x509Cert.Verify(opt)
	if err == nil {
		log.Print("Validated via the system roots.")
		return true, x509Cert
	}

	// If we failed with the system roots, try with the LetsEncrypt
	// ones, since some Windows do not trust LetsEncrypt yet.
	// See https://github.com/golang/go/issues/18609 for why
	// we cannot just add lePem into the result of SystemCertPool.
	opt.Roots = x509.NewCertPool()
	ok := opt.Roots.AppendCertsFromPEM([]byte(lePem))
	if !ok {
		log.Print("Cannot parse LE certificate.")
		return false, nil
	}

	_, err = x509Cert.Verify(opt)
	if err != nil {
		log.Printf("Found certificate in %v but: %v", cerFile, err)
		return false, nil
	}
	log.Print("Validated via the LetsEncrypt root.")
	return true, x509Cert
}

func checkSelf(fqdn string, listenPort string, ok chan bool) {
	// Give the reverse proxy time to start up.
	time.Sleep(2 * time.Second)

	tr := &http.Transport{
		// Use a custom dialer that connects to localhost, no matter
		// what the hostname is, so that we check ourselves,
		// not the public address associated with the FQDN.
		Dial: func(network, addr string) (net.Conn, error) {
			return net.Dial("tcp", fmt.Sprintf("127.0.0.1:%s", listenPort))
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get(fmt.Sprintf("https://%v/ok", fqdn))
	if err != nil {
		log.Println("check self:", err)
		return
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("check self:", err)
		return
	}
	ok <- string(body) == "ok"
	return
}

func getKey(fqdn string) (*ecdsa.PrivateKey, error) {
	keyFile := fmt.Sprintf("%v.key", fqdn)

	if keydat, err := ioutil.ReadFile(keyFile); err == nil {
		// Load the existing key
		priv, _ := pem.Decode(keydat)
		if priv != nil && strings.Contains(priv.Type, "PRIVATE") {
			key, err := x509.ParseECPrivateKey(priv.Bytes)
			if err == nil {
				return key, nil
			}
		}
	}

	// Failed to load it, so generate it.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// write the key
	markey, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("could not marshal key: %v", err)
	}

	buf := &bytes.Buffer{}
	pb := &pem.Block{Type: "EC PRIVATE KEY", Bytes: markey}
	pem.Encode(buf, pb)
	err = ioutil.WriteFile(keyFile, buf.Bytes(), 0600)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func getDomain(fqdn string) string {
	x := strings.Split(fqdn, ".")
	return strings.Join(x[1:], ".")
}

func getCertFromCertomat(fqdn string) error {
	key, err := getKey(fqdn)
	if err != nil {
		return err
	}

	// US-2913: certbot gets mad when there is mixed case in the
	// CSR. So we lowercase the fqdn before passing it to certRequest
	// even though we hope that certbot will get fixed later.
	csr, err := certRequest(key, strings.ToLower(fqdn))
	if err != nil {
		return err
	}

	client := getHttpClient()
	url := fmt.Sprintf("https://certomat.%v/get-cert-from-csr", getDomain(fqdn))
	resp, err := client.Post(url, "text/plain", bytes.NewReader(csr))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("certomat status code: %v", resp.StatusCode)
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading body: %v", err)
	}
	// Save a copy to write into the file.
	data2 := data

	var certDer [][]byte
	for len(data) > 0 {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		certDer = append(certDer, b.Bytes)
	}
	if len(certDer) == 0 {
		return errors.New("pem decode: did not find certificate")
	}

	// verify and create TLS cert
	leaf, err := validCert(fqdn, certDer, key)
	if err != nil {
		return err
	}

	// Setup renew timer
	go renew(fqdn, leaf)

	// Write the certificate
	err = ioutil.WriteFile(fmt.Sprintf("%v.cer", fqdn), data2, 0600)
	return err
}

const week = 3 * time.Hour * 24 * 7

func renew(fqdn string, leaf *x509.Certificate) {
	log.Print("Expires: ", leaf.NotAfter)
	life := leaf.NotAfter.Sub(time.Now())
	if life > week {
		// Sleep until 3 weeks before expiration.
		sleep := life - week
		time.Sleep(sleep)
	}

	// Try twice a day until we are expired, and then give up.
	life = leaf.NotAfter.Sub(time.Now())
	for life > 0 {
		err := getCertFromCertomat(fqdn)
		if err == nil {
			log.Print("Renewed certificate, exiting to reload it.")
			os.Exit(1)
		}
		log.Print("Renewal failed: ", err)
		// try again in 12 hours
		time.Sleep(12 * time.Hour)
		life = leaf.NotAfter.Sub(time.Now())
	}
	log.Print("Certificate expired, exiting.")
	os.Exit(1)
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

package main

import (
	"crypto/tls"
	"crypto/x509"
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

var gitRevision = "(dev)"

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

	if exists(cerFile) && exists(keyFile) && checkCerKey(fqdn, cerFile, keyFile) {
		log.Print("Using certificate in ", cerFile)
	} else {
		log.Print("Using LetsEncrypt to get the certificate")
		keyFile = ""
		cerFile = ""
	}

	go reverseProxy(keyFile, cerFile, fqdn)
	for _, port := range *redirPorts {
		go redir(port, fqdn)
	}

	// Fetch from ourselves once to confirm we are up, so that we
	// can tell OpenERP Web to use us.
	ok := make(chan bool)
	go checkSelf(fqdn, ok)
	select {
	case <-time.After(5 * time.Second):
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

	<-make(chan bool)
}

func exists(fn string) bool {
	_, err := os.Stat(fn)
	return err == nil
}

func checkCerKey(fqdn, cerFile, keyFile string) bool {
	cer, err := tls.LoadX509KeyPair(cerFile, keyFile)
	if err != nil {
		log.Printf("Cannot load certificate: %v", err)
		return false
	}
	x509Cert, err := x509.ParseCertificate(cer.Certificate[0])
	if err != nil {
		log.Printf("Cannot parse certificate: %v", err)
		return false
	}

	// The defaults do the right thing: check with respect
	// to the system roots, and for the current time.
	opt := x509.VerifyOptions{
		DNSName: fqdn,
	}

	_, err = x509Cert.Verify(opt)
	if err != nil {
		log.Print("Found certificate in %v but: %v", cerFile, err)
		return false
	}
	return true
}

func checkSelf(fqdn string, ok chan bool) {
	time.Sleep(1 * time.Second)
	tr := &http.Transport{
		// Use a hacky dialer that connects to localhost, no matter
		// what the hostname is.
		Dial: func(network, addr string) (net.Conn, error) {
			return net.Dial("tcp", "127.0.0.1:443")
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

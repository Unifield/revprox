package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
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

	// Try to find a key/cer. First look in the local dir for manual
	// config.
	if exists(keyFile) && exists(cerFile) && checkKeyCer(keyFile, cerFile) {
	} else {
		// No local key, so start in LetsEncrypt mode
	}

	go reverseProxy(keyFile, cerFile, fqdn)
	for _, port := range *redirPorts {
		go redir(port, fqdn)
	}
	<-make(chan bool)
}

func exists(fn string) bool {
	_, err := os.Stat(fn)
	return err != nil
}

func checkKeyCer(key, cer string) bool {
	// load key, load cer, make sure they match
	// make sure cer's CN matchs fdqn
	// make sure the cert is not expired
	return true
}

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

var domain = flag.String("domain", "prod.unifield.org", "The domain name for this server (not used if dot appears in server name).")
var server = flag.String("server", "", "The server name.")
var version = flag.Bool("version", false, "Show the version and exit.")

var gitRevision = "(dev)"

func main() {
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

	log.Println("Finding a certificate for", fqdn)

	keyFile := fmt.Sprintf("%v.key", fqdn)
	cerFile := fmt.Sprintf("%v.cer", fqdn)

	// Try to find a key/cer. First look in the local dir for manual
	// config.
	if exists(keyFile) && exists(cerFile) && checkKeyCer(keyFile, cerFile) {
	} else {
		// No local key, so start in LetsEncrypt mode
	}

	reverseProxy(keyFile, cerFile, fqdn)
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

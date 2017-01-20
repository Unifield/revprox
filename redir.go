package main

import (
	"fmt"
	"log"
	"net/http"
)

func redir(port uint16, fqdn string) {
	hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Scheme = "https"
		r.URL.Host = fqdn
		http.Redirect(w, r, r.URL.String(), http.StatusFound)
	})

	log.Println("Running HTTP redirect server on port", port)
	err := http.ListenAndServe(fmt.Sprintf(":%d", port), hf)
	if err != nil {
		log.Fatal("redirector could not listen: ", err)
	}
}

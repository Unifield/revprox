package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

func redir(port uint16, fqdn string, httpsPort string) {
	hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		r.URL.Scheme = "https"
		r.URL.Host = fmt.Sprintf("%v:%v", fqdn, httpsPort)
		http.Redirect(w, r, r.URL.String(), http.StatusFound)
	})

	log.Println("Running HTTP redirect server on port", port)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler:      hf,
	}
	err := srv.ListenAndServe()
	if err != nil {
		log.Fatal("redirector could not listen: ", err)
	}
}

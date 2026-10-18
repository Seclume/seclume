// Go's crypto/tls as a server for the interop matrix: answers every
// connection with a short HTTP response.
//
//	go run . -port 9301 -cert c.pem -key k.pem -version 1.3
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
)

func main() {
	port := flag.Int("port", 9301, "port")
	cert := flag.String("cert", "", "certificate chain, PEM")
	key := flag.String("key", "", "key, PEM")
	version := flag.String("version", "1.3", "1.3 or 1.2")
	flag.Parse()

	config := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	if *version == "1.2" {
		config = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}
	}
	server := &http.Server{
		Addr:      fmt.Sprintf("127.0.0.1:%d", *port),
		TLSConfig: config,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "go %s\n", tls.VersionName(r.TLS.Version))
		}),
	}
	log.Fatal(server.ListenAndServeTLS(*cert, *key))
}

// Command laboob is the validation lab's out-of-band collaborator
// (ADR-0008 §6). It never runs in production.
//
//	laboob [--listen :80]
//
// Any request to /t/<token> (any method, any Host) is recorded as a hit for
// token; GET /interactions/<token> answers {"token": ..., "hits": N}. Hits
// are kept in memory and capped; tokens are opaque.
package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/hksolutions/guardhub/apps/scanner/internal/active/oobserver"
)

func main() {
	listen := flag.String("listen", ":80", "listen address")
	flag.Parse()
	srv := &http.Server{Addr: *listen, Handler: oobserver.New(10000), ReadHeaderTimeout: 10 * time.Second}
	log.Printf("laboob listening on %s", *listen)
	log.Fatal(srv.ListenAndServe())
}

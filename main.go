package main

import (
	"log"
	"net/http"
	"strconv"
)

const port = 8080

// Sessions have challenge sessions
var Sessions map[string]SessionData

// DB is ...
var DB []Column

func main() {
	static := http.FileServer(http.Dir("static"))
	Sessions = make(map[string]SessionData)

	// routing
	http.Handle("/", static)
	http.HandleFunc("/register/challenge", HandleRegisterChallenge)
	http.HandleFunc("/register/attestation", HandleRegisterAttestation)

	log.Printf("server listening on port %v.", port)

	http.ListenAndServe(":"+strconv.Itoa(port), nil)
}

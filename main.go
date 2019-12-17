package main

import (
	"log"
	"net/http"
	"strconv"
)

const port = 8080

// Sessions have challenge sessions
var Sessions []SessionData

func main() {
	static := http.FileServer(http.Dir("static"))

	// routing
	http.Handle("/", static)
	http.HandleFunc("/register/challenge", HandleRegisterChallenge)
	http.HandleFunc("/register/apply", HandleRegisterAttestation)

	log.Printf("server listening on port %v.", port)

	http.ListenAndServe(":"+strconv.Itoa(port), nil)
}

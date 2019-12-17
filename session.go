package main

// SessionData is holding challenge prevent to replay attack
type SessionData struct {
	Challenge []byte
	UserID    []byte
	UV        string
}

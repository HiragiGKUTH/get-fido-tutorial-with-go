package main

// SessionData is holding challenge prevent to replay attack
type SessionData struct {
	UserID []byte
	Expire int64
}

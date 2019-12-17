package main

import "./protocol"

type Column struct {
	ID       string
	UserID   []byte
	AuthData protocol.AuthData
}

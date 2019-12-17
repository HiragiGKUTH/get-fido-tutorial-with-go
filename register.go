package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"./protocol"
)

// HandleRegisterChallenge handles client register request and send challenge reponse
func HandleRegisterChallenge(rw http.ResponseWriter, rq *http.Request) {
	// parse challenge request json to golang struct
	var challengeReq protocol.ChallengeRequest
	rawReq := make([]byte, rq.ContentLength)
	rq.Body.Read(rawReq)
	json.Unmarshal(rawReq, &challengeReq)

	fmt.Print(string(rawReq))
	fmt.Printf("%+v", challengeReq)

	// set user infomation
	challenge := make([]byte, 64)
	userID := make([]byte, 32)
	userName := challengeReq.Username
	userDisplayName := challengeReq.DisplayName
	attestationType := challengeReq.AttestationType

	// set challenge
	rand.Read(challenge)
	rand.Read(userID)

	// build options
	credOptions := protocol.ChallengeResponse{
		PublicKey: protocol.PublicKey{
			Challenge:   challenge,
			Attestation: attestationType,
			Rp: protocol.Rp{
				Id:   "localhost",
				Name: "Hiragi Corp",
			},
			User: protocol.User{
				Id:          userID,
				Name:        userName,
				DisplayName: userDisplayName,
			},
			PubKeyCredParams: []protocol.PubKeyCredParam{
				protocol.PubKeyCredParam{
					Type: "public-key",
					Alg:  -7,
				},
			},
		},
	}

	// json stringfy
	response, err := json.MarshalIndent(credOptions, "", "  ")
	if err != nil {
		log.Print(err)
	}
	// set session
	Sessions = append(Sessions, SessionData{Challenge: challenge, UserID: userID, UV: "discourage"})

	// set header adn send!!
	rw.Header().Add("Content-Type", "application/json")
	rw.Write(response)
}

// HandleRegisterAttestation handles clientDataJSON
func HandleRegisterAttestation(rw http.ResponseWriter, rq *http.Request) {
	// parse challenge request json to golang map
	var challengeReq protocol.ChallengeRequest
	rawReq := make([]byte, rq.ContentLength)
	rq.Body.Read(rawReq)
	json.Unmarshal(rawReq, &challengeReq)

	fmt.Fprint(rw, "{}")
}

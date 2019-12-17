package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"./protocol"
	cbor "bitbucket.org/bodhisnarkva/cbor/go"
)

// HandleRegisterChallenge handles client register request and send challenge reponse
func HandleRegisterChallenge(rw http.ResponseWriter, rq *http.Request) {
	// parse challenge request json to golang struct
	var challengeReq protocol.ChallengeRequest
	rawReq := make([]byte, rq.ContentLength)
	rq.Body.Read(rawReq)
	json.Unmarshal(rawReq, &challengeReq)

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
			TimeOut:     60000,
			Rp: protocol.Rp{
				ID:   "localhost",
				Name: "Hiragi Corp",
			},
			User: protocol.User{
				ID:          userID,
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
	response, err := json.Marshal(credOptions)
	if err != nil {
		log.Print(err)
	}
	// set session
	Sessions[fmt.Sprintf("%x", challenge)] = SessionData{
		UserID: userID,
		Expire: time.Now().Add(time.Duration(time.Second * 60)).Unix(),
	}

	log.Println("Register Challenge: Session stored")

	// set header and send!!
	rw.Header().Add("Content-Type", "application/json")
	rw.Write(response)
}

// HandleRegisterAttestation handles clientDataJSON
func HandleRegisterAttestation(rw http.ResponseWriter, rq *http.Request) {
	// JSON request -> go struct
	var tagAuthAttResp protocol.JsonTagAuthenticatorAttestationResponse
	rawReq := make([]byte, rq.ContentLength)
	rq.Body.Read(rawReq)
	json.Unmarshal(rawReq, &tagAuthAttResp)

	// base64 -> JSON
	decodedClientDataJSON, _ := base64.StdEncoding.DecodeString(tagAuthAttResp.Response.ClientDataJSON)
	// base64 -> CBOR
	decodedAttObj, _ := base64.StdEncoding.DecodeString(tagAuthAttResp.Response.AttestationObject)

	// JSON -> go struct
	var tagClientDataJSON protocol.JsonTagClientDataJSON
	json.Unmarshal(decodedClientDataJSON, &tagClientDataJSON)

	// CBOR -> go struct
	var tagAttObj protocol.CborTagAttestationObject
	cbor.NewDecoder(bytes.NewReader(decodedAttObj)).Decode(&tagAttObj)

	// parse hex auth data (Raw HEX -> go hex struct)
	rawHex := tagAttObj.AuthData
	credIDLen := binary.BigEndian.Uint16(rawHex[53:55])
	hexAuthData := protocol.HexAuthData{
		RpIDHash:      rawHex[0:32],
		Flags:         rawHex[32],
		Counter:       rawHex[33:37],
		AAGUID:        rawHex[37:53],
		CredID:        rawHex[55 : 55+credIDLen],
		COSEPublicKey: rawHex[55+credIDLen:],
	}

	// COSE -> map
	mapPublicKey := make(map[int]interface{})
	cbor.NewDecoder(bytes.NewReader(hexAuthData.COSEPublicKey)).Decode(&mapPublicKey)
	publicKeyData := protocol.PublicKeyData{
		Alg: int(mapPublicKey[3].(int64)),
		Kty: int(mapPublicKey[1].(uint64)),
		X:   mapPublicKey[-2].([]byte),
		Y:   mapPublicKey[-3].([]byte),
	}

	// construct parsed authData
	authData := protocol.AuthData{
		PublicKey: publicKeyData,
		AAGUID:    hexAuthData.AAGUID,
		Counter:   binary.BigEndian.Uint32(hexAuthData.Counter),
		CredID:    hexAuthData.CredID,
		Flags:     protocol.AuthDataFlags{false, false, false, false, 0},
		RpIDHash:  hexAuthData.RpIDHash,
	}

	// Parse End! Construct Actual Data Structure
	authrAttResp := protocol.AuthenticatorAttestationResponse{
		ID:   tagAuthAttResp.ID,
		Type: tagAuthAttResp.Type,
		Response: protocol.AttestationResponse{
			AttestationObject: protocol.AttestationObject{
				AttStmt:  tagAttObj.AttStmt,
				Fmt:      tagAttObj.Fmt,
				AuthData: authData,
			},
			ClientDataJSON: protocol.ClientDataJSON{
				Challenge: decodeBase64Url(tagClientDataJSON.Challenge),
				Origin:    tagClientDataJSON.Origin,
				Type: protocol.AuthType{
					TypeString: tagClientDataJSON.Type,
					Create:     true,
					Get:        false,
				},
			},
		},
	}

	// verify challenge
	chStr := fmt.Sprintf("%x", authrAttResp.Response.ClientDataJSON.Challenge)
	session, ok := Sessions[chStr]
	if !ok {
		log.Printf("Register Attestation: invalid challenge(%v)\n", chStr)
		fmt.Fprintf(rw, "{\"error\": \"invalid challenge\", \"c\": \"%v\"}", chStr)
		return
	}
	if session.Expire < time.Now().Unix() {
		log.Println("Register Attestation: session expired")
		fmt.Fprintf(rw, "{\"error\": \"session expired\"}")
		return
	}
	log.Println("Register Attestation: challenge verified")

	// verify origin
	if origin := authrAttResp.Response.ClientDataJSON.Origin; origin != "http://localhost:8080" {
		log.Printf("Register Attestation: invalid origin(%v)\n", origin)
		fmt.Fprintf(rw, "{\"error\": \"invalid origin\", \"o\": \"%v\"}", origin)
		return
	}
	log.Println("Register Attestation: origin verified")

	// verify AuthenticatorAttestationResponse
	// but fmt: "none" ... SKIP VERIFY

	// DB Registration...
	DB = append(DB, Column{
		ID:       authrAttResp.ID,
		UserID:   session.UserID,
		AuthData: authData,
	})

	fmt.Fprint(rw, "{\"message\": \"created\"}")
	log.Printf("Register Attestation: user created\n %+v", DB[len(DB)-1])
}

func decodeBase64(enc string) []byte {
	b, e := base64.StdEncoding.DecodeString(enc)
	if e != nil {
		log.Println(enc)
		log.Panic(e)
	}
	return b
}

func decodeBase64Url(enc string) []byte {
	b, e := base64.RawURLEncoding.DecodeString(enc)
	if e != nil {
		log.Println(enc)
		log.Panic(e)
	}
	return b
}

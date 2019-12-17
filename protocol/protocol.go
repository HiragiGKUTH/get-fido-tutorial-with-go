package protocol

// ChallengeRequest is challenge request
type ChallengeRequest struct {
	Username        string
	DisplayName     string
	AttestationType string
	ResidentKey     bool
}

// Rp is Relay Party entity data
type Rp struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// User is authentication user entity data
type User struct {
	ID          []byte `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

// PubKeyCredParam indicates public key kind
type PubKeyCredParam struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}

// PublicKey is actual key
type PublicKey struct {
	Challenge        []byte            `json:"challenge"`
	Attestation      string            `json:"attestation"`
	Rp               Rp                `json:"rp"`
	User             User              `json:"user"`
	PubKeyCredParams []PubKeyCredParam `json:"pubKeyCredParams"`
}

// ChallengeResponse is challenge response
type ChallengeResponse struct {
	PublicKey PublicKey `json:"publicKey"`
}

// AuthenticatorAttestationResponse is response that client authenticator create for server attestation
type AuthenticatorAttestationResponse struct {
	ClientDataJSON []byte
}

// ClientDataJSON is json string of client authenticator infomation
type ClientDataJSON struct {
	AttestationObject string `json:"attestationObject"`
}

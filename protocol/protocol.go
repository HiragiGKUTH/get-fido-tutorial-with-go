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
	TimeOut          uint64            `json:"timeout"`
}

// ChallengeResponse is challenge response
type ChallengeResponse struct {
	PublicKey PublicKey `json:"publicKey"`
}

// ATTESTATION SECTION

// RawAuthenticatorAttestationResponse is raw json response that client authenticator create for server attestation
type JsonTagAuthenticatorAttestationResponse struct {
	ID       string                    `json:"id"`
	RawID    string                    `json:"rawId"`
	Type     string                    `json:"type"`
	Response JsonTagAttestationReponse `json:"response"`
}

type JsonTagAttestationReponse struct {
	AttestationObject string `json:"attestationObject"`
	ClientDataJSON    string `json:"clientDataJSON"`
}

// ClientDataJSON is json string of client authenticator infomation
type JsonTagClientDataJSON struct {
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
	Type      string `json:"type"`
}

type CborTagAttestationObject struct {
	AttStmt  map[string]string `json:"attStmt"`
	AuthData []byte            `json:"authData"`
	Fmt      string            `json:"fmt"`
}

type AuthenticatorAttestationResponse struct {
	ID       string
	Type     string
	Response AttestationResponse
}

type AttestationResponse struct {
	AttestationObject AttestationObject
	ClientDataJSON    ClientDataJSON
}

type ClientDataJSON struct {
	Challenge []byte
	Origin    string
	Type      AuthType
}

type AuthType struct {
	TypeString string
	Create     bool
	Get        bool
}

type AttestationObject struct {
	AttStmt  map[string]string
	AuthData AuthData
	Fmt      string
}

type HexAuthData struct {
	COSEPublicKey []byte
	AAGUID        []byte
	Counter       []byte
	CredID        []byte
	Flags         byte
	RpIDHash      []byte
}

type AuthData struct {
	PublicKey PublicKeyData
	AAGUID    []byte
	Counter   uint32
	CredID    []byte
	Flags     AuthDataFlags
	RpIDHash  []byte
}

type AuthDataFlags struct {
	Up      bool
	Uv      bool
	At      bool
	Ed      bool
	FlagInt int
}

type PublicKeyData struct {
	Kty int
	Alg int
	X   []byte
	Y   []byte
}

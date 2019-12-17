function bufferDecode(value) {
  return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}


async function register() {
  // send challenge request
  const credOptions = await _sendChallenge();

  // base64 decoding
  credOptions.publicKey.challenge = bufferDecode(credOptions.publicKey.challenge)
  credOptions.publicKey.user.id = bufferDecode(credOptions.publicKey.user.id)

  // show received credentials
  console.log(credOptions.publicKey)

  // create credentials
  const clientData = await navigator.credentials.create(credOptions);

  // send new credentials
  const result = await _sendAttestation(clientData)

  console.log(result)

  return;

  async function _sendChallenge() {
    const endpoint = "http://localhost:8080/register/challenge"
    
    const userName = document.getElementById("register_username").value;
    const displayName = document.getElementById("register_displayname").value;
  
    // build request
    const req = {
      "username": userName,
      "displayName": displayName,
      "attestationType": "none",
      "residentKey": false,
    }

    // send request
    const response = await fetch(endpoint, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(req),
    });

    return response.json();
  }

  async function _sendAttestation(clientData) {
    const endpoint = "http://localhost:8080/register/make"
    const clientDataJSON = JSON.stringify(clientData)

    const response = await fetch(endpoint, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(clientDataJSON),
    });

    return response.json()
  }
}

function login() {
  navigator.credentials.get()
}


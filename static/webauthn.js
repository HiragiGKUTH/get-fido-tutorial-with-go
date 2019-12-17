function encodeBase64(bytes) {
  const table = [];
  for (let i = 65; i < 91; i++) table.push(String.fromCharCode(i))
  for (let i = 97; i < 123; i++) table.push(String.fromCharCode(i))
  for (let i = 0; i < 10; i++) table.push(i.toString(10))
  table.push("+");
  table.push("/");

  let base64 = "";
  let i = 0;
  const len = bytes.byteLength;
  for (i = 0; i < len; i += 3) {
    if (len === i + 1) {  // last 1 byte
      const a = (bytes[i] & 0xfc) >> 2;
      const b = ((bytes[i] & 0x03) << 4);
      base64 += table[a];
      base64 += table[b];
      base64 += "==";
    } else if (len === i + 2) { // last 2 bytes
      const a = (bytes[i] & 0xfc) >> 2;
      const b = ((bytes[i] & 0x03) << 4) | ((bytes[i+1] & 0xf0) >> 4);
      const c = ((bytes[i+1] & 0x0f) << 2);
      base64 += table[a];
      base64 += table[b];
      base64 += table[c];
      base64 += "=";
    } else {
      const a = (bytes[i] & 0xfc) >> 2;
      const b = ((bytes[i] & 0x03) << 4) | ((bytes[i+1] & 0xf0) >> 4);
      const c = ((bytes[i+1] & 0x0f) << 2) | ((bytes[i+2] & 0xc0) >> 6);
      const d = bytes[i+2] & 0x3f;
      base64 += table[a];
      base64 += table[b];
      base64 += table[c];
      base64 += table[d];
    }
  }
  return base64;
}

function bufferDecode(value) {
  return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}

function bufferEncode(value) {
  u8a = new Uint8Array(value);
  return encodeBase64(u8a);
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
    const endpoint = "http://localhost:8080/register/attestation"

    const id = clientData.id;
    const rawId = bufferEncode(clientData.rawId);
    const attestationObject = bufferEncode(clientData.response.attestationObject);
    const clientDataJSON = bufferEncode(clientData.response.clientDataJSON);
    const type = clientData.type;

    console.dir(clientData);
    console.log(clientDataJSON);

    const response = await fetch(endpoint, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        id,
        rawId,
        type,
        response: {
          attestationObject,
          clientDataJSON,
        },
      }),
    });

    return response.json()
  }
}

function login() {
  navigator.credentials.get()
}


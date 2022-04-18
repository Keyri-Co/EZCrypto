// ////////////////////////////////////////////////////////////////////////////
// ////////////////////////////////////////////////////////////////////////////
// ////////////////////////////////////////////////////////////////////////////
//
// Class with methods to make working with subtle crypto
// easier and more obvious
//
class EZCrypto {
  constructor() {
    // super();
  }

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     base64ToArray
  // What is this: Take a base64 string. Convert it to a Uint8Array...
  //
  // Arguments:    strng: - base64 encoded string
  //
  // Returns:      Uint8Array
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  base64ToArray(strng) {
    return Uint8Array.from(atob(strng), (c) => c.charCodeAt(0));
  }

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     arrayToBase64
  // What is this: take a Uint8Array, make it a valid base64 string
  //
  // Arguments:    ary: - Uint8Array
  //
  // Returns:      Base64 String
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  arrayToBase64(ary) {
    return btoa(String.fromCharCode(...ary));
  }

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     hmac (static) (async)
  // What is this: Create a cryptographic signature for a piece of data given a *SHARED* secret.
  //               Similar to ECDSA - Except both parties have to have the secret-key in advance
  //               to make it work.
  //
  // Arguments:    secret - this is the shared secret
  //               data   - this is the string you're encrypting
  //
  // Returns:      hex encoded 32 character string or something...(todo: check length - better def)
  // Notes:        https://stackoverflow.com/questions/47329132/how-to-get-hmac-with-crypto-web-api#47332317
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  HMAC = async (secret, data) => {
    // To do work, we need to convert text to Uint8Arrays
    let encoder = new TextEncoder("utf-8");
    let encodedSecret = encoder.encode(secret);
    let encodedData = encoder.encode(data);

    // Create our HMAC Key
    let key = await window.crypto.subtle.importKey(
      "raw",
      encodedSecret,
      { name: "HMAC", hash: { name: "SHA-256" } },
      false,
      ["sign", "verify"]
    );

    // HMAC Sign our data with our HMAC Key
    let sig = await window.crypto.subtle.sign("HMAC", key, encodedData);

    // Turn the signature into an array; then into hex-text
    // (todo: Maybe this is its own method...?)
    //
    let b = new Uint8Array(sig);
    let str = Array.prototype.map
      .call(b, (x) => ("00" + x.toString(16)).slice(-2))
      .join("");

    return str;
  }

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     AESMakeKey (async)
  // What is this: Generate an AES Key and return its hex
  //
  // Arguments:    *NONE*
  //
  // Returns:      base64 string
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  AESMakeKey = async () => {
    // 1.) Generate the Key
    let key = await window.crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );

    // 2.) Export to Array Buffer
    let out = await window.crypto.subtle.exportKey("raw", key);

    // 3.) Return it as b64
    return this.arrayToBase64(new Uint8Array(out));
  };

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     AESEncrypt (async)
  // What is this: Given
  //
  // Arguments:    key:  base64 AES-key
  //               data: uInt8Array
  //
  // Returns:      base64 string
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  async AESEncrypt(base_64_key, data_array) {
    // 1.) Convert out from base64 to array
    let aes_ary = this.base64ToArray(base_64_key);

    // 2.) Convert the Key-Array to a live Key
    let aes_key = await window.crypto.subtle.importKey(
      "raw",
      aes_ary.buffer,
      "AES-GCM",
      true,
      ["encrypt"]
    );

    // 3.) Create a nonce why not?
    let nonce = window.crypto.getRandomValues(new Uint8Array(16));

    // 4.) encrypt our data
    let encrypted = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce },
      aes_key,
      data_array
    );

    // 5.) Base64 and return our data...
    return {
      ciphertext: this.arrayToBase64(new Uint8Array(encrypted)),
      nonce: this.arrayToBase64(nonce),
    };
  }

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     AESDecrypt (async)
  // What is this: Given
  //
  // Arguments:    key:  base64 AES-key
  //               nonce: base64 of the nonce used at encryption (ok if it is public)
  //               ciphertext: base64 of what's been encoded
  //
  // Returns:      base64 string
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  async AESDecrypt(base_64_key, base_64_nonce, base_64_cipher) {
    // 1.) Convert out from base64 to array
    let aes_ary = this.base64ToArray(base_64_key);
    let nonce_ary = this.base64ToArray(base_64_nonce);
    let cipher_ary = this.base64ToArray(base_64_cipher);

    // 2.) Convert the Key-Array to a live Key
    let aes_key = await window.crypto.subtle.importKey(
      "raw",
      aes_ary.buffer,
      "AES-GCM",
      true,
      ["decrypt"]
    );

    // 3.) Decrypt
    return await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce_ary },
      aes_key,
      cipher_ary
    );
  }

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     EcMakeCryptKeys (async)
  // What is this: Given
  //
  // Arguments:    none
  //
  // Returns:      object containing public and private key pair
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  EcMakeCryptKeys = async () => {
    // Step 1) Create ECDH KeyS
    let keys = await window.crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveKey"]
    );

    // Step 2) Export keys to SPKI|PKCS8 format
    let b64Keys = await Promise.all([
      window.crypto.subtle.exportKey("spki", keys.publicKey).then((key) => {
        return this.arrayToBase64(new Uint8Array(key));
      }),
      window.crypto.subtle.exportKey("pkcs8", keys.privateKey).then((key) => {
        return this.arrayToBase64(new Uint8Array(key));
      }),
    ]);

    // Step 3) Convert the keys to base64 and return...
    return { publicKey: b64Keys[0], privateKey: b64Keys[1] };
  };

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     EcEncrypt (async)
  // What is this: Encrypt Uint8Data with 2 SPKI-Encoded ECDH Keys.
  //               ---
  //               Basically it does the dirty work of:
  //               - convert base64 keys to live keys
  //               - creating AES key from live keys
  //               - encrypting data with AES Key
  //               - return base64 ciphertext and nonce
  //
  //
  // Arguments:    base64privateKey: string;
  //               base64publicKey: string;
  //
  // Returns:      object containing public and private key pair
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  EcEncrypt = async (b64Private, b64Public, data) => {
    // 1.) convert the given keys to real keys
    let publicKey = await window.crypto.subtle.importKey(
      "spki",
      this.base64ToArray(b64Public),
      { name: "ECDH", namedCurve: "P-256" },
      true,
      []
    );
    let privateKey = await window.crypto.subtle.importKey(
      "pkcs8",
      this.base64ToArray(b64Private),
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveKey"]
    );

    // 2.) generate shared key
    let aes_key = await window.crypto.subtle.deriveKey(
      { name: "ECDH", public: publicKey },
      privateKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );

    // 3.) Create a nonce why not?
    let nonce = window.crypto.getRandomValues(new Uint8Array(16));

    // 4.) encrypt our data
    let encrypted = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce },
      aes_key,
      data
    );

    // 5.) Base64 and return our data...
    return {
      ciphertext: this.arrayToBase64(new Uint8Array(encrypted)),
      nonce: this.arrayToBase64(nonce),
    };
  };

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     EcDecrypt (async)
  // What is this: Decrypt Uint8Data with 2 SPKI-Encoded ECDH Keys.
  //               ---
  //               Basically it does the dirty work of:
  //               - convert base64 keys to live keys
  //               - creating AES key from live keys
  //               - encrypting data with AES Key
  //               - return base64 ciphertext and nonce
  //
  //
  // Arguments:    base64privateKey: string;
  //               base64publicKey: string;
  //               base64nonce: string;
  //               base64data: string;
  //
  // Returns:      object containing public and private key pair
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  EcDecrypt = async (b64Private, b64Public, b64Nonce, b64data) => {
    // 1.) convert the given keys to real keys
    let publicKey = await window.crypto.subtle.importKey(
      "spki",
      this.base64ToArray(b64Public),
      { name: "ECDH", namedCurve: "P-256" },
      true,
      []
    );
    let privateKey = await window.crypto.subtle.importKey(
      "pkcs8",
      this.base64ToArray(b64Private),
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveKey"]
    );
    let nonce = this.base64ToArray(b64Nonce);
    let data = this.base64ToArray(b64data);

    // 2.) generate shared key
    let aes_key = await window.crypto.subtle.deriveKey(
      { name: "ECDH", public: publicKey },
      privateKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );

    // 4.) encrypt our data
    return await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce },
      aes_key,
      data
    );
  };
  
  
  
  
  
  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     EcMakeSigKeys (async)
  // What is this: Given
  //
  // Arguments:    none
  //
  // Returns:      object containing public and private key pair
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  
  EcMakeSigKeys = async () => {
    // Step 1) Create ECDSA KeyS
    let keys = await window.crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign","verify"]
    );

    // Step 2) Export keys to SPKI|PKCS8 format
    let b64Keys = await Promise.all([
      window.crypto.subtle.exportKey("spki", keys.publicKey).then((key) => {
        return this.arrayToBase64(new Uint8Array(key));
      }),
      window.crypto.subtle.exportKey("pkcs8", keys.privateKey).then((key) => {
        return this.arrayToBase64(new Uint8Array(key));
      }),
    ]);

    // Step 3) Convert the keys to base64 and return...
    return { publicKey: b64Keys[0], privateKey: b64Keys[1] };
  };
  
  
  
  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     EcSignData (async)
  // What is this: Create a crypto-signature from a private key and data
  //
  // Arguments:    base64privateKey: string;
  //               data: Uint8Array;
  //
  // Returns:      base64 encoded signature
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  EcSignData = async (b64PrivateKey, data) => {
    // 1.) convert the given keys to real keys
    let privateKey = await window.crypto.subtle.importKey(
      "pkcs8",
      this.base64ToArray(b64PrivateKey),
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign"]
    );

    // 2.) sign the data with the live key
    let signature = await window.crypto.subtle.sign({"name": "ECDSA", "hash": {"name": "SHA-256"}}, privateKey, data);

    // 3.) Base64 and return our data...
    return  await this.arrayToBase64(new Uint8Array(signature));
  
  };
  
  
  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     EcVerifySig (async)
  // What is this: Given a public key, some data, and a signature; prove the
  //               signature came from the data and the public key
  //
  // Arguments:    base64PublicKey: string;
  //               data: Uint8Array;
  //
  // Returns:      base64 encoded signature
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  EcVerifySig = async (b64PublicKey, b64Signature, data) => {
    
    // 1.) convert the given keys to real keys
    let publicKey = await window.crypto.subtle.importKey(
      "spki",
      this.base64ToArray(b64PublicKey),
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"]
    );

    // 2.) Convert the signature to an array
    let signature = this.base64ToArray(b64Signature);

    // 3.) verify the data with the live key
    return await window.crypto.subtle.verify({"name": "ECDSA", "hash": {"name": "SHA-256"}}, publicKey, signature, data);

  
  };
}
// \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
// \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
// \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
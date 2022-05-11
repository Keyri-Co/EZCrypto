// ////////////////////////////////////////////////////////////////////////////
// ////////////////////////////////////////////////////////////////////////////
// ////////////////////////////////////////////////////////////////////////////
//
// Class with methods to make working with subtle crypto
// easier and more obvious
//
export class EZCrypto {
  constructor() {}

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
  // Function:     AESImportKey (async)
  // What is this: Generate an AES Key and return its hex
  //
  // Arguments:    base64 string
  //
  // Returns:      Live AES Key
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  AESImportKey = async (base64) => {
    // 1.) Generate the Key
    return await window.crypto.subtle.importKey(
        "raw",
        this.base64ToArray(base64).buffer,
        "AES-GCM",
        true,
        ["encrypt", "decrypt"]
      );
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

  async AESEncrypt(base_64_key, base_64_data) {
    
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
      this.base64ToArray(base_64_data)
    );

    // 5.) Base64 and return our data...
    return {
      ciphertext: this.arrayToBase64(new Uint8Array(encrypted)),
      iv: this.arrayToBase64(nonce),
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

  EcMakeCryptKeys = async (exportable = true) => {
    // Step 1) Create ECDH KeyS
    let keys = await window.crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      exportable,
      ["deriveKey","deriveBits"]
    );

    // Step 2) Export keys to SPKI|PKCS8|JWK|RAW format
    let exportKeys;

    if(exportable){
      exportKeys = await Promise.all([
          window.crypto.subtle.exportKey("spki", keys.publicKey).then((key) => {
            return this.arrayToBase64(new Uint8Array(key));
          }),
          window.crypto.subtle.exportKey("pkcs8", keys.privateKey).then((key) => {
            return this.arrayToBase64(new Uint8Array(key));
          }),
          window.crypto.subtle.exportKey("jwk", keys.publicKey).then((key) => {
            return (key);
          }),
          window.crypto.subtle.exportKey("jwk", keys.privateKey).then((key) => {
            return (key);
          }),
          window.crypto.subtle.exportKey("raw", keys.publicKey).then((key) => {
            return this.arrayToBase64( new Uint8Array(key));
          }),
          window.crypto.subtle.exportKey("raw", keys.publicKey).then((key) => {
            return this.arrayToBase64( new Uint8Array(key).slice(1,1000));
          })
      ]);
      
    } else {
      exportKeys = await Promise.all([
          window.crypto.subtle.exportKey("spki", keys.publicKey).then((key) => {
            return this.arrayToBase64(new Uint8Array(key));
          }),
          (new Promise((s,j) => {return s(keys.privateKey)})),
          window.crypto.subtle.exportKey("jwk", keys.publicKey).then((key) => {
            return (key);
          }),
          (new Promise((s,j) => {return s(keys.privateKey)})),
          window.crypto.subtle.exportKey("raw", keys.publicKey).then((key) => {
            return this.arrayToBase64( new Uint8Array(key));
          }),
          window.crypto.subtle.exportKey("raw", keys.publicKey).then((key) => {
            return this.arrayToBase64( new Uint8Array(key).slice(1,1000));
          })
      ]);
    }

    

    // Step 3) Convert the keys to base64 and return...
    return { 
      publicKey: exportKeys[0], 
      privateKey: exportKeys[1], 
      jwkPublicKey: exportKeys[2], 
      jwkPrivateKey: exportKeys[3], 
      rawPublicKey: exportKeys[4],
      rawPublicKeyLite: exportKeys[5]
    };
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
  //               base64data: string;
  //
  // Returns:      object containing public and private key pair
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  EcEncrypt = async (b64Private, b64Public, b64data) => {

    // 1.) convert the given keys to real keys in the most
    //     generic way possible...
    let publicKey = await this.EcdhConvertKey(b64Public);
    let privateKey = await this.EcdhConvertKey(b64Private);
    
    // 2.) generate shared key
    let aes_key = await window.crypto.subtle.deriveKey(
      { name: "ECDH", public: publicKey },
      privateKey,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    )
    
    // 3.) convert it out to data-array
    let aes_key_raw = await window.crypto.subtle.exportKey("raw",aes_key);
    
    // 4.) convert that to base64
    let b64_aes_key = this.arrayToBase64(new Uint8Array(aes_key_raw));
    
    // 5.) Work smarter, not harder, dummy...
    return await this.AESEncrypt(b64_aes_key, b64data);
  
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

    // 1.) convert the given keys to real keys in the most
    //     generic way possible...
    let publicKey = await this.EcdhConvertKey(b64Public);
    let privateKey = await this.EcdhConvertKey(b64Private);
    let nonce = this.base64ToArray(b64Nonce);
    let data = this.base64ToArray(b64data);

    // 2.) generate shared key
    let aes_key = await window.crypto.subtle.deriveKey(
      { name: "ECDH", public: publicKey },
      privateKey,
      { name: "AES-GCM", length: 256 },
      true,
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
  // Function:     HKDFEncrypt (async)
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
  //               base64data: string;
  //
  // Returns:      object containing public and private key pair
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

  HKDFEncrypt = async (b64Private, b64Public, b64data) => {

    // 1.) convert the given keys to real keys in the most
    //     generic way possible...
    let publicKey = await this.EcdhConvertKey(b64Public);
    let privateKey = await this.EcdhConvertKey(b64Private);
    
    // 2.) generate shared secret for HKDF
    //
    let sharedSecret = await window.crypto.subtle.deriveBits({ 
      "name": "ECDH", 
      "namedCurve": "P-256", 
      "public": publicKey 
    },privateKey,256);
    
    // 3.) convert shared-secret into a key
    //
    let sharedSecretKey = await window.crypto.subtle.importKey(
      "raw", sharedSecret, 
      { "name": 'HKDF' }, 
      false, 
      ['deriveKey','deriveBits']
    );
    
    // 4.) create SALT
    //
    let salt = window.crypto.getRandomValues(new Uint8Array(16));
    
    // 5.) convert the live-shared-secret-key into an aes key
    //
    let derivedKey = await window.crypto.subtle.deriveBits({
      "name": 'HKDF', 
      "hash": 'SHA-256', 
      "salt": salt,
      "info": new Uint8Array([])},
      sharedSecretKey,256
    );
    
    //
    // 6.) 
    //   ___  __  __ _____ ____
    //  / _ \|  \/  |  ___/ ___|
    // | | | | |\/| | |_ | |  _
    // | |_| | |  | |  _|| |_| |
    //  \___/|_|  |_|_|   \____|
    //
    // THIS SHOULD NOT BE THIS HARD!
    //
    //     Convert the Key-Array to a live Key
    let aes_key = await window.crypto.subtle.importKey(
      "raw",
      derivedKey,
      "AES-GCM",
      true,
      ["encrypt","decrypt"]
    );
    
    // 7.) Init Vector
    //
    //
    let iv = window.crypto.getRandomValues(new Uint8Array(16));
    
    // 7.) Encrypt
    //
    //
    let encrypted = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      aes_key,
      this.base64ToArray(b64data)
    );
    
    // 8.) Base64 and return our data...
    return {
      "ciphertext": this.arrayToBase64(new Uint8Array(encrypted)),
      "salt": this.arrayToBase64(salt),
      "iv": this.arrayToBase64(iv)
    };

  
  };

  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     HKDFDecrypt (async)
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

  HKDFDecrypt = async (b64Private, b64Public, b64Salt, b64iv, b64data) => {

    // 1.) convert the given keys to real keys in the most
    //     generic way possible...
    let publicKey = await this.EcdhConvertKey(b64Public);
    console.log({b64Public, publicKey});
    
    let privateKey = await this.EcdhConvertKey(b64Private);
    console.log({b64Private,privateKey});
    
    let salt = this.base64ToArray(b64Salt);
    let iv = this.base64ToArray(b64iv);
    let data = this.base64ToArray(b64data);
    console.log({b64Salt,b64iv,b64data});
    
    
    // 2.) generate shared secret for HKDF
    //
    let sharedSecret = await window.crypto.subtle.deriveBits({ 
      "name": "ECDH", 
      "namedCurve": "P-256", 
      "public": publicKey 
    },privateKey,256);
    let nSharedSecret = this.arrayToBase64(new Uint8Array(sharedSecret));
    console.log({nSharedSecret});
    
    // 3.) convert shared-secret into a key
    //
    let sharedSecretKey = await window.crypto.subtle.importKey(
      "raw", sharedSecret, 
      { "name": 'HKDF' }, 
      false, 
      ['deriveKey','deriveBits']
    );
    console.log({sharedSecretKey});
    
    // 4.) convert the live-shared-secret-key into an aes key
    //
    let derivedKey = await window.crypto.subtle.deriveBits({
      "name": 'HKDF', 
      "hash": 'SHA-256', 
      "salt": salt,
      "info": new Uint8Array([])},
      sharedSecretKey,256
    );
    
    let n_derivedKey = this.arrayToBase64(new Uint8Array(derivedKey));
    console.log({n_derivedKey});
    
    //
    // 5.) 
    //     Convert the Key-Array to a live Key
    let aes_key = await window.crypto.subtle.importKey(
      "raw",
      derivedKey,
      "AES-GCM",
      true,
      ["encrypt","decrypt"]
    );

    let n_aes_key = await window.crypto.subtle.exportKey("raw", aes_key);
    n_aes_key = this.arrayToBase64(new Uint8Array(n_aes_key));
    console.log({n_aes_key});


    // 6.) decrypt our data
    //
    try{
      let aes_data = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        aes_key,
        data
      );
    } catch(e){
      console.log({e});
    }
    
    console.log({aes_data});
    
    return aes_data;
    
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

  EcSignData = async (b64PrivateKey, b64data) => {
    
    // 1.) convert the given keys to real keys
    let privateKey = await this.EcdsaConvertKey(b64PrivateKey);

    // 2.) sign the data with the live key
    let signature = await window.crypto.subtle.sign({"name": "ECDSA", "hash": {"name": "SHA-256"}}, privateKey, this.base64ToArray(b64data));

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

  EcVerifySig = async (b64PublicKey, b64Signature, b64data) => {

    // 1.) convert the given keys to real keys
    let publicKey = await this.EcdsaConvertKey(b64PublicKey);
    

    // 2.) Convert the signature to an array
    let signature = this.base64ToArray(b64Signature);

    // 3.) verify the data with the live key
    return await window.crypto.subtle.verify({"name": "ECDSA", "hash": {"name": "SHA-256"}}, publicKey, signature, this.base64ToArray(b64data));

  };
  
  
  
  
  
  
  
  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     EzConvertKey (base64key)
  // What is this: Sloppy AF function to try converting random data into a key
  //               until something works...
  //
  // Arguments:    none
  //
  // Returns:      hopefully a live key...probably an error and an hour of debugging.
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  
  
  
  EcdhConvertKey = async (unknown_key) => {

    let key;
    let longKey;
    
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // NATURAL KEY
    if(unknown_key instanceof CryptoKey){
      return unknown_key;
    }
    //
    //
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // SPKI PUBLIC?
    //
    //
    try {
      key = await window.crypto.subtle.importKey(
        "spki",
        this.base64ToArray(unknown_key),
        { name: "ECDH", namedCurve: "P-256" },
        true,
        []
      );
      return key;

    } catch(e){}
    //
    //
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // RAW PUBLIC
    //
    //
    try {
      key = await window.crypto.subtle.importKey(
        "raw",
        this.base64ToArray(unknown_key),
        { name: "ECDH", namedCurve: "P-256" },
        true,
        []
      );
      return key;
      
    } catch(e){}
    //
    //
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // PKCS8 PRIVATE
    //
    //
    try{
      key = await window.crypto.subtle.importKey(
        "pkcs8",
        this.base64ToArray(unknown_key),
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveKey","deriveBits"]
      );
      return key;
      
    } catch(e){}
    //
    //
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // RAW PUBLIC - PERVERTED
    //
    //
    try {
      
      longKey = new Uint8Array([4].concat(Array.from(this.base64ToArray(unknown_key))));
      key = await window.crypto.subtle.importKey(
        "raw",
        longKey,
        { name: "ECDH", namedCurve: "P-256" },
        true,
        []
      );
      return key;
      
    } catch(e){
      throw new Error("UNRECOGNIZED KEY FORMAT");
    }



  }




  // //////////////////////////////////////////////////////////////////////////
  // //////////////////////////////////////////////////////////////////////////
  //
  // Function:     EcdsaConvertKey (some sort of key)
  // What is this: Sloppy AF function to try converting random data into a key
  //               until something works...
  //
  // Arguments:    none
  //
  // Returns:      hopefully a live key...probably an error and an hour of debugging.
  // Notes:
  //
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
  
  EcdsaConvertKey = async (unknown_key) => {
    
    let key;
    let longKey;
    let err = true;
    
    
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // NATURAL KEY
    if(unknown_key instanceof CryptoKey){
      return unknown_key;
    }
    
    
    //
    //
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // SPKI PUBLIC?
    //
    //
    try {
      
      key = await window.crypto.subtle.importKey(
        "spki",
        this.base64ToArray(unknown_key),
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["verify"]
      );
      
      return key;
      
    } catch(e){}

    //
    //
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // RAW PUBLIC
    //
    //
    try {
      
      key = await window.crypto.subtle.importKey(
        "raw",
        this.base64ToArray(unknown_key),
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["verify"]
      );

      return key;
      
    } catch(e){}

    //
    //
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // PKCS8 PRIVATE
    //
    //
    try{

      key = await window.crypto.subtle.importKey(
        "pkcs8",
        this.base64ToArray(unknown_key),
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign"]
      );

      return key;
      
    } catch(e){}

    //
    //
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
    // RAW PUBLIC - PERVERTED
    //
    //
    try {

      longKey = new Uint8Array([4].concat(Array.from(this.base64ToArray(unknown_key))));
      key = await window.crypto.subtle.importKey(
        "raw",
        longKey,
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign"]
      );

      return key;
      
    } catch(e){
      throw new Error("UNRECOGNIZED KEY FORMAT");
    }

  }

  
  
}
// \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
// \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
// \\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\

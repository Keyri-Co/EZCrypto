//
// QUICK AND DIRTY DEMO OF HOW TO USE ECDH IN BROWSER AND NODE:
// - CREATE KEY-PAIR
// - IMPORT PUBLIC KEY
// - ENCRYPT
// - DECRYPT
//
//

(async () => {

  const {
    createECDH,
    webcrypto
  } = require('crypto');


// //////////////////////////////////////////////////////////////////////////
//  /////////////////////////////////////////////////////////////////////////
/*
| | _____ _   _  __ _  ___ _ __
| |/ / _ | | | |/ _` |/ _ | '_ \
|   |  __| |_| | (_| |  __| | | |
|_|\_\___|\__, |\__, |\___|_| |_|
          |___/ |___/
*/
//  /////////////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////////////



// //////////////////////////////////////////////////////////////////////////
// Server Generates Keys
// //////////////////////////////////////////////////////////////////////////
  const _server = createECDH('prime256v1');
  _server.generateKeys();
  
  let _serverPrivate = _server.getPrivateKey("base64");
  let _serverPublic = _server.getPublicKey("base64");

// //////////////////////////////////////////////////////////////////////////
// Browser Generates Keys
// //////////////////////////////////////////////////////////////////////////
  const _browser = await webcrypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey"]
  );
  
  let _browserPub = await webcrypto.subtle.exportKey("raw", _browser.publicKey).then((key) => {return Buffer.from(key).toString("base64")});
  let _browserPriv = await webcrypto.subtle.exportKey("pkcs8", _browser.privateKey).then((key) => {return Buffer.from(key).toString("base64")});


  let b64keys = {_serverPrivate, _serverPublic, _browserPub, _browserPriv};
  console.log(b64keys);
  
//  /////////////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////////////
/*
 _                 _ _
| | ___   __ _  __| | | _____ _   _ ___
| |/ _ \ / _` |/ _` | |/ / _ | | | / __|
| | (_) | (_| | (_| |   |  __| |_| \__ \
|_|\___/ \__,_|\__,_|_|\_\___|\__, |___/
                              |___/
*/
//  /////////////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////////////
  
  
// //////////////////////////////////////////////////////////////////////////
// Browser Imports Browser Private
// //////////////////////////////////////////////////////////////////////////
let BrowserLoadedBrowserPrivate = await webcrypto.subtle.importKey(
    "pkcs8",
    Buffer.from(_browserPriv,"base64"),
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey"]
  );
// //////////////////////////////////////////////////////////////////////////
// Browser Imports Server Public
// //////////////////////////////////////////////////////////////////////////
let BrowserLoadedServerPublic = await webcrypto.subtle.importKey(
    "raw",
    Buffer.from(_serverPublic,"base64"),
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );
  
  
// //////////////////////////////////////////////////////////////////////////
// SERVER IMPORTS SERVER PRIVATE => MAKES SERVER SECRET
// //////////////////////////////////////////////////////////////////////////
let __server = createECDH('prime256v1');

// Import private from base64
__server.setPrivateKey(Buffer.from(_serverPrivate,"base64"));

// Show me your secret-shared-whatnot!
let __serverSecret = await __server.computeSecret(Buffer.from(_browserPub,"base64"),null,"base64");




// //////////////////////////////////////////////////////////////////////////
// BROWSER IMPORTS BROWSER PRIVATE => MAKES BROWSER SECRET
// //////////////////////////////////////////////////////////////////////////
  
// 2.) generate shared key
let __browserSecret = await webcrypto.subtle.deriveKey(
  { name: "ECDH", public: BrowserLoadedServerPublic },
  BrowserLoadedBrowserPrivate,
  { name: "AES-GCM", length: 256 },
  true,
  ["encrypt", "decrypt"]
)

__browserSecret = Buffer.from(await webcrypto.subtle.exportKey("raw", __browserSecret)).toString("base64");







console.log({__serverSecret, __browserSecret});


  
})()
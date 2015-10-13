'use strict';

var macaroons = require('macaroons.js'),
  NodeRSA = require('node-rsa'),
  deserializeFn = macaroons.MacaroonsBuilder.deserialize,
  MacaroonsBuilder = macaroons.MacaroonsBuilder;

module.exports = {
  addPublicKey3rdPartyCaveat:  function (serializedMac, location, caveatKey, thirdPartyMessage, publicKeyPem) {
    debugger 
    var messageWithCaveat = "caveat_key = " + caveatKey + "\n" + "message = " + thirdPartyMessage + "\n";
    var key = new NodeRSA();
    key.importKey(publicKeyPem);
    var encryptedIdentifier = key.encrypt(messageWithCaveat, 'base64');
    
    return {
      macaroon: MacaroonsBuilder.modify(deserializeFn(serializedMac))
        .add_third_party_caveat(location, caveatKey, "enc = " + encryptedIdentifier)
        .getMacaroon()
        .serialize(),
      discharge: encryptedIdentifier
    };
  }
};
'use strict';

var MacaroonsBuilder = require('macaroons.js').MacaroonsBuilder,
  NodeRSA = require('node-rsa');

module.exports = {
  addPublicKey3rdPartyCaveat:  function (mac, location, caveatKey, thirdPartyMessage, publicKeyPem) {
    var messageWithCaveat = "caveat_key = " + caveatKey + "\n" + "message = " + thirdPartyMessage + "\n";
    var key = new NodeRSA();
    key.importKey(publicKeyPem);
    var encryptedIdentifier = key.encrypt(messageWithCaveat, 'base64');
    
    return {
      macaroon: MacaroonsBuilder.modify(mac)
        .add_third_party_caveat(location, caveatKey, "enc = " + encryptedIdentifier)
        .getMacaroon()
        .serialize(),
      discharge: encryptedIdentifier
    };
  }
};
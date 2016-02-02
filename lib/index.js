'use strict';

var macaroons = require('node-macaroons'),
  NodeRSA = require('node-rsa');

module.exports = {
  addPublicKey3rdPartyCaveat:  function (mac, location, caveatKey, thirdPartyMessage, publicKeyPem) {
    var messageWithCaveat = "caveat_key = " + caveatKey + "\n" + "message = " + thirdPartyMessage + "\n";
    var key = new NodeRSA();
    key.importKey(publicKeyPem);
    var encryptedIdentifier = key.encrypt(messageWithCaveat, 'base64');

    return {
      macaroon: macaroons.serialize(mac.addThirdPartyCaveat(caveatKey, "enc = " + encryptedIdentifier, location)),
      discharge: encryptedIdentifier
    };
  }
};
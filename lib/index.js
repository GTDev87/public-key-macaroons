'use strict';

var macaroons = require('macaroons.js'),
  ursa = require('ursa'),
  deserializeFn = macaroons.MacaroonsBuilder.deserialize,
  MacaroonsBuilder = macaroons.MacaroonsBuilder;

module.exports = {
  addPublicKey3rdPartyCaveat:  function (serializedMac, location, caveatKey, thirdPartyMessage, publicKeyPem) {
    var messageWithCaveat = "caveat_key = " + caveatKey + "\n" + "message = " + thirdPartyMessage + "\n";
    var encryptedIdentifier =  ursa.createPublicKey(publicKeyPem).encrypt(messageWithCaveat, 'utf8', 'base64');
    
    return {
      macaroon: MacaroonsBuilder.modify(deserializeFn(serializedMac))
        .add_third_party_caveat(location, caveatKey, "enc = " + encryptedIdentifier)
        .getMacaroon()
        .serialize(),
      discharge: encryptedIdentifier
    };
  }
};
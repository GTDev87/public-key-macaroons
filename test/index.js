'use strict';

var expect = require('chai').expect, 
  macaroons = require('macaroons.js'),
  _ = require("lodash"),
  fs = require('fs'),
  ursa = require('ursa'),
  MacaroonsBuilder = macaroons.MacaroonsBuilder,
  deserializeFn = MacaroonsBuilder.deserialize,
  publicKeyMacaroons = require('../lib');

describe("public-key-macaroons", function () {
  describe("third party caveats", function() {

    var fooPublicKeyPem = fs.readFileSync(__dirname + "/pem/foo.pub.pem", "utf8");
    var fooPrivateKeyPem = fs.readFileSync(__dirname + "/pem/foo.priv.pem", "utf8");
    var serializedMac = new MacaroonsBuilder("thing1.com", "my secret", "identifier")
      .getMacaroon()
      .serialize();

    it("bind encrypted third party caveat", function () {
      var caveatKey = "my caveat secret";
      var message = "account = 11238";
      var actualMessage = "caveat_key = " + caveatKey + "\n" + "message = " + message + "\n";

      var macAndDischarge = publicKeyMacaroons.addPublicKey3rdPartyCaveat(serializedMac, "thing2.com", caveatKey, message, fooPublicKeyPem);

      var inspectedMac = deserializeFn(macAndDischarge.macaroon).inspect();
      var lineWithEncoding = _.find(inspectedMac.split("\n"), function (line) {return line.indexOf("cid enc = ") !== -1; });
      var encoding = lineWithEncoding.split("cid enc = ")[1];

      expect(ursa.createPrivateKey(fooPrivateKeyPem).decrypt(encoding, 'base64', 'utf8')).to.equal(actualMessage);
    });

    it("discharge valid", function () {
      var caveatKey = "my caveat secret";
      var message = "account = 11238";
      var actualMessage = "caveat_key = " + caveatKey + "\n" + "message = " + message + "\n";
      var macAndDischarge = publicKeyMacaroons.addPublicKey3rdPartyCaveat(serializedMac, "thing2.com", caveatKey, message, fooPublicKeyPem);

      var encryptedDischarge = macAndDischarge.discharge;
      console.log("encryptedDischarge = %j", encryptedDischarge);

      expect(ursa.createPrivateKey(fooPrivateKeyPem).decrypt(encryptedDischarge, 'base64', 'utf8')).to.equal(actualMessage);
    });
  });
});

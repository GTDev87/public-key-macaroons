'use strict';

var expect = require('chai').expect, 
  macaroons = require('node-macaroons'),
  _ = require("lodash"),
  Buffer = require("buffer"),
  fs = require('fs'),
  NodeRSA = require('node-rsa'),
  // MacaroonsBuilder = macaroons.MacaroonsBuilder,
  // deserializeFn = MacaroonsBuilder.deserialize,
  publicKeyMacaroons = require('../lib');

describe("public-key-macaroons", function () {
  describe("third party caveats", function() {

    var fooPublicKeyPem = fs.readFileSync(__dirname + "/pem/foo.pub.pem", "utf8");
    var fooPrivateKeyPem = fs.readFileSync(__dirname + "/pem/foo.priv.pem", "utf8");

    var deserializedMac = macaroons.newMacaroon("my secret", "identifier", "thing1.com");

    describe("bound macaroon", function () {
      it("bind encrypted third party caveat", function () {

        var caveatKey = "my caveat secret";
        var message = "account = 11238";
        var actualMessage = "caveat_key = " + caveatKey + "\n" + "message = " + message + "\n";

        var macAndDischarge = publicKeyMacaroons.addPublicKey3rdPartyCaveat(deserializedMac, "thing2.com", caveatKey, message, fooPublicKeyPem);

        var cavWithEncoding = _.find(macAndDischarge.getCaveats(), function (cav) { return cav._identifier.indexOf("enc = ") !== -1; });
        var encoding = cavWithEncoding._identifier.split("enc = ")[1];

        var key = new NodeRSA();
        key.importKey(fooPrivateKeyPem);

        expect(key.decrypt(encoding).toString('utf8')).to.equal(actualMessage);
      });
    });
  });
});

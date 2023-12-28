import {secp256r1} from "@noble/curves/p256";
import crypto from "crypto";
import {toBuffer, formatHex} from "../src/utils";
import {ethers} from "ethers";
import * as asn1 from "asn1.js";
import BN from "bn.js";

const EcdsaSigAsnParse: {
  decode: (asnStringBuffer: Buffer, format: "der") => { r: BN; s: BN };
} = asn1.define("EcdsaSig", function(this: any) {
  // eslint-disable-next-line no-invalid-this
  this.seq().obj(this.key("r").int(), this.key("s").int());
});

const obj = {
  "clientDataJson": "{\"type\":\"webauthn.get\",\"challenge\":\"YVhWYmJBbCtRbHNnVDVmZTY5TlhpeHFtSGhZR1dyMmtQbDB0V2xUQnExRT0\",\"origin\":\"http://localhost:3000\",\"crossOrigin\":false}",
  "signature": "0x30450220346e732283df559379544ac5dcf4750dc4a86a7c06bd89868cd8815eba745301022100e52efea59cd07d4e6333d6cca1809a0d9af24d687f842f60461ae24ae6b0c9df",
  "authData": "0x49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000",
  "passkey": {
    "id": "xEsa5na2J4rQlgC954wmU404Uoo",
    "x": "0x33d40965477929bca0c8f624977a731ea3f21ac238339615545c957d0318bbf3",
    "y": "0x8932ece81514ca6d123690eb1559e898606bdc52a46f97bf06301bcff23c1c67"
  },
};

const verify = () => {
  const clientDataHash = crypto
      .createHash("sha256")
      .update(obj.clientDataJson)
      .digest();
  const authData32 = toBuffer(obj.authData).subarray(0, 32);
  console.log(authData32);
  const signedData = Buffer.concat([
    authData32,
    clientDataHash,
  ]);

  const signedData2 = Buffer.concat([
    toBuffer(obj.authData),
    clientDataHash,
  ]);
  const signedDataHash = crypto
      .createHash("sha256")
      .update(signedData2)
      .digest("hex");
  const uncompressedPubKey = ethers.solidityPacked(
      ["uint8", "uint256", "uint256"],
      [4, formatHex(obj.passkey.x), formatHex(obj.passkey.y)]
  );

  const decoded = EcdsaSigAsnParse.decode(toBuffer(obj.signature), "der");
  const newDecoded = {
    r: BigInt("0x" + decoded.r.toString("hex")),
    s: BigInt("0x" + decoded.s.toString("hex")),
  };
  if (
    !secp256r1.verify(
        newDecoded,
        signedDataHash,
        uncompressedPubKey.slice(2) // remove "0x"
    )
  ) {
    console.log("wrong2");
  }

  if (
    !secp256r1.verify(
        newDecoded,
        signedData,
        uncompressedPubKey.slice(2) // remove "0x"
    )
  ) {
    console.log("wrong");
  }
};

verify();



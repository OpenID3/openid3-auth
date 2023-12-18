import {secp256r1} from "@noble/curves/p256";
import {PrivateKey} from "eciesjs";
import crypto from "crypto";
import {ethers} from "ethers";

export interface Key {
    privKey: Uint8Array | Buffer,
    pubKey: {x: string, y: string},
}

export const genPasskey = (id: string): any => {
  const privKey = secp256r1.utils.randomPrivateKey();
  const pubKey = secp256r1.getPublicKey(privKey);
  const point = secp256r1.ProjectivePoint.fromHex(pubKey);
  const x = ethers.solidityPacked(["uint256"], [point.x]).slice(2);
  const y = ethers.solidityPacked(["uint256"], [point.y]).slice(2);
  return {privKey, pubKey: {x, y, id}};
};

export const signWithPasskey = (
    challenge: any,
    origin: string,
    passkey: any,
) => {
  const clientDataJson = JSON.stringify({
    challenge,
    origin,
    somekey: "somevalue",
  });
  const clientDataHash = crypto.createHash("sha256")
      .update(clientDataJson)
      .digest();
  const authData = Buffer.concat([
    Buffer.from(passkey.pubKey.x),
    Buffer.from(passkey.pubKey.y),
    // sha256("somerandomdata")
    Buffer.from("dbdffb426fe23336753b7ccc6ced25bafea6616c92e8922a3d857d95cf30d4f0", "hex"),
  ]);
  const signedData = Buffer.concat([
    authData,
    clientDataHash,
  ]);
  const signedDataHash = crypto.createHash("sha256")
      .update(signedData)
      .digest("hex");
  const signature = secp256r1.sign(signedDataHash, passkey.privKey);
  return {
    clientDataJson,
    authData: authData.toString("hex"),
    signature,
  };
};

export const signRegisterRequest = (
    username: string,
    origin: string,
    passkey: any,
    operator: string,
    metadata: string,
    salt: string,
) => {
  const challenge = crypto.createHash("sha256").update(
      Buffer.concat([
        Buffer.from("register", "utf-8"), // action
        Buffer.from(username, "utf-8"), // username
        Buffer.from(operator, "hex"), // operator
        Buffer.from(metadata, "hex"), // metadata
        Buffer.from(salt, "hex"), // salt
      ])
  ).digest("base64");
  return signWithPasskey(challenge, origin, passkey);
};

export const signLoginRequest = (
    address: string,
    origin: string,
    challenge: string,
    passkey: any,
    encryptedSalt?: string, // ciphertext
    newSalt?: string, // plaintext
) => {
  const signedChallenge = crypto.createHash("sha256").update(
      Buffer.concat([
        Buffer.from("login", "utf-8"), // action
        Buffer.from(address, "hex"), // address
        Buffer.from(challenge, "hex"), // challenge
        Buffer.from(newSalt ?? ethers.ZeroHash, "hex"), // new salt
        Buffer.from(encryptedSalt ?? "", "utf-8"), // salt
      ])
  ).digest("base64");
  return signWithPasskey(signedChallenge, origin, passkey);
};

export const genEciesKey = () => {
  const privKey = new PrivateKey();
  return {
    privKey,
    pubKey: privKey.publicKey.toHex(),
  };
};

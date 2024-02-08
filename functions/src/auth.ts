import cors from "cors";
import * as functions from "firebase-functions";
import crypto from "crypto";
import { secp256r1 } from "@noble/curves/p256";
import { ethers } from "ethers";

import { ServerError, epoch, formatHex, handleError, toBuffer } from "./utils";
import {
  decryptWithSymmKey,
  encryptWithSymmKey,
  getPublicKeyPemRsa,
  signAsymmetricRsa,
} from "./gcloudKms";
import { getChallengeRateLimit, registerRateLimit } from "./ratelimiter";
import { registerUser, getAuth, postAuth } from "./db/user";
import { genRegistrationInfo, getAccountAddress } from "./account";
import * as asn1 from "asn1.js";
import BN from "bn.js";
import base64url from "base64url";
import { Server } from "http";

const secrets = functions.config().doppler || {};
const SESSION_TTL = 3600 * 24;

/**
 * req.body: {
 *  mizuname: string,
 *  factory: string,
 *  operator: string,
 *  passkey: {
 *    id: string,
 *    x: string,
 *    y: string,
 *  },
 *  profile: {
 *    name: string,
 *    about: string,
 *    avatar: string,
 *    nostrPubkey: string,
 *    relays: string[],
 *    mizuname: string,
 *  },
 *  dek: string,
 *  invitationCode: string,
 * }
 *
 * res: {
 *   token: string,
 *   address: string,
 *   csrfToken: string,
 *   encDek: string,
 * }
 */
export const registerUserWithPasskey = functions.https.onRequest((req, res) => {
  return cors({ origin: [secrets.REACT_APP_ORIGIN], credentials: true })(
    req,
    res,
    async () => {
      try {
        if (secrets.ENV !== "dev" && (await registerRateLimit(req.ip || ""))) {
          throw new ServerError(429, "Too many requests");
        }
        const registrationInfo = genRegistrationInfo(
          req.body.mizuname,
          req.body.passkey,
          req.body.factory,
          req.body.operator
        );
        const namehash = ethers.namehash(req.body.mizuname);
        const address = await getAccountAddress(registrationInfo);
        const [, encDek] = await Promise.all([
          registerUser(
            address,
            namehash,
            req.body.passkey,
            registrationInfo,
            req.body.profile,
            req.body.invitationCode
          ),
          encryptWithSymmKey(req.body.dek, toBuffer(address)),
        ]);
        res.status(200).json({ address, encDek, registrationInfo });
      } catch (err: unknown) {
        handleError(res, err);
      }
    }
  );
});

/*
 * req.body: {
 *   auth?: {
 *     address: string,
 *     clientDataJson: string,
 *     authData: string, // hex
 *     signature: string, // hex
 *   },
 *   message?: string,
 *   encDek: string, // to decrypt
 *   newDek: string, // to encrypt
 * }
 *
 * res: {
 *   signature?: string,
 *   kek: string, // decrypted
 *   encNewDek: string, // encrypted
 * }
 */
export const signAndRotateKek = functions.https.onRequest((req, res) => {
  cors({ origin: [secrets.REACT_APP_ORIGIN], credentials: true })(
    req,
    res,
    async () => {
      let address;
      try {
        if (req.body.message && !req.body.auth) {
          throw new ServerError(400, "auth required");
        }

        if (req.body.auth) {
          address = ethers.getAddress(req.body.auth.address);
          const auth = await getAuth(address);
          if (!auth) {
            throw new ServerError(404, "User not found");
          }
          const challenge = crypto
            .createHash("sha256")
            .update(
              Buffer.concat([
                Buffer.from("login", "utf-8"), // action
                toBuffer(address), // address
                toBuffer(ethers.solidityPacked(["bytes32"], [auth.nonce])), // challenge
                Buffer.from(req.body.encDek ?? "", "utf-8"), // encrypted dek
                toBuffer(req.body.newDek ?? ethers.ZeroHash), // new dek
              ])
            )
            .digest("base64");
          validatePasskeySignature(
            req.body.clientDataJson,
            [
              ["challenge", challenge],
              ["origin", secrets.REACT_APP_ORIGIN],
            ],
            req.body.authData,
            req.body.signature,
            auth.passkey
          );
        } else {
          address = await verifyIdToken(req.body.auth);
        }

        const aad = toBuffer(address);
        const [, dek, encNewDek, token] = await Promise.all([
          postAuth(address),
          decryptWithSymmKey(req.body.encDek, aad),
          encryptWithSymmKey(req.body.newDek, aad),
          signJwt(address, SESSION_TTL),
        ]);
        res.status(200).json({ token, dek, encNewDek });
      } catch (err: unknown) {
        handleError(res, err);
      }
    }
  );
});

/**
 * req.body: {
 *   address: string,
 * }
 *
 * res: {
 *   challenge: string, // hex
 * }
 */
export const getNonce = functions.https.onRequest((req, res) => {
  cors({ origin: [secrets.REACT_APP_ORIGIN], credentials: true })(
    req,
    res,
    async () => {
      try {
        if (
          secrets.ENV !== "dev" &&
          (await getChallengeRateLimit(req.ip || ""))
        ) {
          throw new ServerError(429, "Too many requests");
        }
        const address = ethers.getAddress(req.body.address);
        const auth = await getAuth(address);
        if (auth == null) {
          throw new ServerError(404, "User not found");
        }
        res.status(200).json({ nonce: auth.nonce });
      } catch (err: unknown) {
        handleError(res, err);
      }
    }
  );
});

const verifyIdToken = async (req: functions.https.Request) => {
  const token = req.headers.authorization?.split("Bearer ")[1];
  if (!token) {
    throw new ServerError(401, "UNAUTHORIZED REQUEST");
  }
  return verifyJwt(token);
};

const EcdsaSigAsnParse: {
  decode: (asnStringBuffer: Buffer, format: "der") => { r: BN; s: BN };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any, space-before-function-paren
} = asn1.define("EcdsaSig", function (this: any) {
  // eslint-disable-next-line no-invalid-this
  this.seq().obj(this.key("r").int(), this.key("s").int());
});

const validatePasskeySignature = (
  clientDataJson: string,
  expected: string[][],
  authData: string, // hex
  signature: string, // hex
  pubKey: { x: string; y: string } // hex
) => {
  const parsed = JSON.parse(clientDataJson);
  for (const [key, value] of expected) {
    if (parsed[key] !== value) {
      if (key === "challenge") {
        const decodedChallenge = Buffer.from(parsed[key], "base64").toString(
          "utf-8"
        );
        if (decodedChallenge !== value) {
          throw new ServerError(400, "invalid client data");
        }
      } else {
        if (parsed[key] !== value) {
          throw new ServerError(400, "invalid client data");
        }
      }
    }
  }

  const clientDataHash = crypto
    .createHash("sha256")
    .update(clientDataJson)
    .digest();
  const signedData = Buffer.concat([toBuffer(authData), clientDataHash]);
  const signedDataHash = crypto
    .createHash("sha256")
    .update(signedData)
    .digest("hex");
  const uncompressedPubKey = ethers.solidityPacked(
    ["uint8", "uint256", "uint256"],
    [4, formatHex(pubKey.x), formatHex(pubKey.y)]
  );
  const decoded = EcdsaSigAsnParse.decode(toBuffer(signature), "der");
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
    throw new ServerError(400, "invalid signature");
  }
};

const signJwt = async (address: string, ttl: number): Promise<string> => {
  const header = base64url(
    JSON.stringify({
      alg: "RS256",
      typ: "JWT",
    })
  );
  const payload = base64url(
    JSON.stringify({
      sub: address,
      iss: secrets.REACT_APP_DOMAIN,
      aud: secrets.REACT_APP_DOMAIN,
      iat: epoch(),
      exp: epoch() + ttl,
    })
  );
  const signature = await signAsymmetricRsa(
    Buffer.from(`${header}.${payload}`)
  );
  return `${header}.${payload}.${base64url.encode(signature)}`;
};

const verifyJwt = async (token: string) => {
  const jwtPubPem = await getPublicKeyPemRsa();
  const [header, payload, signature] = token.split(".");
  const signatureBuffer = Buffer.from(signature, "base64url");
  const verify = crypto.createVerify("RSA-SHA256");
  verify.update(`${header}.${payload}`);
  if (
    !verify.verify(
      { key: jwtPubPem, padding: crypto.constants.RSA_PKCS1_PADDING },
      signatureBuffer
    )
  ) {
    throw new ServerError(401, "invalid jwt signature");
  }
  const parsedHeader = JSON.parse(base64url.decode(header));
  if (parsedHeader.typ !== "JWT" || parsedHeader.alg !== "RS256") {
    throw new ServerError(401, "invalid jwt header");
  }
  const parsedPayload = JSON.parse(base64url.decode(payload));
  if (parsedPayload.exp < epoch()) {
    throw new ServerError(401, "token expired");
  }
  if (
    parsedPayload.iss !== secrets.REACT_APP_DOMAIN ||
    parsedPayload.sub === undefined
  ) {
    throw new ServerError(401, "invalid jwt payload");
  }
  return parsedPayload.sub as string;
};

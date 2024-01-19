import cors from "cors";
import * as functions from "firebase-functions";
import * as admin from "firebase-admin";
import crypto from "crypto";
import { secp256r1 } from "@noble/curves/p256";
import { ethers } from "ethers";

import {
  ServerError,
  epoch,
  formatHex,
  genNameHash,
  handleError,
  toBuffer,
} from "./utils";
import {
  decryptWithSymmKey,
  encryptWithSymmKey,
} from "./gcloudKms";
import {
  getChallengeRateLimit,
  registerRateLimit,
  verifyPinRateLimit,
} from "./ratelimiter";
import { registerUser, getAuth, postAuth, preAuth, setPin } from "./db/auth";
import { getAccountAddress } from "./account";
import * as asn1 from "asn1.js";
import BN from "bn.js";

const secrets = functions.config().doppler || {};

/**
 * req.body: {
 *  username: string,
 *  factory: string,
 *  operator: string,
 *  metadata: string,
 *  pin: string,
 *  passkey: {
 *    id: string,
 *    x: string,
 *    y: string,
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
        const address = await getAccountAddress(req.body);
        const nameHash = genNameHash(req.body.username);
        const [, encDek, token] = await Promise.all([
          registerUser(nameHash, address, req.body),
          encryptWithSymmKey(req.body.dek, toBuffer(address)),
          admin.auth().createCustomToken(address),
        ]);
        res.status(200).json({ token, address, encDek });
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
export const getPasskeyChallenge = functions.https.onRequest((req, res) => {
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
        if (auth.challenge && auth.updatedAt.seconds + 180 > epoch()) {
          res.status(200).json({ challenge: auth.challenge });
        } else {
          const challenge = crypto.randomBytes(32).toString("hex");
          await preAuth(address, challenge);
          res.status(200).json({ challenge });
        }
      } catch (err: unknown) {
        handleError(res, err);
      }
    }
  );
});

/*
 * req.body: {
 *   address: string,
 *   clientDataJson: string,
 *   authData: string, // hex
 *   signature: string, // hex
 *   encDek?: string, // to decrypt
 *   newDek?: string, // to encrypt
 * }
 *
 * res: {
 *   token: string,
 *   dek?: string, // decrypted
 *   encNewDek?: string, // encrypted
 * }
 */
export const loginWithPasskey = functions.https.onRequest((req, res) => {
  cors({ origin: [secrets.REACT_APP_ORIGIN], credentials: true })(
    req,
    res,
    async () => {
      try {
        const address = ethers.getAddress(req.body.address);
        const auth = await getAuth(address);
        if (!auth?.challenge) {
          throw new ServerError(404, "User not found or challenge not set");
        }
        if (auth.updatedAt.seconds + 180 < epoch()) {
          throw new ServerError(403, "invalid challenge");
        }
        const challenge = crypto
          .createHash("sha256")
          .update(
            Buffer.concat([
              Buffer.from("login", "utf-8"), // action
              toBuffer(address), // address
              toBuffer(auth.challenge), // challenge
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
        const aad = toBuffer(address);
        const [, dek, encNewDek, token] = await Promise.all([
          postAuth(address),
          decryptWithSymmKey(req.body.encDek, aad),
          encryptWithSymmKey(req.body.newDek, aad),
          admin.auth().createCustomToken(address),
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
 *   clientDataJson: string,
 *   authData: string, // hex
 *   signature: string, // hex
 *   encDek: string, // to decrypt
 *   newDek?: string, // to encrypt
 * }
 *
 * res: {
 *   dek: string, // decrypted
 *   encNewDek?: string, // encrypted
 * }
 */
export const getDeks = functions.https.onRequest((req, res) => {
  cors({ origin: [secrets.REACT_APP_ORIGIN], credentials: true })(
    req,
    res,
    async () => {
      try {
        const uid = await verifyIdToken(req);
        const auth = await getAuth(uid);
        if (!auth) {
          throw new ServerError(404, "User not found");
        }
        const challenge = crypto
          .createHash("sha256")
          .update(
            Buffer.concat([
              Buffer.from("getDeks", "utf-8"), // action
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
        const aad = toBuffer(uid);
        const [dek, encNewDek] = await Promise.all([
          decryptWithSymmKey(req.body.encDek, aad),
          encryptWithSymmKey(req.body.newDek, aad),
        ]);
        res.status(200).json({ dek, encNewDek });
      } catch (err: unknown) {
        handleError(res, err);
      }
    }
  );
});

/**
 * req.body: {
*    pin: string,
 *   encDek: string, // to decrypt
 *   newDek?: string, // to encrypt
 * }
 *
 * res: {
 *   dek: string, // decrypted
 *   encNewDek?: string, // encrypted
 * }
 */
export const getDeksWithPin = functions.https.onRequest((req, res) => {
  cors({ origin: [secrets.REACT_APP_ORIGIN], credentials: true })(
    req,
    res,
    async () => {
      try {
        const uid = await authenticateWithPin(req, req.body.pin);
        const aad = toBuffer(uid);
        const [dek, encNewDek] = await Promise.all([
          decryptWithSymmKey(req.body.encDek, aad),
          encryptWithSymmKey(req.body.newDek, aad),
        ]);
        res.status(200).json({ dek, encNewDek });
      } catch (err: unknown) {
        handleError(res, err);
      }
    }
  );
});

/**
 * req.body: {
 *   pin: string,
 *   newPin: string,
 * }
 *
 * res: {
 *   success: boolean,
 * }
 */
export const updatePin = functions.https.onRequest((req, res) => {
  cors({ origin: [secrets.REACT_APP_ORIGIN], credentials: true })(
    req,
    res,
    async () => {
      try {
        const uid = await authenticateWithPin(req, req.body.pin);
        await setPin(uid, req.body.newPin);
        res.status(200).json({ success: true });
      } catch (err: unknown) {
        handleError(res, err);
      }
    }
  );
});

/**
 * req.body: {
 *   newPin: string,
 *   clientDataJson: string,
 *   authData: string, // hex
 *   signature: string, // hex
 * }
 *
 * res: {
 *   success: boolean,
 * }
 */
export const resetPin = functions.https.onRequest((req, res) => {
  cors({ origin: [secrets.REACT_APP_ORIGIN], credentials: true })(
    req,
    res,
    async () => {
      try {
        const uid = await verifyIdToken(req);
        const auth = await getAuth(uid);
        if (!auth) {
          throw new ServerError(404, "User not found");
        }
        const challenge = crypto
          .createHash("sha256")
          .update(
            Buffer.concat([
              Buffer.from("resetPin", "utf-8"), // action
              toBuffer(uid), // address
              toBuffer(req.body.newPin), // new pin
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
        await setPin(uid, req.body.newPin);
        res.status(200).json({ success: true });
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
  const decoded = await admin.auth().verifyIdToken(token);
  return decoded.uid;
};

const authenticateWithPin = async (
  req: functions.https.Request,
  pin: string
) => {
  const uid = await verifyIdToken(req);
  const auth = await getAuth(uid);
  if (await verifyPinRateLimit(uid, true)) {
    throw new ServerError(429, "Too many requests");
  }
  if (pin !== auth?.pin) {
    await verifyPinRateLimit(uid, false);
    throw new ServerError(401, "UNAUTHORIZED REQUEST");
  }
  return uid;
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

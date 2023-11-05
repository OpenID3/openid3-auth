import cors from "cors";
import * as functions from "firebase-functions";
import * as admin from "firebase-admin";
import crypto from "crypto";
import {secp256r1} from "@noble/curves/p256";
import { encrypt } from 'eciesjs'

import {
  HexlinkError,
  epoch,
  handleError,
} from "./utils";
import {decryptWithSymmKey, encryptWithSymmKey} from "./gcloudKms";
import { getChallengeRateLimit, registerRateLimit } from "./ratelimiter";
import { createUser, genNameHash, getUser, postAuth, preAuth, rotateDek } from "./user";

const secrets = functions.config().doppler || {};

/**
 * req.body: {
 *  username: string,
 *  passkey: string, // hex
 *  kek: string, // hex
 *  clientDataJson: string,
 *  authData: string, // hex
 *  signature: string, // hex
 * }
 * 
 * res: {
 *   token: string,
 *   dek: string, // base64
 * }
 */
export const registerUserWithPasskey = functions.https.onRequest((req, res) => {
  return cors({origin: true})(req, res, async () => {
    try {
      if (secrets.ENV !== "dev" && await registerRateLimit(req.ip || "")) {
        throw new HexlinkError(429, "Too many requests");
      }
      const challenge = crypto.createHash("sha256").update(
          JSON.stringify({
            action: "register",
            uid: req.body.username,
            kek: req.body.kek,
          })
      ).digest("hex");
      validatePasskeySignature(
          req.body.clientDataJson,
          [
            ["challenge", challenge],
            ["origin", "https://openid3.org"],
          ],
          req.body.authData,
          req.body.signature,
          req.body.passkey,
      );
      const newDek = crypto.randomBytes(32).toString("hex");
      const newDekClientEncrypted = encrypt(req.body.kek, Buffer.from(newDek));
      const newDekServerEncrypted = await encryptWithSymmKey(newDek);
      const uid = genNameHash(req.body.username);
      await createUser(
        uid,
        req.body.passkey,
        newDekServerEncrypted);
      await admin.auth().createUser({uid});
      const token = await admin.auth().createCustomToken(uid);
      res.status(200).json({
        token: token,
        dek: newDekClientEncrypted.toString("hex")
      });
    } catch (err: unknown) {
      handleError(res, err);
    }
  });
});

export const getPasskeyChallenge = functions.https.onRequest((req, res) => {
  cors({origin: true})(req, res, async () => {
    try {
      if (secrets.ENV !== "dev" && await getChallengeRateLimit(req.ip || "")) {
        throw new HexlinkError(429, "Too many requests");
      }
      const user = await getUser(req.body.uid);
      if (user == null) {
        throw new HexlinkError(404, "User not found");
      }
      if (user.loginStatus.step === "challenge"
        && user.loginStatus.updatedAt.seconds + 180 > epoch()) {
        res.status(200).json({challenge: user.loginStatus.challenge});
      } else {
        const challenge = crypto.randomBytes(32).toString("hex");
        await preAuth(req.body.uid, challenge);
        res.status(200).json({challenge});
      }
    } catch (err: unknown) {
      handleError(res, err);
    }
  });
});

export const loginWithPasskey = functions.https.onRequest((req, res) => {
  cors({origin: true})(req, res, async () => {
    try {
      const user = await getUser(req.body.uid);
      if (user == null) {
        throw new HexlinkError(404, "User not found");
      }
      if (user.loginStatus.challenge.length > 0
          && user.loginStatus.updatedAt.seconds + 180 < epoch()) {
        throw new HexlinkError(403, "invalid challenge");
      }
      const challenge = crypto.createHash("sha256").update(
          JSON.stringify({
            action: "login",
            uid: req.body.uid,
            challenge: user.loginStatus.challenge,
          })
      ).digest("hex");
      validatePasskeySignature(
          req.body.clientDataJson,
          [
            ["challenge", challenge],
            ["origin", "https://dev.hexlink.io"],
          ],
          req.body.authData,
          req.body.signature,
          user.passkey,
      );
      await postAuth(req.body.uid);
      const token = admin.auth().createCustomToken(req.body.uid);
      res.status(200).json({token: token});
    } catch (err: unknown) {
      handleError(res, err);
    }
  });
});

export const getDataEncryptionKey = functions.https.onRequest((req, res) => {
  cors({origin: true})(req, res, async () => {
    try {
      const decoded = await admin.auth().verifyIdToken(extractIdToken(req));
      const user = await getUser(decoded.uid);
      if (user == null) {
        throw new HexlinkError(404, "User not found");
      }
      for (const dekServerEncrypted of user.deks) {
        const decryptedDek = await decryptWithSymmKey(dekServerEncrypted);
        const dekClientEncrypted = encrypt(
          req.body.kek, Buffer.from(decryptedDek));
        const keyId = crypto.createHash(decryptedDek).update("sha256").digest("hex");
        if (keyId === req.body.keyId) {
          const newDek = crypto.randomBytes(32).toString("hex");
          const newDekServerEncrypted = await encryptWithSymmKey(newDek);
          const newDekClientEncrypted = encrypt(
            req.body.kek, Buffer.from(newDek));
          await rotateDek(decoded.uid, dekServerEncrypted, newDekServerEncrypted);
          res.status(200).json({
            dek: dekClientEncrypted.toString("hex"),
            newDek: newDekClientEncrypted.toString("hex")
          });
          return;
        }
      }
      throw new HexlinkError(404, "Key not found");
    } catch (err: unknown) {
      handleError(res, err);
    }
  });
});

const extractIdToken = (req: functions.Request) => {
  if ((!req.headers.authorization || !req.headers.authorization.startsWith("Bearer ")) &&
      !(req.cookies && req.cookies.__session)) {
    functions.logger.error(
        "No Firebase ID token was passed as a Bearer token in the Authorization header.",
        "Make sure you authorize your request by providing the following HTTP header:",
        "Authorization: Bearer <Firebase ID Token>",
        "or by passing a \"__session\" cookie."
    );
    throw new HexlinkError(403, "Unauthorized");
  }
  if (req.headers.authorization && req.headers.authorization.startsWith("Bearer ")) {
    return req.headers.authorization.split("Bearer ")[1];
  } else if (req.cookies) {
    return req.cookies.__session;
  } else {
    throw new HexlinkError(403, "Unauthorized");
  }
};

const validatePasskeySignature = (
    clientDataJson: string,
    expected: string[][],
    authData: string, // hex
    signature: string, // hex
    pubKey: string, // hex
) => {
  const parsed = JSON.parse(clientDataJson);
  for (const [key, value] of expected) {
    if (parsed[key] !== value) {
      throw new HexlinkError(400, "Invalid client data");
    }
  }

  const clientDataHash = crypto.createHash("sha256")
      .update(clientDataJson)
      .digest();
  const signedData = Buffer.concat([
    Buffer.from(authData, "hex"),
    clientDataHash,
  ]);
  const signedDataHash = crypto.createHash("sha256")
      .update(signedData)
      .digest("hex");
  if (!secp256r1.verify(Buffer.from(signature, "hex"), signedDataHash, pubKey)) {
    throw new HexlinkError(400, "Invalid signature");
  }
};

import cors from "cors";
import {
  HexlinkError,
  epoch,
  handleError,
} from "./utils";
import * as functions from "firebase-functions";
import {Firebase} from "./firebase";
import {Firestore, Timestamp} from "firebase-admin/firestore";
import {decryptWithSymmKey, encryptWithSymmKey} from "./gcloudKms";
import crypto from "crypto";
import {secp256r1} from "@noble/curves/p256";
import ecccrypto from "eccrypto";
import {ethers} from "ethers";
import { getChallengeRateLimit, registerRateLimit } from "./ratelimiter";

const secrets = functions.config().doppler || {};

export const registerUserWithPasskey = functions.https.onRequest((req, res) => {
  cors({origin: true})(req, res, async () => {
    try {
      const firebase = Firebase.getInstance();
      if (secrets.ENV !== "dev" && await registerRateLimit(req.ip || "")) {
        throw new HexlinkError(429, "Too many requests");
      }
      const user = await getUser(firebase.db, req.body.uid);
      if (user != null) {
        throw new HexlinkError(400, "User already exists");
      }
      const challenge = crypto.createHash("sha256").update(
          JSON.stringify({
            action: "register",
            uid: req.body.uid,
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
          req.body.passkey,
      );
      await firebase.auth.createUser({uid: req.body.uid});
      const dek = crypto.randomBytes(32).toString("hex");
      const encryptedDek = ecccrypto.encrypt(req.body.kek, Buffer.from(dek));
      await firebase.db.collection("users").doc(req.body.uid).set({
        passkey: req.body.passkey,
        dek: await encryptWithSymmKey(dek),
        createdAt: new Timestamp(epoch(), 0),
        loginStatus: {
          challenge: "",
          updatedAt: new Timestamp(epoch(), 0),
        },
      });
      const token = firebase.auth.createCustomToken(req.body.uid);
      res.status(200).json({token: token, dek: encryptedDek});
    } catch (err: unknown) {
      handleError(res, err);
    }
  });
});

export const getChallenge = functions.https.onRequest((req, res) => {
  cors({origin: true})(req, res, async () => {
    try {
      const firebase = Firebase.getInstance();
      if (secrets.ENV !== "dev" && await getChallengeRateLimit(req.ip || "")) {
        throw new HexlinkError(429, "Too many requests");
      }
      const user = await getUser(firebase.db, req.body.uid);
      if (user == null) {
        throw new HexlinkError(404, "User not found");
      }
      const challenge = crypto.randomBytes(32).toString("hex");
      await firebase.db.collection("users").doc(req.body.uid).update({
        loginStatus: {
          challenge: challenge,
          updatedAt: new Timestamp(epoch(), 0),
        },
      });
      res.status(200).json({challege: challenge});
    } catch (err: unknown) {
      handleError(res, err);
    }
  });
});

export const loginWithPasskey = functions.https.onRequest((req, res) => {
  cors({origin: true})(req, res, async () => {
    try {
      const firebase = Firebase.getInstance();
      const user = await getUser(firebase.db, req.body.uid);
      if (user == null) {
        throw new HexlinkError(404, "User not found");
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
      await firebase.db.collection("users").doc(req.body.uid).update({
        loginStatus: {
          challenge: "",
          updatedAt: new Timestamp(epoch(), 0),
        },
      });
      const token = firebase.auth.createCustomToken(req.body.uid);
      res.status(200).json({token: token});
    } catch (err: unknown) {
      handleError(res, err);
    }
  });
});

export const getEncryptionKey = functions.https.onRequest((req, res) => {
  cors({origin: true})(req, res, async () => {
    try {
      const firebase = Firebase.getInstance();
      const decoded = await firebase.auth.verifyIdToken(extractIdToken(req));
      const user = await getUser(firebase.db, decoded.uid);
      if (user == null) {
        throw new HexlinkError(404, "User not found");
      }
      const currentDek = await decryptWithSymmKey(user.dek);
      const dek = ecccrypto.encrypt(req.body.kek, Buffer.from(currentDek));
      // rotate dek
      const newDek = crypto.randomBytes(32).toString("hex");
      const nextDek = ecccrypto.encrypt(req.body.kek, Buffer.from(newDek));
      await firebase.db.collection("users").doc(decoded.uid).update({
        dek: await encryptWithSymmKey(newDek),
      });
      res.status(200).json({dek, nextDek});
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
      throw new HexlinkError(403, "Invalid client data");
    }
  }
  const clientDataHash = crypto.createHash("sha256")
      .update(clientDataJson)
      .digest("hex");
  const signedDataHex = ethers.solidityPacked(
      ["bytes", "bytes32"],
      [authData, "0x" + clientDataHash]
  );
  const signedDataHash = crypto.createHash("sha256")
      .update(ethers.getBytes(signedDataHex))
      .digest("hex");
  if (!secp256r1.verify(signature, signedDataHash, pubKey)) {
    throw new HexlinkError(403, "Invalid signature");
  }
};

/* Database */

interface User {
    passkey: string; // public key of passkey
    kek: string, // stored at client side to decrypt the dek from server
    dek: string, // stored at server side
    loginStatus: {
        step: "challenge" | "loggedin" | "loggedout",
        challenge: string,
        updatedAt: Timestamp,
    }
    createdAt: Timestamp;
}

async function getUser(
    db: Firestore,
    uid: string,
) : Promise<User | null> {
  const result = await db.collection("users").doc(uid).get();
  if (result && result.exists) {
    return result.data() as User;
  }
  return null;
}

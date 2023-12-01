import cors from "cors";
import * as functions from "firebase-functions";
import * as admin from "firebase-admin";
import crypto from "crypto";
import {secp256r1} from "@noble/curves/p256";
import {encrypt} from "eciesjs";
import {ethers} from "ethers";

import {
  HexlinkError,
  epoch,
  genNameHash,
  handleError,
  sha256,
} from "./utils";
import {decryptWithSymmKey, encryptWithSymmKey} from "./gcloudKms";
import {
  checkNameRateLimit,
  getChallengeRateLimit,
  registerRateLimit,
} from "./ratelimiter";
import {
  User,
  getUser,
  postAuth,
  preAuth,
  registerUser,
  resolveName,
  updateDeks,
} from "./db";
import {getAccountAddress} from "./account";

const secrets = functions.config().doppler || {};

/**
 * req.body: {
 *   uid: string,
 * }
 *
 * res: {
 *   registered: boolean,
 *   address?: string,
 *   operator?: string,
 *   passkey?: Passkey,
 * }
 */
export const getUserByUid = functions.https.onRequest((req, res) => {
  return cors({origin: true, credentials: true})(req, res, async () => {
    try {
      if (secrets.ENV !== "dev" && await checkNameRateLimit(req.ip || "")) {
        throw new HexlinkError(429, "Too many requests");
      }
      const address = await resolveName(req.body.uid);
      if (!address) {
        res.status(200).json({registered: false});
      } else {
        const user = await getUser(address);
        if (user) {
          res.status(200).json({
            registered: true,
            user: {
              address,
              passkey: user.passkey,
              operatorPubKey: user.operator,
            },
          });
        } else {
          throw new HexlinkError(500, "user data lost");
        }
      }
    } catch (err: unknown) {
      handleError(res, err);
    }
  });
});

/**
 * req.body: {
 *  username: string,
 *  operator: string,
 *  kek: string, // hex
 *  passkey: {
 *    id: string,
 *    pubKeyX: string,
 *    pubKeyY: string,
 *  },
 *  clientDataJson: string,
 *  authData: string, // hex
 *  signature: string, // hex
 * }
 *
 * res: {
 *   address: string,
 *   token: string,
 *   dek: string, // base64
 * }
 */
export const registerUserWithPasskey =
  functions.https.onRequest((req, res) => {
    return cors({origin: true, credentials: true})(req, res, async () => {
      try {
        if (secrets.ENV !== "dev" && await registerRateLimit(req.ip || "")) {
          throw new HexlinkError(429, "Too many requests");
        }
        const uid = genNameHash(req.body.username);
        const address = getAccountAddress(
            req.body.passkey, req.body.operator);
        const challenge = crypto.createHash("sha256").update(
            Buffer.concat([
              Buffer.from("register", "utf-8"), // action
              Buffer.from(req.body.username, "utf-8"), // username
              Buffer.from(req.body.operator, "hex"), // operator
              Buffer.from(req.body.kek, "hex"), // kek
            ])
        ).digest("base64");
        validatePasskeySignature(
            req.body.clientDataJson,
            [
              ["challenge", challenge],
              ["origin", secrets.ORIGIN],
            ],
            req.body.authData,
            req.body.signature,
            req.body.passkey,
        );
        const newDek = crypto.randomBytes(32).toString("hex");
        const dekId = sha256(newDek).toString("hex");
        const newDekClientEncrypted = encrypt(
            req.body.kek, Buffer.from(newDek));
        await registerUser(
            uid,
            address,
            req.body.passkey,
            req.body.operator,
            req.body.kek,
            {[dekId]: await encryptWithSymmKey(newDek)}
        );
        await admin.auth().createUser({uid});
        const token = await admin.auth().createCustomToken(uid);
        res.status(200).json({
          address,
          token: token,
          dek: newDekClientEncrypted.toString("hex"),
        });
      } catch (err: unknown) {
        handleError(res, err);
      }
    });
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
export const getPasskeyChallenge =
  functions.https.onRequest((req, res) => {
    cors({origin: true, credentials: true})(req, res, async () => {
      try {
        if (secrets.ENV !== "dev" && await getChallengeRateLimit(req.ip || "")) {
          throw new HexlinkError(429, "Too many requests");
        }
        const user = await getUser(req.body.address);
        if (user == null) {
          throw new HexlinkError(404, "User not found");
        }
        if (user.loginStatus.challenge.length > 0 &&
        user.loginStatus.updatedAt.seconds + 180 > epoch()) {
          res.status(200).json({challenge: user.loginStatus.challenge});
        } else {
          const challenge = crypto.randomBytes(32).toString("hex");
          await preAuth(req.body.address, challenge);
          res.status(200).json({challenge});
        }
      } catch (err: unknown) {
        handleError(res, err);
      }
    });
  });

/*
 * req.body: {
 *   address: string,
 *   dekId?: string, // optional
 *   kek: string, // hex
 *   clientDataJson: string,
 *   authData: string, // hex
 *   signature: string, // hex
 * }
 *
 * res: {
 *   token: string,
 *   dek: string,
 *   newDek: string,
 * }
 */
export const loginWithPasskey =
  functions.https.onRequest((req, res) => {
    cors({origin: true, credentials: true})(req, res, async () => {
      try {
        const user = await getUser(req.body.address);
        if (user == null) {
          throw new HexlinkError(404, "User not found");
        }
        if (user.loginStatus.challenge.length > 0 &&
          user.loginStatus.updatedAt.seconds + 180 < epoch()) {
          throw new HexlinkError(403, "invalid challenge");
        }
        const challenge = crypto.createHash("sha256").update(
            Buffer.concat([
              Buffer.from("login", "utf-8"), // action
              Buffer.from(req.body.address, "hex"), // address
              Buffer.from(req.body.kek, "hex"), // kek
              Buffer.from(req.body.dekId ?? ethers.ZeroHash.slice(2), "hex"), // dekId
              Buffer.from(user.loginStatus.challenge, "hex"), // challenge
            ])
        ).digest("base64");
        validatePasskeySignature(
            req.body.clientDataJson,
            [
              ["challenge", challenge],
              ["origin", secrets.ORIGIN],
            ],
            req.body.authData,
            req.body.signature,
            user.passkey,
        );
        if (req.body.dekId) {
          const {dek, newDek} = await getAndGenDeks(
              req.body.dekId, req.body.kek, user);
          await postAuth(req.body.address, req.body.kek, {
            [dek.keyId]: dek.server,
            [newDek.keyId]: newDek.server,
          });
          const token = await admin.auth().createCustomToken(
              req.body.address);
          res.status(200).json({
            token: token,
            dek: dek.client,
            newDek: newDek.client,
          });
        } else {
          await postAuth(req.body.address, req.body.kek);
          const token = await admin.auth().createCustomToken(
              req.body.address);
          res.status(200).json({token});
        }
      } catch (err: unknown) {
        handleError(res, err);
      }
    });
  });

/**
 * req.body: {
 *   keyId: string,
 * }
 *
 * res: {
 *   dek: string,
 *   newDek: string,
 * }
 */
export const getDataEncryptionKey =
  functions.https.onRequest((req, res) => {
    cors({origin: true, credentials: true})(req, res, async () => {
      try {
        const firebaseIdToken = extractFirebaseIdToken(req);
        const decoded = await admin.auth().verifyIdToken(firebaseIdToken);
        const user = await getUser(decoded.uid);
        if (user == null) {
          throw new HexlinkError(404, "User not found");
        }
        const {dek, newDek} = await getAndGenDeks(
            req.body.keyId, user.kek, user);
        await updateDeks(
            decoded.uid,
            {
              [dek.keyId]: dek.server,
              [newDek.keyId]: newDek.server,
            }
        );
        res.status(200).json({dek: dek.client, newDek: newDek.client});
      } catch (err: unknown) {
        handleError(res, err);
      }
    });
  });

const getAndGenDeks = async (keyId: string, kek: string, user: User) => {
  const dekServerEncrypted = user.deks[keyId];
  if (!dekServerEncrypted) {
    throw new HexlinkError(404, "Key not found");
  }
  const newDek = crypto.randomBytes(32).toString("hex");
  const [
    decryptedDek, newDekServerEncrypted,
  ] = await Promise.all([
    decryptWithSymmKey(dekServerEncrypted),
    encryptWithSymmKey(newDek),
  ]);
  const keyIdFromDek = sha256(Buffer.from(decryptedDek, "hex"));
  if (keyIdFromDek.toString("hex") !== keyId) {
    throw new HexlinkError(500, "server data corrupted");
  }
  const dekClientEncrypted = encrypt(
      kek, Buffer.from(decryptedDek, "hex"));
  const newKeyId = sha256(Buffer.from(newDek, "hex")).toString("hex");
  const newDekClientEncrypted = encrypt(
      kek, Buffer.from(newDek, "hex"));
  return {
    dek: {
      keyId,
      server: dekServerEncrypted,
      client: dekClientEncrypted.toString("hex"),
    },
    newDek: {
      keyId: newKeyId,
      server: newDekServerEncrypted,
      client: newDekClientEncrypted.toString("hex"),
    },
  };
};

export const extractFirebaseIdToken = (req: functions.Request) => {
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
    pubKey: {x: string, y: string}, // hex
) => {
  const parsed = JSON.parse(clientDataJson);
  for (const [key, value] of expected) {
    if (parsed[key] !== value) {
      if (key === "challenge") {
        const decodedChallenge = Buffer.from(parsed[key], "base64").toString("utf-8");
        if (decodedChallenge !== value) {
          throw new HexlinkError(400, "invalid client data");
        }
      } else {
        if (parsed[key] !== value) {
          throw new HexlinkError(400, "invalid client data");
        }
      }
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
  const uncompressedPubKey = ethers.solidityPacked(
      ["uint8", "uint256", "uint256"],
      [4, "0x" + pubKey.x, "0x" + pubKey.y]
  );
  if (!secp256r1.verify(
      Buffer.from(signature, "hex"),
      signedDataHash,
      uncompressedPubKey.slice(2) // remove "0x"
  )) {
    throw new HexlinkError(400, "invalid signature");
  }
};

import cors from "cors";
import * as functions from "firebase-functions";
import * as admin from "firebase-admin";
import crypto from "crypto";
import {secp256r1} from "@noble/curves/p256";
import {encrypt} from "eciesjs";
import {ethers} from "ethers";
import * as cookie from "cookie";

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
 *   address?: string, // only valid if registered is true
 */

export const getAddressByUid = functions.https.onRequest((req, res) => {
  return cors({origin: true, credentials: true})(req, res, async () => {
    try {
      if (secrets.ENV !== "dev" && await checkNameRateLimit(req.ip || "")) {
        throw new HexlinkError(429, "Too many requests");
      }
      const address = await resolveName(req.body.uid);
      if (!address) {
        res.status(200).json({registered: false});
      } else {
        res.status(200).json({registered: true, address});
      }
    } catch (err: unknown) {
      handleError(res, err);
    }
  });
});

/**
 * req.body: {
 *   uid: string,
 * }
 *
 * res: {
 *   registered: boolean,
 *   user?: { // only valid if registered is true
 *     address: string,
 *     operator: string,
 *     metadata: string,
 *     passkey: Passkey,
 *     name?: string,
 *   }
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
              name: user.name,
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
 *   address: string,
 * }
 *
 * res: {
 *   registered: boolean,
 *   user?: { // only valid if registered is true
 *     address: string,
 *     operator: string,
 *     metadata: string,
 *     passkey: Passkey,
 *     name?: string,
 *   }
 */
export const getUserByAddress = functions.https.onRequest((req, res) => {
  return cors({origin: true, credentials: true})(req, res, async () => {
    try {
      if (secrets.ENV !== "dev" && await checkNameRateLimit(req.ip || "")) {
        throw new HexlinkError(429, "Too many requests");
      }
      const user = await getUser(req.body.address);
      if (user) {
        res.status(200).json({
          registered: true,
          user: {
            address: req.body.address,
            passkey: user.passkey,
            operatorPubKey: user.operator,
            name: user.name,
          },
        });
      } else {
        throw new HexlinkError(404, "user not found");
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
 *  metadata: string,
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
 *   dek: string, // base64,
 *   csrfToken: string,
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
              Buffer.from(req.body.metadata, "hex"), // metadata
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
        const dek = crypto.randomBytes(32);
        const dekId = sha256(dek).toString("hex");
        const newDekClientEncrypted = encrypt(req.body.kek, dek);
        const csrfToken = crypto.randomBytes(32).toString("hex");
        await registerUser(
            uid,
            address,
            req.body.passkey,
            req.body.operator,
            req.body.metadata,
            req.body.kek,
            {[dekId]: await encryptWithSymmKey(dek.toString("hex"))},
            csrfToken,
            req.body.username,
        );
        // use address as the user id
        await admin.auth().createUser({uid: address});
        const token = await admin.auth().createCustomToken(address);
        res.status(200).json({
          address,
          token: token,
          dek: newDekClientEncrypted.toString("hex"),
          csrfToken,
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
 *   csrfToken: string,
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
        const csrfToken = crypto.randomBytes(32).toString("hex");
        if (req.body.dekId) {
          const {dek, newDek} = await getAndGenDeks(
              req.body.dekId, req.body.kek, user);
          await postAuth(req.body.address, req.body.kek, csrfToken, {
            [dek.keyId]: dek.server,
            [newDek.keyId]: newDek.server,
          });
          const token = await admin.auth().createCustomToken(
              req.body.address);
          res.status(200).json({
            token: token,
            dek: dek.client,
            newDek: newDek.client,
            csrfToken,
          });
        } else {
          await postAuth(req.body.address, req.body.kek, csrfToken);
          const token = await admin.auth().createCustomToken(
              req.body.address);
          res.status(200).json({token, csrfToken});
        }
      } catch (err: unknown) {
        handleError(res, err);
      }
    });
  });

/**
 * req.body: {
 *   idToken: string,
 *   csrfToken: string,
 * }
 *
 * res: {
 *   success: true,
 * }
 */
export const sessionLogin =
  functions.https.onRequest((req, res) => {
    cors({
      origin: true,
      credentials: true,
      allowedHeaders: ["Content-Type", "Set-Cookie"],
    })(req, res, async () => {
      try {
        const idToken = req.body.idToken;
        const csrfToken = req.body.csrfToken;
        const decoded = await admin.auth().verifyIdToken(idToken);
        const user = await getUser(decoded.uid);
        // Guard against CSRF attacks.
        if (csrfToken !== user?.csrfToken) {
          throw new HexlinkError(401, "UNAUTHORIZED REQUEST");
        }
        // Only process if the user just signed in in the last 5 minutes.
        if (new Date().getTime() / 1000 - decoded.auth_time > 5 * 60) {
          throw new HexlinkError(401, "recent sign in required");
        }
        const expiresIn = 60 * 60 * 24 * 7 * 1000; // valid for 7 days
        const sessionCookie = await admin.auth().createSessionCookie(
            idToken, {expiresIn});
        res.cookie("__session", sessionCookie, {
          maxAge: expiresIn,
          httpOnly: true,
          secure: true,
          sameSite: "none",
        }).appendHeader("Cache-Control", "private")
            .status(200).json({success: true});
      } catch (err: unknown) {
        handleError(res, err);
      }
    });
  });

/**
 * req.body: {
 *   keyId: string,
 *   csrfToken: string,
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
        const claims = await verifySessionCookie(req);
        const user = await getUser(claims.uid);
        if (!user || req.body.csrfToken != user?.csrfToken) {
          throw new HexlinkError(401, "Access denied");
        }
        const {dek, newDek} = await getAndGenDeks(
            req.body.keyId, user.kek, user);
        await updateDeks(
            claims.uid,
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
  const newDek = crypto.randomBytes(32);
  const [
    decryptedDekStr, newDekServerEncrypted,
  ] = await Promise.all([
    decryptWithSymmKey(dekServerEncrypted),
    encryptWithSymmKey(newDek.toString("hex")),
  ]);
  const decryptedDek = Buffer.from(decryptedDekStr, "hex");
  const keyIdFromDek = sha256(decryptedDek);
  if (keyIdFromDek.toString("hex") !== keyId) {
    throw new HexlinkError(500, "server data corrupted");
  }
  const dekClientEncrypted = encrypt(kek, decryptedDek);
  const newKeyId = sha256(newDek).toString("hex");
  const newDekClientEncrypted = encrypt(kek, newDek);
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

export const verifySessionCookie = async (req: functions.Request) => {
  const sessionCookie = cookie.parse(req.headers.cookie || "");
  const session = sessionCookie.__session;
  if (!session) {
    throw new HexlinkError(401, "UNAUTHORIZED REQUEST");
  }
  try {
    return admin.auth().verifySessionCookie(
        session, true /** checkRevoked */);
  } catch (err: unknown) {
    console.log(err);
    throw new HexlinkError(401, "UNAUTHORIZED REQUEST");
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

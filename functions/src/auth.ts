import cors from "cors";
import * as functions from "firebase-functions";
import * as admin from "firebase-admin";
import crypto from "crypto";
import {secp256r1} from "@noble/curves/p256";
import {ethers} from "ethers";
import * as cookie from "cookie";

import {
  HexlinkError,
  epoch,
  formatHex,
  genNameHash,
  handleError,
  toBuffer,
} from "./utils";
import {decryptWithSymmKey, encryptWithSymmKey} from "./gcloudKms";
import {getChallengeRateLimit, registerRateLimit} from "./ratelimiter";
import {registerUser, getAuth, postAuth, preAuth} from "./db/auth";
import {getAccountAddress} from "./account";

const secrets = functions.config().doppler || {};

/**
 * req.body: {
 *  username: string,
 *  factory: string,
 *  operator: string,
 *  metadata: string,
 *  passkey: {
 *    id: string,
 *    x: string,
 *    y: string,
 *  },
 *  clientDataJson: string,
 *  authData: string, // hex
 *  signature: string, // hex
 *  dek: string,
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
  return cors({origin: true, credentials: true})(req, res, async () => {
    try {
      if (secrets.ENV !== "dev" && (await registerRateLimit(req.ip || ""))) {
        throw new HexlinkError(429, "Too many requests");
      }
      const address = await getAccountAddress(req.body);
      const nameHash = genNameHash(req.body.username);
      const csrfToken = crypto.randomBytes(32).toString("hex");
      const [, encDek, token] = await Promise.all([
        registerUser(
            nameHash,
            address,
            req.body.passkey,
            req.body.factory,
            req.body.operator,
            req.body.metadata,
            csrfToken
        ),
        encryptWithSymmKey(req.body.dek, toBuffer(address)),
        createNewUser(address),
      ]);
      res.status(200).json({
        token,
        address,
        csrfToken,
        encDek,
      });
    } catch (err: unknown) {
      handleError(res, err);
    }
  });
});

async function createNewUser(address: string): Promise<string> {
  await admin.auth().createUser({uid: address});
  return admin.auth().createCustomToken(address);
}

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
  cors({origin: true, credentials: true})(req, res, async () => {
    try {
      if (
        secrets.ENV !== "dev" &&
        (await getChallengeRateLimit(req.ip || ""))
      ) {
        throw new HexlinkError(429, "Too many requests");
      }
      const address = ethers.getAddress(req.body.address);
      const auth = await getAuth(address);
      if (auth == null) {
        throw new HexlinkError(404, "User not found");
      }
      if (auth.challenge && auth.updatedAt.seconds + 180 > epoch()) {
        res.status(200).json({challenge: auth.challenge});
      } else {
        const challenge = crypto.randomBytes(32).toString("hex");
        await preAuth(address, challenge);
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
 *   clientDataJson: string,
 *   authData: string, // hex
 *   signature: string, // hex
 *   encDek?: string, // to decrypt
 *   newDek?: string, // to encrypt
 * }
 *
 * res: {
 *   token: string,
 *   csrfToken: string,
 *   dek?: string, // decrypted
 *   encNewDek?: string, // encrypted
 * }
 */
export const loginWithPasskey = functions.https.onRequest((req, res) => {
  cors({origin: true, credentials: true})(req, res, async () => {
    try {
      const address = ethers.getAddress(req.body.address);
      const auth = await getAuth(address);
      if (!auth?.challenge) {
        throw new HexlinkError(404, "User not found or challenge not set");
      }
      if (auth.updatedAt.seconds + 180 < epoch()) {
        throw new HexlinkError(403, "invalid challenge");
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
      const csrfToken = crypto.randomBytes(32).toString("hex");
      const aad = toBuffer(address);
      const [, token, dek, encNewDek] = await Promise.all([
        postAuth(address, csrfToken),
        admin.auth().createCustomToken(address),
        decryptWithSymmKey(req.body.encDek, aad),
        encryptWithSymmKey(req.body.newDek, aad),
      ]);
      res.status(200).json({token, csrfToken, dek, encNewDek});
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
export const sessionLogin = functions.https.onRequest((req, res) => {
  cors({
    origin: true,
    credentials: true,
    allowedHeaders: ["Content-Type", "Set-Cookie"],
  })(req, res, async () => {
    try {
      const idToken = req.body.idToken;
      const csrfToken = req.body.csrfToken;
      const decoded = await admin.auth().verifyIdToken(idToken);
      const auth = await getAuth(decoded.uid);
      // Guard against CSRF attacks.
      if (csrfToken !== auth?.csrfToken) {
        throw new HexlinkError(401, "UNAUTHORIZED REQUEST");
      }
      // Only process if the user just signed in in the last 5 minutes.
      if (new Date().getTime() / 1000 - decoded.auth_time > 5 * 60) {
        throw new HexlinkError(401, "recent sign in required");
      }
      const expiresIn = 60 * 60 * 24 * 7 * 1000; // valid for 7 days
      const sessionCookie = await admin
          .auth()
          .createSessionCookie(idToken, {expiresIn});
      res
          .cookie("__session", sessionCookie, {
            maxAge: expiresIn,
            httpOnly: true,
            secure: true,
            sameSite: "none",
          })
          .appendHeader("Cache-Control", "private")
          .status(200)
          .json({success: true});
    } catch (err: unknown) {
      handleError(res, err);
    }
  });
});

/**
 * req.body: {
 *   encDek: string, // to decrypt
 *   newDek?: string, // to encrypt
 *   csrfToken: string,
 * }
 *
 * res: {
 *   dek: string, // decrypted
 *   encNewDek?: string, // encrypted
 * }
 */
export const getDeks = functions.https.onRequest((req, res) => {
  cors({origin: true, credentials: true})(req, res, async () => {
    try {
      const claims = await verifySessionCookie(req);
      const auth = await getAuth(claims.uid);
      if (!auth || req.body.csrfToken != auth?.csrfToken) {
        throw new HexlinkError(401, "Access denied");
      }
      const aad = toBuffer(claims.uid);
      const [dek, encNewDek] = await Promise.all([
        decryptWithSymmKey(req.body.encDek, aad),
        encryptWithSymmKey(req.body.newDek, aad),
      ]);
      res.status(200).json({dek, encNewDek});
    } catch (err: unknown) {
      handleError(res, err);
    }
  });
});

export const verifySessionCookie = async (req: functions.Request) => {
  const sessionCookie = cookie.parse(req.headers.cookie || "");
  const session = sessionCookie.__session;
  if (!session) {
    throw new HexlinkError(401, "UNAUTHORIZED REQUEST");
  }
  try {
    return admin.auth().verifySessionCookie(session, true /** checkRevoked */);
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
          throw new HexlinkError(400, "invalid client data");
        }
      } else {
        if (parsed[key] !== value) {
          throw new HexlinkError(400, "invalid client data");
        }
      }
    }
  }

  const clientDataHash = crypto
      .createHash("sha256")
      .update(clientDataJson)
      .digest();
  const signedData = Buffer.concat([
    toBuffer(authData),
    clientDataHash,
  ]);
  const signedDataHash = crypto
      .createHash("sha256")
      .update(signedData)
      .digest("hex");
  const uncompressedPubKey = ethers.solidityPacked(
      ["uint8", "uint256", "uint256"],
      [4, formatHex(pubKey.x), formatHex(pubKey.y)]
  );
  if (
    !secp256r1.verify(
        toBuffer(signature),
        signedDataHash,
        uncompressedPubKey.slice(2) // remove "0x"
    )
  ) {
    throw new HexlinkError(400, "invalid signature");
  }
};
import cors from "cors";
import * as functions from "firebase-functions";
import crypto from "crypto";
import { secp256r1 } from "@noble/curves/p256";
import { ethers } from "ethers";
import * as cookie from "cookie";

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
  getPublicKeyPemRsa,
  signAsymmetricRsa,
} from "./gcloudKms";
import { getChallengeRateLimit, registerRateLimit } from "./ratelimiter";
import {
  registerUser,
  getAuth,
  postAuth,
  preAuth,
  postLogout,
} from "./db/auth";
import { getAccountAddress } from "./account";
import * as asn1 from "asn1.js";
import BN from "bn.js";
import base64url from "base64url";

const secrets = functions.config().doppler || {};
const SESSION_TTL = 60 * 60 * 24 * 5; // valid for 5 days

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
  return cors({ origin: true, credentials: true })(req, res, async () => {
    try {
      if (secrets.ENV !== "dev" && (await registerRateLimit(req.ip || ""))) {
        throw new ServerError(429, "Too many requests");
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
        // we reuse csrfToken as session id since it's unique per session
        signJwt(address, csrfToken, SESSION_TTL),
      ]);
      res
        .cookie("__session", token, {
          maxAge: SESSION_TTL,
          httpOnly: true,
          secure: true,
          sameSite: "none",
        })
        .appendHeader("Cache-Control", "private")
        .status(200)
        .json({ address, csrfToken, encDek });
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
export const getPasskeyChallenge = functions.https.onRequest((req, res) => {
  cors({ origin: true, credentials: true })(req, res, async () => {
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
  cors({ origin: true, credentials: true })(req, res, async () => {
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
      const csrfToken = crypto.randomBytes(32).toString("hex");
      const aad = toBuffer(address);
      const [, dek, encNewDek, token] = await Promise.all([
        postAuth(address, csrfToken),
        decryptWithSymmKey(req.body.encDek, aad),
        encryptWithSymmKey(req.body.newDek, aad),
        // we reuse csrfToken as session id since it's unique per session
        signJwt(address, csrfToken, SESSION_TTL),
      ]);
      res
        .cookie("__session", token, {
          maxAge: SESSION_TTL,
          httpOnly: true,
          secure: true,
          sameSite: "none",
        })
        .appendHeader("Cache-Control", "private")
        .status(200)
        .json({ csrfToken, dek, encNewDek });
    } catch (err: unknown) {
      handleError(res, err);
    }
  });
});

/**
 * req.body: { }
 *
 * res: {
 *   success: boolean,
 * }
 */
export const logout = functions.https.onRequest((req, res) => {
  cors({ origin: true, credentials: true })(req, res, async () => {
    try {
      const sessionCookie = cookie.parse(req.headers.cookie || "");
      const session = sessionCookie.__session;
      if (!session) {
        res.status(200).json({ success: true });
        return;
      }
      const claims = await verifyJwt(session);
      await postLogout(claims.uid);
      res.cookie("__session", undefined).status(200).json({ success: true });
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
  cors({ origin: true, credentials: true })(req, res, async () => {
    try {
      const sessionCookie = cookie.parse(req.headers.cookie || "");
      const session = sessionCookie.__session;
      if (!session) {
        throw new ServerError(401, "UNAUTHORIZED REQUEST");
      }
      const claims = await verifyJwt(session);
      const auth = await getAuth(claims.uid);
      if (
        !auth?.csrfToken ||
        req.body.csrfToken != auth.csrfToken ||
        claims.session != auth.csrfToken
      ) {
        throw new ServerError(401, "Access denied");
      }
      const aad = toBuffer(claims.uid);
      const [dek, encNewDek] = await Promise.all([
        decryptWithSymmKey(req.body.encDek, aad),
        encryptWithSymmKey(req.body.newDek, aad),
      ]);
      res.status(200).json({ dek, encNewDek });
    } catch (err: unknown) {
      handleError(res, err);
    }
  });
});

const EcdsaSigAsnParse: {
  decode: (asnStringBuffer: Buffer, format: "der") => { r: BN; s: BN };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
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

async function signJwt(
  address: string,
  sessionId: string,
  ttl: number
): Promise<string> {
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
      session: sessionId,
    })
  );
  const signature = await signAsymmetricRsa(
    Buffer.from(`${header}.${payload}`)
  );
  return `${header}.${payload}.${base64url.encode(signature)}`;
}

export const verifyJwt = async function (token: string): Promise<{
  uid: string;
  session: string;
}> {
  const jwtPubPem = await getPublicKeyPemRsa();
  const [header, payload, signature] = token.split(".");
  const signatureBuffer = Buffer.from(signature, "base64url");
  const verify = crypto.createVerify("RSA-SHA256");
  verify.update(`${header}.${payload}`);
  if (
    !verify.verify(
      { key: jwtPubPem, padding: crypto.constants.RSA_PKCS1_PSS_PADDING },
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
    throw new ServerError(401, "auth token expired");
  }
  if (
    parsedPayload.iss !== secrets.REACT_APP_DOMAIN ||
    parsedPayload.sub === undefined
  ) {
    throw new ServerError(401, "invalid jwt payload");
  }
  return {
    uid: parsedPayload.sub,
    session: parsedPayload.session,
  };
};

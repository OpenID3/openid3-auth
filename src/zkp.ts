import cors from "cors";
import * as functions from "firebase-functions";
import * as admin from "firebase-admin";
import axios from "axios";
import * as jose from "jose";

import {HexlinkError, handleError, sha256} from "./utils";
import {addNewZkpRequest, addZkProof, getZkp, markZkProofError} from "./db";
import {defineSecret} from "firebase-functions/params";
import {extractFirebaseIdToken} from "./auth";
import {
  JwtInput,
  genUserOpHash,
  genZkAdminSignature,
  submitUserOp,
} from "./userop";

const secrets = functions.config().doppler || {};
const ZKP_SERVICE_SECRET = defineSecret("zkp-service-secret");

const GOOGLE_JWKS = jose.createLocalJWKSet({
  keys: [
    {
      alg: "RS256",
      kid: "f833e8a7fe3fe4b878948219a1684afa373ca86f",
      kty: "RSA",
      use: "sig",
      n: "uB-3s136B_Vcme1zGQEg-Avs31_voau8BPKtvbYhB0QOHTtrXCF_wxIH5vWjl-5ts8up8Iy2kVnaItsecGohBAy_0kRgq8oi-n_cZ0i5bspAX5VW0peh_QU3KTlKSBaz3ZD9xMCDWuJFFniHuxLtJ4QtL4v2oDD3pBPNRPyIcZ_LKhH3-Jm-EAvubI5-6lB01zkP5x8f2mp2upqAmyex0jKFka2e0DOBavmGsGvKHKtTnE9oSOTDlhINgQPohoSmir89NRbEqqzeZVb55LWRl_hkiDDOZmcM_oJ8iUbm6vQu3YwCy-ef9wGYEij5GOWLmpYsws5vLVtTE2U-0C_ItQ",
      e: "AQAB",
    },
    {
      e: "AQAB",
      use: "sig",
      n: "4VCFlBofjCVMvApNQ97Y-473vGov--idNmGQioUg0PXJv0oRaAClXWINwNaMuLIegChkWNNpbvsrdJpapSNHra_cdAoSrhd_tLNWDtBGm6tsVZM8vciggnJHuJwMtGwZUiUjHeYWebaJrZmWh1WemYluQgyxgDAY_Rf7OdIthAlwsAzvmObuByoykU-74MyMJVal7QzATaEh0je7BqoDEafG750UrMwzSnACjlZvnmrCHR4KseT4Tv4Fa0rCc_wpRP-Uuplri_EbMSr15OXoGTDub6UM8_0LIjNL0yRqh5JpesbOtxW_OU1bMeSUOJeAZzAA4-vq_l-jrDlelHxZxw",
      kty: "RSA",
      alg: "RS256",
      kid: "5b3706960e3e60024a2655e78cfa63f87c97d309",
    },
  ],
});

/**
 * req.body: {
 *   provider: "google",
 *   idToken: string,
 *   chain: Chain,
 *   userOp: UserOpStruct,
 *   dev: boolean,
 * }
 *
 * res: {
 *   status: "processing" | "error" | "done";
 * }
 */
export const requestToReset = functions
    .runWith({
      secrets: [ZKP_SERVICE_SECRET],
    })
    .https.onRequest((req, res) => {
      return cors({origin: true})(req, res, async () => {
        try {
          const firebaseIdToken = extractFirebaseIdToken(req);
          const decoded = await admin.auth().verifyIdToken(firebaseIdToken);
          const jwtInput = await genJwtInput(
              decoded.uid,
              req.body.provider,
              req.body.idToken,
          );
          const zkp = await getZkp(decoded.uid);
          if (zkp && zkp.status === "processing") {
            throw new HexlinkError(400, "reset ongoing");
          }
          await addNewZkpRequest(
              decoded.uid,
              jwtInput,
              req.body.chain,
              req.body.userOp
          );
          if (!req.body.dev) {
            await requestZkp(
                decoded.uid,
                req.body.idToken,
                ZKP_SERVICE_SECRET.value()
            );
          }
          res.status(200).json({status: "processing"});
        } catch (err: unknown) {
          handleError(res, err);
        }
      });
    });

/**
 * req.body: {
 *    chain: Chain,
 * }
 *
 * res: {
 *    status: "processing" | "error" | "done",
 *    userOpHash: string,
 *    error?: string,
 * }
 */
export const queryResetStatus = functions.https.onRequest((req, res) => {
  return cors({origin: true})(req, res, async () => {
    try {
      const firebaseIdToken = extractFirebaseIdToken(req);
      const decoded = await admin.auth().verifyIdToken(firebaseIdToken);
      const zkp = await getZkp(decoded.uid);
      if (!zkp) {
        throw new HexlinkError(404, "id token not found");
      }
      const userOpHash = await genUserOpHash(zkp.chain, zkp.userOp);
      if (zkp.status === "processing") {
        res.status(200).json({status: "processing"});
      } else if (zkp.status === "error") {
        res.status(200).json({status: "error", userOpHash, error: zkp.error});
      } else if (zkp.status === "done") {
        res.status(200).json({status: "done", userOpHash});
      }
    } catch (err: unknown) {
      handleError(res, err);
    }
  });
});

/**
 * req.body: {
 *   uid: string;
 *   idToken: string;
 *   success: boolean,
 *   proof?: OidcZkProof,
 *   error?: string,
 * }
 *
 * res: {
 *   success: boolean,
 * }
 *
 * This can only be called by the zkp service.
 */
export const submitZkProof = functions
    .runWith({
      secrets: [ZKP_SERVICE_SECRET],
    })
    .https.onRequest((req, res) => {
      return cors({origin: true})(req, res, async () => {
        try {
          const accessToken = extractFirebaseIdToken(req);
          const secret = ZKP_SERVICE_SECRET.value();
          if (secret && accessToken !== secret) {
            throw new HexlinkError(401, "unauthorized");
          }
          const zkp = await getZkp(req.body.uid);
          if (zkp == null || zkp.status !== "processing") {
            throw new HexlinkError(400, "no active zkp request");
          }
          if (req.body.success) {
            if (req.body.proof == null) {
              throw new HexlinkError(400, "proof is required");
            }
            await addZkProof(req.body.uid, req.body.proof);
            zkp.userOp.signature = genZkAdminSignature(
                zkp.jwtInput,
                req.body.proof
            );
            await submitUserOp(zkp.chain, zkp.userOp);
          } else {
            await markZkProofError(
                req.body.uid,
                req.body.error ?? "unknown error"
            );
          }
          res.status(200).json({success: true});
        } catch (err: unknown) {
          handleError(res, err);
        }
      });
    });

async function validateGoogleIdToken(idToken: string, uid: string) {
  try {
    const options = {
      issuer: "https://accounts.google.com",
      sub: uid,
    };
    return jose.jwtVerify(idToken, GOOGLE_JWKS, options);
  } catch (err) {
    console.log(err);
    throw new HexlinkError(400, "invalid id token");
  }
}

async function genJwtInput(
    uid: string,
    provider: string,
    idToken: string
): Promise<JwtInput> {
  if (provider === "google") {
    const {protectedHeader, payload} = await validateGoogleIdToken(
        idToken,
        uid
    );
    const [headerB64, payloadB64, jwtSignature] = idToken.split(".");
    const signedHash = sha256(headerB64 + "." + payloadB64).toString("hex");
    if (protectedHeader.kid == null) {
      throw new HexlinkError(400, "kid is required");
    }
    return {
      kidSha256: "0x" + sha256(protectedHeader.kid).toString("hex"),
      iat: String(payload.iat),
      jwtHeaderAndPayloadHash: "0x" + signedHash,
      jwtSignature,
    } as JwtInput;
  }
  throw new Error(`Unsupported provider: ${provider}`);
}

async function requestZkp(uid: string, idToken: string, secret: string) {
  try {
    const config = {headers: {authorization: "Bearer " + secret}};
    const res = await axios.post(
        secrets.ZKP_SERVICE_URL,
        {uid, idToken},
        config
    );
    if (!res.data.success) {
      throw new Error("failed to request zkp: " + res.data.message);
    }
  } catch (err) {
    console.log(err);
    await markZkProofError(uid, JSON.stringify(err));
    throw new HexlinkError(500, "failed to generate zkp proof");
  }
}

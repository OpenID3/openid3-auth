import cors from "cors";
import * as functions from "firebase-functions";
import * as admin from "firebase-admin";
import axios from "axios";
import * as jose from "jose";

import {HexlinkError, handleError, sha256} from "./utils";
import {addZkProof, getZkp, postZkpRequest} from "./db";
import {defineSecret} from "firebase-functions/params";
import {extractFirebaseIdToken} from "./auth";

const ZKP_SERVICE_SECRET = defineSecret("zkp-service-secret");

const GOOGLE_JWKS = jose.createLocalJWKSet({
  "keys": [
    {
      "alg": "RS256",
      "kid": "f833e8a7fe3fe4b878948219a1684afa373ca86f",
      "kty": "RSA",
      "use": "sig",
      "n": "uB-3s136B_Vcme1zGQEg-Avs31_voau8BPKtvbYhB0QOHTtrXCF_wxIH5vWjl-5ts8up8Iy2kVnaItsecGohBAy_0kRgq8oi-n_cZ0i5bspAX5VW0peh_QU3KTlKSBaz3ZD9xMCDWuJFFniHuxLtJ4QtL4v2oDD3pBPNRPyIcZ_LKhH3-Jm-EAvubI5-6lB01zkP5x8f2mp2upqAmyex0jKFka2e0DOBavmGsGvKHKtTnE9oSOTDlhINgQPohoSmir89NRbEqqzeZVb55LWRl_hkiDDOZmcM_oJ8iUbm6vQu3YwCy-ef9wGYEij5GOWLmpYsws5vLVtTE2U-0C_ItQ",
      "e": "AQAB",
    },
    {
      "e": "AQAB",
      "use": "sig",
      "n": "4VCFlBofjCVMvApNQ97Y-473vGov--idNmGQioUg0PXJv0oRaAClXWINwNaMuLIegChkWNNpbvsrdJpapSNHra_cdAoSrhd_tLNWDtBGm6tsVZM8vciggnJHuJwMtGwZUiUjHeYWebaJrZmWh1WemYluQgyxgDAY_Rf7OdIthAlwsAzvmObuByoykU-74MyMJVal7QzATaEh0je7BqoDEafG750UrMwzSnACjlZvnmrCHR4KseT4Tv4Fa0rCc_wpRP-Uuplri_EbMSr15OXoGTDub6UM8_0LIjNL0yRqh5JpesbOtxW_OU1bMeSUOJeAZzAA4-vq_l-jrDlelHxZxw",
      "kty": "RSA",
      "alg": "RS256",
      "kid": "5b3706960e3e60024a2655e78cfa63f87c97d309",
    },
  ],
});

/**
 * req.body: {
 *   provider: "google",
 *   idToken: string,
 * }
 *
 * res: {
 *   status: "processing" | "error" | "done",
 *   proof: "string" | null,
 * }
 */
export const requestZkProof = functions.runWith({
  secrets: [ZKP_SERVICE_SECRET],
}).https.onRequest((req, res) => {
  return cors({origin: true})(req, res, async () => {
    try {
      const firebaseIdToken = extractFirebaseIdToken(req);
      const decoded = await admin.auth().verifyIdToken(firebaseIdToken);
      await validateProviderIdToken(
          req.body.provider, req.body.idToken, decoded.uid);
      await requestZkp(
          decoded.uid, req.body.idToken, ZKP_SERVICE_SECRET.value());
      res.status(200).json({status: "processing"});
    } catch (err: unknown) {
      handleError(res, err);
    }
  });
});

/**
 * req.body: {
 *   idTokenHash: string
 * }
 *
 * res: {
 *    status: "processing" | "error" | "done",
 *    proof?: string
 * }
 */
export const queryZkProof = functions.https.onRequest((req, res) => {
  return cors({origin: true})(req, res, async () => {
    try {
      const firebaseIdToken = extractFirebaseIdToken(req);
      const decoded = await admin.auth().verifyIdToken(firebaseIdToken);
      const zkp = await getZkp(decoded.uid);
      if (zkp == null || zkp.idTokenHash != req.body.idTokenHash) {
        throw new HexlinkError(400, "id token not found");
      }
      if (zkp.status === "processing") {
        res.status(200).json({status: "processing"});
      } else if (zkp.status === "error") {
        res.status(200).json({status: "error", message: zkp.error});
      } else if (zkp.status === "done") {
        res.status(200).json({status: "done", proof: zkp.proof});
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
 *   status: "error" | "done",
 *   proof?: string,
 *   error?: string,
 * }
 *
 * res: {
 *   success: boolean,
 * }
 *
 * This can only be called by the zkp service.
 */
export const storeZkProof = functions.runWith({
  secrets: [ZKP_SERVICE_SECRET],
}).https.onRequest((req, res) => {
  return cors({origin: true})(req, res, async () => {
    try {
      const accessToken = extractFirebaseIdToken(req);
      if (accessToken !== ZKP_SERVICE_SECRET.value()) {
        throw new HexlinkError(401, "unauthorized");
      }
      const zkp = await getZkp(req.body.uid);
      if (zkp == null ||
        zkp.status !== "processing" ||
        zkp.idTokenHash !== sha256(req.body.idToken).toString("hex")
      ) {
        throw new HexlinkError(400, "no active zkp request");
      }
      if (req.body.status === "done") {
        if (req.body.proof == null) {
          throw new HexlinkError(400, "proof is required");
        }
      } else if (req.body.status === "error") {
        if (req.body.error == null) {
          throw new HexlinkError(400, "error message is required");
        }
      } else {
        throw new HexlinkError(400, "invalid status");
      }
      await addZkProof(
          req.body.uid,
          req.body.status,
          req.body.proof,
          req.body.error,
      );
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
    await jose.jwtVerify(idToken, GOOGLE_JWKS, options);
  } catch (err) {
    console.log(err);
    throw new HexlinkError(400, "invalid id token");
  }
}

async function validateProviderIdToken(
    uid: string,
    provider: string,
    idToken: string,
) {
  if (provider === "google") {
    return validateGoogleIdToken(idToken, uid);
  }
  throw new Error(`Unsupported provider: ${provider}`);
}

const ZKP_SERVER_URL = "https://localhost:8080/zkp/generate";

async function requestZkp(
    uid: string,
    idToken: string,
    secret: string,
) {
  const zkp = await getZkp(uid);
  if (zkp && zkp.status === "processing") {
    throw new HexlinkError(400, "zkp is already processing");
  }
  try {
    const config = {headers: {authorization: "Bearer " + secret}};
    const res = await axios.post(ZKP_SERVER_URL, {idToken}, config);
    if (!res.data.success) {
      throw new Error("failed to request zkp: " + res.data.message);
    }
    await postZkpRequest(uid, idToken);
  } catch (err) {
    console.log(err);
    throw new HexlinkError(500, "failed to generate zkp proof");
  }
}

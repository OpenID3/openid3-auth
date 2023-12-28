"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.submitZkProof = exports.queryResetStatus = exports.requestToReset = void 0;
const cors_1 = __importDefault(require("cors"));
const functions = __importStar(require("firebase-functions"));
const admin = __importStar(require("firebase-admin"));
const axios_1 = __importDefault(require("axios"));
const jose = __importStar(require("jose"));
const utils_1 = require("./utils");
const zkp_1 = require("./db/zkp");
const params_1 = require("firebase-functions/params");
const userop_1 = require("./userop");
const secrets = functions.config().doppler || {};
const ZKP_SERVICE_SECRET = (0, params_1.defineSecret)("zkp-service-secret");
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
exports.requestToReset = functions
    .runWith({
    secrets: [ZKP_SERVICE_SECRET],
})
    .https.onRequest((req, res) => {
    return (0, cors_1.default)({ origin: true })(req, res, async () => {
        try {
            const firebaseIdToken = extractFirebaseIdToken(req);
            const decoded = await admin.auth().verifyIdToken(firebaseIdToken);
            const jwtInput = await genJwtInput(decoded.uid, req.body.provider, req.body.idToken);
            const zkp = await (0, zkp_1.getZkp)(decoded.uid);
            if (zkp && zkp.status === "processing") {
                throw new utils_1.HexlinkError(400, "reset ongoing");
            }
            await (0, zkp_1.addNewZkpRequest)(decoded.uid, jwtInput, req.body.chain, req.body.userOp);
            if (!req.body.dev) {
                await requestZkp(decoded.uid, req.body.idToken, ZKP_SERVICE_SECRET.value());
            }
            res.status(200).json({ status: "processing" });
        }
        catch (err) {
            (0, utils_1.handleError)(res, err);
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
exports.queryResetStatus = functions.https.onRequest((req, res) => {
    return (0, cors_1.default)({ origin: true })(req, res, async () => {
        try {
            const firebaseIdToken = extractFirebaseIdToken(req);
            const decoded = await admin.auth().verifyIdToken(firebaseIdToken);
            const zkp = await (0, zkp_1.getZkp)(decoded.uid);
            if (!zkp) {
                throw new utils_1.HexlinkError(404, "id token not found");
            }
            const userOpHash = await (0, userop_1.genUserOpHash)(zkp.chain, zkp.userOp);
            if (zkp.status === "processing") {
                res.status(200).json({ status: "processing" });
            }
            else if (zkp.status === "error") {
                res.status(200).json({ status: "error", userOpHash, error: zkp.error });
            }
            else if (zkp.status === "done") {
                res.status(200).json({ status: "done", userOpHash });
            }
        }
        catch (err) {
            (0, utils_1.handleError)(res, err);
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
exports.submitZkProof = functions
    .runWith({
    secrets: [ZKP_SERVICE_SECRET],
})
    .https.onRequest((req, res) => {
    return (0, cors_1.default)({ origin: true })(req, res, async () => {
        try {
            const accessToken = extractFirebaseIdToken(req);
            const secret = ZKP_SERVICE_SECRET.value();
            if (secret && accessToken !== secret) {
                throw new utils_1.HexlinkError(401, "unauthorized");
            }
            const zkp = await (0, zkp_1.getZkp)(req.body.uid);
            if (!zkp || zkp.status !== "processing") {
                throw new utils_1.HexlinkError(404, "zkp request not found");
            }
            if (req.body.success) {
                if (req.body.proof == null) {
                    throw new utils_1.HexlinkError(400, "proof is required");
                }
                await (0, zkp_1.addZkProof)(req.body.uid, req.body.proof);
                zkp.userOp.signature = (0, userop_1.genZkAdminSignature)(zkp.jwtInput, req.body.proof);
                await (0, userop_1.submitUserOp)(zkp.chain, zkp.userOp);
            }
            else {
                await (0, zkp_1.markZkProofError)(req.body.uid, req.body.error ?? "unknown error");
            }
            res.status(200).json({ success: true });
        }
        catch (err) {
            (0, utils_1.handleError)(res, err);
        }
    });
});
async function validateGoogleIdToken(idToken, uid) {
    try {
        const options = {
            issuer: "https://accounts.google.com",
            sub: uid,
        };
        return jose.jwtVerify(idToken, GOOGLE_JWKS, options);
    }
    catch (err) {
        console.log(err);
        throw new utils_1.HexlinkError(400, "invalid id token");
    }
}
async function genJwtInput(uid, provider, idToken) {
    if (provider === "google") {
        const { protectedHeader, payload } = await validateGoogleIdToken(idToken, uid);
        const [headerB64, payloadB64, jwtSignature] = idToken.split(".");
        const signedHash = (0, utils_1.sha256)(headerB64 + "." + payloadB64).toString("hex");
        if (protectedHeader.kid == null) {
            throw new utils_1.HexlinkError(400, "kid is required");
        }
        return {
            kidSha256: "0x" + (0, utils_1.sha256)(protectedHeader.kid).toString("hex"),
            iat: String(payload.iat),
            jwtHeaderAndPayloadHash: "0x" + signedHash,
            jwtSignature,
        };
    }
    throw new Error(`Unsupported provider: ${provider}`);
}
async function requestZkp(uid, idToken, secret) {
    try {
        const config = { headers: { authorization: "Bearer " + secret } };
        const res = await axios_1.default.post(secrets.ZKP_SERVICE_URL, { uid, idToken }, config);
        if (!res.data.success) {
            throw new Error("failed to request zkp: " + res.data.message);
        }
    }
    catch (err) {
        console.log(err);
        await (0, zkp_1.markZkProofError)(uid, JSON.stringify(err));
        throw new utils_1.HexlinkError(500, "failed to generate zkp proof");
    }
}
const extractFirebaseIdToken = (req) => {
    if ((!req.headers.authorization ||
        !req.headers.authorization.startsWith("Bearer ")) &&
        !(req.cookies && req.cookies.__session)) {
        functions.logger.error("No Firebase ID token was passed as a Bearer token in the Authorization header.", "Make sure you authorize your request by providing the following HTTP header:", "Authorization: Bearer <Firebase ID Token>", "or by passing a \"__session\" cookie.");
        throw new utils_1.HexlinkError(403, "Unauthorized");
    }
    if (req.headers.authorization &&
        req.headers.authorization.startsWith("Bearer ")) {
        return req.headers.authorization.split("Bearer ")[1];
    }
    else if (req.cookies) {
        return req.cookies.__session;
    }
    else {
        throw new utils_1.HexlinkError(403, "Unauthorized");
    }
};
//# sourceMappingURL=zkp.js.map
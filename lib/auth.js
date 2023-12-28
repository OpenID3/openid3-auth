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
exports.verifySessionCookie = exports.getDeks = exports.sessionLogin = exports.loginWithPasskey = exports.getPasskeyChallenge = exports.registerUserWithPasskey = void 0;
const cors_1 = __importDefault(require("cors"));
const functions = __importStar(require("firebase-functions"));
const admin = __importStar(require("firebase-admin"));
const crypto_1 = __importDefault(require("crypto"));
const p256_1 = require("@noble/curves/p256");
const ethers_1 = require("ethers");
const cookie = __importStar(require("cookie"));
const utils_1 = require("./utils");
const gcloudKms_1 = require("./gcloudKms");
const ratelimiter_1 = require("./ratelimiter");
const auth_1 = require("./db/auth");
const account_1 = require("./account");
const asn1 = __importStar(require("asn1.js"));
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
exports.registerUserWithPasskey = functions.https.onRequest((req, res) => {
    return (0, cors_1.default)({ origin: true, credentials: true })(req, res, async () => {
        try {
            if (secrets.ENV !== "dev" && (await (0, ratelimiter_1.registerRateLimit)(req.ip || ""))) {
                throw new utils_1.HexlinkError(429, "Too many requests");
            }
            const address = await (0, account_1.getAccountAddress)(req.body);
            const nameHash = (0, utils_1.genNameHash)(req.body.username);
            const challenge = crypto_1.default
                .createHash("sha256")
                .update(Buffer.concat([
                Buffer.from("register", "utf-8"),
                (0, utils_1.toBuffer)(nameHash),
                (0, utils_1.toBuffer)(req.body.factory),
                (0, utils_1.toBuffer)(req.body.operator),
                (0, utils_1.toBuffer)(req.body.metadata),
                (0, utils_1.toBuffer)(req.body.dek), // dek
            ]))
                .digest("base64");
            validatePasskeySignature(req.body.clientDataJson, [
                ["challenge", challenge],
                ["origin", secrets.REACT_APP_ORIGIN],
            ], req.body.authData, req.body.signature, req.body.passkey);
            const csrfToken = crypto_1.default.randomBytes(32).toString("hex");
            const [, encDek, token] = await Promise.all([
                (0, auth_1.registerUser)(nameHash, address, req.body.passkey, req.body.factory, req.body.operator, req.body.metadata, csrfToken),
                (0, gcloudKms_1.encryptWithSymmKey)(req.body.dek, (0, utils_1.toBuffer)(address)),
                createNewUser(address),
            ]);
            res.status(200).json({
                token,
                address,
                csrfToken,
                encDek,
            });
        }
        catch (err) {
            (0, utils_1.handleError)(res, err);
        }
    });
});
async function createNewUser(address) {
    await admin.auth().createUser({ uid: address });
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
exports.getPasskeyChallenge = functions.https.onRequest((req, res) => {
    (0, cors_1.default)({ origin: true, credentials: true })(req, res, async () => {
        try {
            if (secrets.ENV !== "dev" &&
                (await (0, ratelimiter_1.getChallengeRateLimit)(req.ip || ""))) {
                throw new utils_1.HexlinkError(429, "Too many requests");
            }
            const address = ethers_1.ethers.getAddress(req.body.address);
            const auth = await (0, auth_1.getAuth)(address);
            if (auth == null) {
                throw new utils_1.HexlinkError(404, "User not found");
            }
            if (auth.challenge && auth.updatedAt.seconds + 180 > (0, utils_1.epoch)()) {
                res.status(200).json({ challenge: auth.challenge });
            }
            else {
                const challenge = crypto_1.default.randomBytes(32).toString("hex");
                await (0, auth_1.preAuth)(address, challenge);
                res.status(200).json({ challenge });
            }
        }
        catch (err) {
            (0, utils_1.handleError)(res, err);
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
exports.loginWithPasskey = functions.https.onRequest((req, res) => {
    (0, cors_1.default)({ origin: true, credentials: true })(req, res, async () => {
        try {
            const address = ethers_1.ethers.getAddress(req.body.address);
            const auth = await (0, auth_1.getAuth)(address);
            if (!auth?.challenge) {
                throw new utils_1.HexlinkError(404, "User not found or challenge not set");
            }
            if (auth.updatedAt.seconds + 180 < (0, utils_1.epoch)()) {
                throw new utils_1.HexlinkError(403, "invalid challenge");
            }
            const challenge = crypto_1.default
                .createHash("sha256")
                .update(Buffer.concat([
                Buffer.from("login", "utf-8"),
                (0, utils_1.toBuffer)(address),
                (0, utils_1.toBuffer)(auth.challenge),
                Buffer.from(req.body.encDek ?? "", "utf-8"),
                (0, utils_1.toBuffer)(req.body.newDek ?? ethers_1.ethers.ZeroHash), // new dek
            ]))
                .digest("base64");
            validatePasskeySignature(req.body.clientDataJson, [
                ["challenge", challenge],
                ["origin", secrets.REACT_APP_ORIGIN],
            ], req.body.authData, req.body.signature, auth.passkey);
            const csrfToken = crypto_1.default.randomBytes(32).toString("hex");
            const aad = (0, utils_1.toBuffer)(address);
            const [, token, dek, encNewDek] = await Promise.all([
                (0, auth_1.postAuth)(address, csrfToken),
                admin.auth().createCustomToken(address),
                (0, gcloudKms_1.decryptWithSymmKey)(req.body.encDek, aad),
                (0, gcloudKms_1.encryptWithSymmKey)(req.body.newDek, aad),
            ]);
            res.status(200).json({ token, csrfToken, dek, encNewDek });
        }
        catch (err) {
            (0, utils_1.handleError)(res, err);
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
exports.sessionLogin = functions.https.onRequest((req, res) => {
    (0, cors_1.default)({
        origin: true,
        credentials: true,
        allowedHeaders: ["Content-Type", "Set-Cookie"],
    })(req, res, async () => {
        try {
            const idToken = req.body.idToken;
            const csrfToken = req.body.csrfToken;
            const decoded = await admin.auth().verifyIdToken(idToken);
            const auth = await (0, auth_1.getAuth)(decoded.uid);
            // Guard against CSRF attacks.
            if (csrfToken !== auth?.csrfToken) {
                throw new utils_1.HexlinkError(401, "UNAUTHORIZED REQUEST");
            }
            // Only process if the user just signed in in the last 5 minutes.
            if (new Date().getTime() / 1000 - decoded.auth_time > 5 * 60) {
                throw new utils_1.HexlinkError(401, "recent sign in required");
            }
            const expiresIn = 60 * 60 * 24 * 7 * 1000; // valid for 7 days
            const sessionCookie = await admin
                .auth()
                .createSessionCookie(idToken, { expiresIn });
            res
                .cookie("__session", sessionCookie, {
                maxAge: expiresIn,
                httpOnly: true,
                secure: true,
                sameSite: "none",
            })
                .appendHeader("Cache-Control", "private")
                .status(200)
                .json({ success: true });
        }
        catch (err) {
            (0, utils_1.handleError)(res, err);
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
exports.getDeks = functions.https.onRequest((req, res) => {
    (0, cors_1.default)({ origin: true, credentials: true })(req, res, async () => {
        try {
            const claims = await (0, exports.verifySessionCookie)(req);
            const auth = await (0, auth_1.getAuth)(claims.uid);
            if (!auth || req.body.csrfToken != auth?.csrfToken) {
                throw new utils_1.HexlinkError(401, "Access denied");
            }
            const aad = (0, utils_1.toBuffer)(claims.uid);
            const [dek, encNewDek] = await Promise.all([
                (0, gcloudKms_1.decryptWithSymmKey)(req.body.encDek, aad),
                (0, gcloudKms_1.encryptWithSymmKey)(req.body.newDek, aad),
            ]);
            res.status(200).json({ dek, encNewDek });
        }
        catch (err) {
            (0, utils_1.handleError)(res, err);
        }
    });
});
const verifySessionCookie = async (req) => {
    const sessionCookie = cookie.parse(req.headers.cookie || "");
    const session = sessionCookie.__session;
    if (!session) {
        throw new utils_1.HexlinkError(401, "UNAUTHORIZED REQUEST");
    }
    try {
        return admin.auth().verifySessionCookie(session, true /** checkRevoked */);
    }
    catch (err) {
        console.log(err);
        throw new utils_1.HexlinkError(401, "UNAUTHORIZED REQUEST");
    }
};
exports.verifySessionCookie = verifySessionCookie;
const EcdsaSigAsnParse = asn1.define("EcdsaSig", function () {
    // eslint-disable-next-line no-invalid-this
    this.seq().obj(this.key("r").int(), this.key("s").int());
});
const validatePasskeySignature = (clientDataJson, expected, authData, // hex
signature, // hex
pubKey // hex
) => {
    const parsed = JSON.parse(clientDataJson);
    for (const [key, value] of expected) {
        if (parsed[key] !== value) {
            if (key === "challenge") {
                const decodedChallenge = Buffer.from(parsed[key], "base64").toString("utf-8");
                if (decodedChallenge !== value) {
                    throw new utils_1.HexlinkError(400, "invalid client data");
                }
            }
            else {
                if (parsed[key] !== value) {
                    throw new utils_1.HexlinkError(400, "invalid client data");
                }
            }
        }
    }
    const clientDataHash = crypto_1.default
        .createHash("sha256")
        .update(clientDataJson)
        .digest();
    const signedData = Buffer.concat([
        (0, utils_1.toBuffer)(authData),
        clientDataHash,
    ]);
    const signedDataHash = crypto_1.default
        .createHash("sha256")
        .update(signedData)
        .digest("hex");
    const uncompressedPubKey = ethers_1.ethers.solidityPacked(["uint8", "uint256", "uint256"], [4, (0, utils_1.formatHex)(pubKey.x), (0, utils_1.formatHex)(pubKey.y)]);
    const decoded = EcdsaSigAsnParse.decode((0, utils_1.toBuffer)(signature), "der");
    const newDecoded = {
        r: BigInt("0x" + decoded.r.toString("hex")),
        s: BigInt("0x" + decoded.s.toString("hex")),
    };
    if (!p256_1.secp256r1.verify(newDecoded, signedDataHash, uncompressedPubKey.slice(2) // remove "0x"
    )) {
        throw new utils_1.HexlinkError(400, "invalid signature");
    }
};
//# sourceMappingURL=auth.js.map
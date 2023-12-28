"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.genEciesKey = exports.signLoginRequest = exports.signRegisterRequest = exports.signWithPasskey = exports.genPasskey = void 0;
const p256_1 = require("@noble/curves/p256");
const eciesjs_1 = require("eciesjs");
const crypto_1 = __importDefault(require("crypto"));
const ethers_1 = require("ethers");
const utils_1 = require("../utils");
const genPasskey = (id) => {
    const privKey = p256_1.secp256r1.utils.randomPrivateKey();
    const pubKey = p256_1.secp256r1.getPublicKey(privKey);
    const point = p256_1.secp256r1.ProjectivePoint.fromHex(pubKey);
    const x = ethers_1.ethers.solidityPacked(["uint256"], [point.x]).slice(2);
    const y = ethers_1.ethers.solidityPacked(["uint256"], [point.y]).slice(2);
    return { privKey, pubKey: { x, y, id } };
};
exports.genPasskey = genPasskey;
const signWithPasskey = (challenge, origin, passkey) => {
    const clientDataJson = JSON.stringify({
        challenge,
        origin,
        somekey: "somevalue",
    });
    const clientDataHash = crypto_1.default.createHash("sha256")
        .update(clientDataJson)
        .digest();
    const authData = Buffer.concat([
        Buffer.from(passkey.pubKey.x),
        Buffer.from(passkey.pubKey.y),
        // sha256("somerandomdata")
        Buffer.from("dbdffb426fe23336753b7ccc6ced25bafea6616c92e8922a3d857d95cf30d4f0", "hex"),
    ]);
    const signedData = Buffer.concat([
        authData,
        clientDataHash,
    ]);
    const signedDataHash = crypto_1.default.createHash("sha256")
        .update(signedData)
        .digest("hex");
    const signature = p256_1.secp256r1.sign(signedDataHash, passkey.privKey);
    return {
        clientDataJson,
        authData: authData.toString("hex"),
        signature,
    };
};
exports.signWithPasskey = signWithPasskey;
const signRegisterRequest = (username, origin, factory, passkey, operator, metadata, dek) => {
    const uid = (0, utils_1.genNameHash)(username);
    const challenge = crypto_1.default.createHash("sha256").update(Buffer.concat([
        Buffer.from("register", "utf-8"),
        (0, utils_1.toBuffer)(uid),
        (0, utils_1.toBuffer)(factory),
        (0, utils_1.toBuffer)(operator),
        (0, utils_1.toBuffer)(metadata),
        (0, utils_1.toBuffer)(dek), // dek
    ])).digest("base64");
    return (0, exports.signWithPasskey)(challenge, origin, passkey);
};
exports.signRegisterRequest = signRegisterRequest;
const signLoginRequest = (address, origin, challenge, passkey, dek, // ciphertext
newDek) => {
    const signedChallenge = crypto_1.default.createHash("sha256").update(Buffer.concat([
        Buffer.from("login", "utf-8"),
        (0, utils_1.toBuffer)(address),
        (0, utils_1.toBuffer)(challenge),
        Buffer.from(dek ?? "", "utf-8"),
        (0, utils_1.toBuffer)(newDek ?? ethers_1.ethers.ZeroHash), // new dek
    ])).digest("base64");
    return (0, exports.signWithPasskey)(signedChallenge, origin, passkey);
};
exports.signLoginRequest = signLoginRequest;
const genEciesKey = () => {
    const privKey = new eciesjs_1.PrivateKey();
    return {
        privKey,
        pubKey: privKey.publicKey.toHex(),
    };
};
exports.genEciesKey = genEciesKey;
//# sourceMappingURL=passkey.js.map
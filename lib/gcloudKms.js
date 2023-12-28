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
exports.decryptWithSymmKey = exports.encryptWithSymmKey = void 0;
/* eslint-disable require-jsdoc */
const kms = __importStar(require("@google-cloud/kms"));
const crc32c = __importStar(require("fast-crc32c"));
const functions = __importStar(require("firebase-functions"));
const crypto_1 = __importDefault(require("crypto"));
const secrets = functions.config().doppler;
const client = new kms.KeyManagementServiceClient();
const DEV_ENC_ALGORITHM = "aes-256-gcm";
const encryptorConfig = () => ({
    projectId: secrets.FIREBASE_PROJECT_ID,
    locationId: secrets.GCP_KEY_LOCATION_GLOBAL,
    keyRingId: secrets.ENCRYPTOR_KEY_RING_ID,
    keyId: secrets.ENCRYPTOR_KEY_ID,
});
const getSymmKeyName = async function () {
    const config = encryptorConfig();
    return client.cryptoKeyPath(config.projectId, config.locationId, config.keyRingId, config.keyId);
};
const encryptWithDevKey = (plaintext, aad) => {
    const key = Buffer.from(secrets.DEV_KEY, "hex");
    const iv = Buffer.from(secrets.DEV_KEY_IV, "hex");
    const cipher = crypto_1.default.createCipheriv(DEV_ENC_ALGORITHM, key, iv);
    cipher.setAAD(aad);
    const encrypted = cipher.update(plaintext);
    const result = Buffer.concat([encrypted, cipher.final()]).toString("base64");
    return JSON.stringify({
        encrypted: result,
        authTag: cipher.getAuthTag().toString("hex"),
    });
};
const decryptWithDevKey = (text, aad) => {
    const { encrypted, authTag } = JSON.parse(text);
    const ciphertext = Buffer.from(encrypted, "base64");
    const key = Buffer.from(secrets.DEV_KEY, "hex");
    const iv = Buffer.from(secrets.DEV_KEY_IV, "hex");
    const decipher = crypto_1.default.createDecipheriv(DEV_ENC_ALGORITHM, key, iv);
    decipher.setAAD(aad);
    decipher.setAuthTag(Buffer.from(authTag, "hex"));
    const decrypted = decipher.update(ciphertext);
    return Buffer.concat([decrypted, decipher.final()]).toString("utf-8");
};
const encryptWithSymmKey = async function (plaintext, aad) {
    if (plaintext === undefined) {
        return undefined;
    }
    if (secrets.ENV === "dev") {
        return encryptWithDevKey(plaintext, aad);
    }
    const plaintextBuffer = Buffer.from(plaintext);
    const keyName = await getSymmKeyName();
    const plaintextCrc32c = crc32c.calculate(plaintextBuffer);
    const [encryptResponse] = await client.encrypt({
        name: keyName,
        plaintext: plaintextBuffer,
        additionalAuthenticatedData: aad,
        plaintextCrc32c: {
            value: plaintextCrc32c,
        },
    });
    const ciphertext = encryptResponse.ciphertext;
    if (!ciphertext ||
        !encryptResponse.verifiedPlaintextCrc32c ||
        !encryptResponse.ciphertextCrc32c ||
        crc32c.calculate(ciphertext) !==
            Number(encryptResponse.ciphertextCrc32c.value)) {
        throw new Error("Encrypt: request corrupted in-transit");
    }
    return Buffer.from(ciphertext).toString("base64");
};
exports.encryptWithSymmKey = encryptWithSymmKey;
const decryptWithSymmKey = async function (text, aad) {
    if (text === undefined) {
        return undefined;
    }
    if (secrets.ENV === "dev") {
        return decryptWithDevKey(text, aad);
    }
    const ciphertext = Buffer.from(text, "base64");
    const keyName = await getSymmKeyName();
    const ciphertextCrc32c = crc32c.calculate(ciphertext);
    const [decryptResponse] = await client.decrypt({
        name: keyName,
        additionalAuthenticatedData: aad,
        ciphertext: ciphertext,
        ciphertextCrc32c: {
            value: ciphertextCrc32c,
        },
    });
    const plaintextBuffer = Buffer.from(decryptResponse.plaintext);
    if (crc32c.calculate(plaintextBuffer) !==
        Number(decryptResponse.plaintextCrc32c.value)) {
        throw new Error("Decrypt: response corrupted in-transit");
    }
    return plaintextBuffer.toString("utf8");
};
exports.decryptWithSymmKey = decryptWithSymmKey;
//# sourceMappingURL=gcloudKms.js.map
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.formatHex = exports.toBuffer = exports.genNameHash = exports.SUBDOMAIN_NOT_ALLOWED = exports.INVALID_USER_NAME_NON_MIZU_NAME = exports.INVALID_USER_NAME_DISALLOWED_CHARACTERS = exports.INVALID_USER_NAME_EMTPY_LABEL = exports.INVALID_USER_NAME_TOO_SHORT = exports.sha256 = exports.sha3 = exports.handleError = exports.HexlinkError = exports.epoch = void 0;
const crypto_1 = __importDefault(require("crypto"));
const ethers_1 = require("ethers");
const epoch = () => {
    return Math.floor(new Date().getTime() / 1000);
};
exports.epoch = epoch;
class HexlinkError extends Error {
    constructor(code, message) {
        super(message);
        this.code = code;
    }
}
exports.HexlinkError = HexlinkError;
const handleError = function (res, err) {
    if (err instanceof HexlinkError) {
        res.status(err.code).json({ message: err.message });
    }
    else {
        console.log("Error: ", err);
        res.status(500).json({ message: "internal server error" });
    }
};
exports.handleError = handleError;
const sha3 = (data) => {
    return crypto_1.default.createHash("sha3-256").update(data).digest();
};
exports.sha3 = sha3;
const sha256 = (data) => {
    return crypto_1.default.createHash("sha256").update(data).digest();
};
exports.sha256 = sha256;
exports.INVALID_USER_NAME_TOO_SHORT = "invalid username: must be at least 5 characters";
exports.INVALID_USER_NAME_EMTPY_LABEL = "invalid username: empty label";
exports.INVALID_USER_NAME_DISALLOWED_CHARACTERS = "invalid username: disallowed characters";
exports.INVALID_USER_NAME_NON_MIZU_NAME = "invalid username: must end with mizu";
exports.SUBDOMAIN_NOT_ALLOWED = "invalid username: subdomain not allowed";
const genNameHash = (username) => {
    username = validateUsername(username);
    return nameHash(username);
};
exports.genNameHash = genNameHash;
// the name is with .mizu suffix
const validateUsername = (username) => {
    username = username.trim().toLowerCase();
    if (!username.endsWith(".mizu")) {
        throw new HexlinkError(400, exports.INVALID_USER_NAME_NON_MIZU_NAME);
    }
    const labels = username.split(".");
    if (labels.length > 2) {
        throw new HexlinkError(400, exports.SUBDOMAIN_NOT_ALLOWED);
    }
    if (labels[0].length < 5) {
        throw new HexlinkError(400, exports.INVALID_USER_NAME_TOO_SHORT);
    }
    if (!/^[a-z0-9]+$/.test(labels[0])) {
        throw new HexlinkError(400, exports.INVALID_USER_NAME_DISALLOWED_CHARACTERS);
    }
    return username;
};
const nameHash = (name) => {
    if (name == "") {
        return ethers_1.ethers.ZeroHash;
    }
    const index = name.indexOf(".");
    if (index === -1) {
        return ethers_1.ethers.solidityPackedKeccak256(["bytes32", "bytes32"], [nameHash(""), ethers_1.ethers.keccak256(ethers_1.ethers.toUtf8Bytes(name))]);
    }
    else {
        const label = name.slice(0, index);
        const remainder = name.slice(index + 1);
        return ethers_1.ethers.solidityPackedKeccak256(["bytes32", "bytes32"], [nameHash(remainder), ethers_1.ethers.keccak256(ethers_1.ethers.toUtf8Bytes(label))]);
    }
};
const toBuffer = (data) => {
    const normalized = data.startsWith("0x") ? data.slice(2) : data;
    return Buffer.from(normalized, "hex");
};
exports.toBuffer = toBuffer;
const formatHex = (data) => {
    if (data.startsWith("0x")) {
        return data;
    }
    return "0x" + data;
};
exports.formatHex = formatHex;
//# sourceMappingURL=utils.js.map
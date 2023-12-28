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
exports.genZkAdminSignature = exports.buildZkAdminData = exports.submitUserOp = exports.genUserOpHash = exports.getPimlicoBundler = void 0;
const ethers_1 = require("ethers");
const providers_1 = require("@ethersproject/providers");
const utils_1 = require("@account-abstraction/utils");
const base64url_1 = __importDefault(require("base64url"));
const functions = __importStar(require("firebase-functions"));
const secrets = functions.config().doppler || {};
const ENTRY_POINT_ADDRESS = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789";
const getPimlicoBundler = (chain) => {
    const apiKey = secrets.PIMLICO_API_KEY;
    return new providers_1.StaticJsonRpcProvider(`https://api.pimlico.io/v1/${chain.name}/rpc?apikey=${apiKey}`);
};
exports.getPimlicoBundler = getPimlicoBundler;
const genUserOpHash = async (chain, op) => {
    const opHash = ethers_1.ethers.keccak256(ethers_1.ethers.AbiCoder.defaultAbiCoder().encode([
        "address",
        "uint256",
        "bytes32",
        "bytes32",
        "uint256",
        "uint256",
        "uint256",
        "uint256",
        "uint256",
        "bytes32",
    ], [
        op.sender,
        op.nonce,
        ethers_1.ethers.keccak256(op.initCode),
        ethers_1.ethers.keccak256(op.callData),
        op.callGasLimit,
        op.verificationGasLimit,
        op.preVerificationGas,
        op.maxFeePerGas,
        op.maxPriorityFeePerGas,
        ethers_1.ethers.keccak256(op.paymasterAndData),
    ]));
    return ethers_1.ethers.keccak256(ethers_1.ethers.AbiCoder.defaultAbiCoder().encode(["bytes32", "address", "uint256"], [opHash, ENTRY_POINT_ADDRESS, chain.id]));
};
exports.genUserOpHash = genUserOpHash;
async function submitUserOp(chain, op) {
    const bundler = (0, exports.getPimlicoBundler)(chain);
    const hexifiedUserOp = (0, utils_1.deepHexlify)(await ethers_1.ethers.resolveProperties(op));
    const uoHash = await bundler.send("eth_sendUserOperation", [
        hexifiedUserOp,
        ENTRY_POINT_ADDRESS,
    ]);
    console.log("UserOperation: ", uoHash);
    return uoHash;
}
exports.submitUserOp = submitUserOp;
const buildZkAdminData = (admin, accountHash) => {
    const adminData = admin.interface.encodeFunctionData("linkAccount", [accountHash]);
    return ethers_1.ethers.solidityPacked(["address", "bytes"], [admin.target, adminData]);
};
exports.buildZkAdminData = buildZkAdminData;
function genZkAdminSignature(jwt, proof) {
    const jwtSignature = "0x" + base64url_1.default.toBuffer(jwt.jwtSignature).toString("hex");
    const validationData = ethers_1.ethers.AbiCoder.defaultAbiCoder().encode(["tuple(tuple(bytes32, string, bytes32, bytes), bytes32, bytes)"], [
        [
            [
                jwt.kidSha256,
                jwt.iat,
                jwt.jwtHeaderAndPayloadHash,
                jwtSignature,
            ],
            proof.verifier_digest,
            proof.proof,
        ],
    ]);
    return ethers_1.ethers.solidityPacked(["uint8", "bytes"], [0, validationData]);
}
exports.genZkAdminSignature = genZkAdminSignature;
//# sourceMappingURL=userop.js.map
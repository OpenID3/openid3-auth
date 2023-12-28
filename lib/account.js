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
Object.defineProperty(exports, "__esModule", { value: true });
exports.getAccountAddress = exports.getProvider = exports.predictDeterministicAddressOffline = exports.buildAccountInitData = exports.buildPasskeyAdminData = void 0;
/* eslint-disable camelcase */
const contracts_1 = require("@openid3/contracts");
const functions = __importStar(require("firebase-functions"));
const ethers_1 = require("ethers");
const secrets = functions.config().doppler || {};
function formatHex(hex) {
    if (hex.startsWith("0x")) {
        return hex;
    }
    return "0x" + hex;
}
function buildPasskeyAdminData(passkey) {
    const adminData = contracts_1.PasskeyAdmin__factory.createInterface().encodeFunctionData("setPasskey", [
        {
            pubKeyX: BigInt(formatHex(passkey.x)),
            pubKeyY: BigInt(formatHex(passkey.y)),
        },
        passkey.id,
    ]);
    return ethers_1.ethers.solidityPacked(["address", "bytes"], [secrets.CONTRACT_V0_0_8_PASSSKEY_ADMIN, adminData]);
}
exports.buildPasskeyAdminData = buildPasskeyAdminData;
function buildAccountInitData(passkey, operator, metadata) {
    return contracts_1.OpenId3Account__factory.createInterface().encodeFunctionData("initialize", [buildPasskeyAdminData(passkey), operator, formatHex(metadata)]);
}
exports.buildAccountInitData = buildAccountInitData;
function predictDeterministicAddressOffline(impl, deployer, salt) {
    impl = impl.toLowerCase().slice(2);
    deployer = deployer.toLowerCase().slice(2);
    salt = salt.slice(2);
    let assembly = `3d602d80600a3d3981f3363d3d373d3d3d363d73${impl}5af43d82803e903d91602b57fd5bf3ff${deployer}${salt}`;
    assembly += ethers_1.ethers
        .solidityPackedKeccak256(["bytes"], ["0x" + assembly.slice(0, 110)])
        .slice(2);
    return ethers_1.ethers.getAddress(ethers_1.ethers
        .solidityPackedKeccak256(["bytes"], ["0x" + assembly.slice(110, 280)])
        .slice(-40));
}
exports.predictDeterministicAddressOffline = predictDeterministicAddressOffline;
// we have unified address across all chains so it doesn't
// matter which chain id we use
const getProvider = (chainId = 11155111) => {
    return new ethers_1.InfuraProvider(chainId, secrets.INFURA_API_KEY);
};
exports.getProvider = getProvider;
async function getAccountAddress(input) {
    const provider = (0, exports.getProvider)();
    const accountData = buildAccountInitData(input.passkey, input.operator, input.metadata);
    const salt = ethers_1.ethers.keccak256(accountData);
    const factory = contracts_1.AccountFactory__factory.connect(input.factory, provider);
    return await factory.predictClonedAddress(salt);
}
exports.getAccountAddress = getAccountAddress;
//# sourceMappingURL=account.js.map
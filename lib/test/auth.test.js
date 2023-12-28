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
const assert_1 = __importDefault(require("assert"));
const passkey_1 = require("./passkey");
const firebase_functions_test_1 = __importDefault(require("firebase-functions-test"));
const crypto_1 = __importDefault(require("crypto"));
const testEnv = (0, firebase_functions_test_1.default)();
const ORIGIN = "https://localhost:3000";
const CONTRACT_V0_0_8_ACCOUNT_FACTORY = "0xa5727531591A3dE7ADaC6b3759bEF5BD5549c121";
testEnv.mockConfig({
    doppler: {
        ENV: "dev",
        DEV_KEY: crypto_1.default.randomBytes(32).toString("hex"),
        DEV_KEY_IV: crypto_1.default.randomBytes(16).toString("hex"),
        ORIGIN,
        CONTRACT_V0_0_8_ACCOUNT_PROXY: "0x7CB55518ad352E220882935E419F7Fd3cA68B21A",
        CONTRACT_V0_0_8_ACCOUNT_FACTORY,
        CONTRACT_V0_0_8_PASSSKEY_ADMIN: "0x3dAdb4660d8e99B839d1eB6cAb6bB2Fd0414DcF1",
    },
});
jest.mock("firebase-admin", () => {
    return {
        auth: jest.fn().mockReturnThis(),
        createUser: jest.fn(() => Promise.resolve()),
        createCustomToken: jest.fn((uid) => Promise.resolve(uid)),
        verifyIdToken: jest.fn((token) => Promise.resolve({ uid: token })),
    };
});
// import after testEnv is setup and properly mocked
// otherwise the env won't inject into the functions
const auth = __importStar(require("../auth"));
const adb = __importStar(require("../db/auth"));
const utils = __importStar(require("../utils"));
const acc = __importStar(require("../account"));
const firestore_1 = require("@google-cloud/firestore");
const gcloudKms_1 = require("../gcloudKms");
const ethers_1 = require("ethers");
const utils_1 = require("../utils");
const account = "0x" + crypto_1.default.randomBytes(20).toString("hex");
jest.spyOn(acc, "getAccountAddress").mockImplementation(() => Promise.resolve(account));
jest.spyOn(adb, "getAuth").mockImplementation(() => Promise.resolve(null));
jest.spyOn(adb, "registerUser").mockImplementation(() => Promise.resolve());
describe("registerPasskey", () => {
    let passkey;
    let operator;
    let pkId;
    const metadata = ethers_1.ethers.ZeroHash.slice(2);
    const dek = crypto_1.default.randomBytes(32).toString("hex");
    const newDek = crypto_1.default.randomBytes(32).toString("hex");
    const factory = CONTRACT_V0_0_8_ACCOUNT_FACTORY;
    let encDek;
    let encNewDek;
    beforeAll(async () => {
        jest.clearAllMocks();
        jest.useFakeTimers();
        pkId = "passkey1";
        passkey = (0, passkey_1.genPasskey)(pkId);
        operator = ethers_1.ethers.Wallet.createRandom();
        const aad = utils.toBuffer(account);
        encDek = (await (0, gcloudKms_1.encryptWithSymmKey)(dek, aad));
        encNewDek = (await (0, gcloudKms_1.encryptWithSymmKey)(newDek, aad));
    });
    const buildRegisterRequest = (username) => {
        const { clientDataJson, authData, signature } = (0, passkey_1.signRegisterRequest)(username, ORIGIN, factory, passkey, operator.address, metadata, dek);
        return {
            headers: { origin: true },
            body: {
                username,
                factory,
                passkey: passkey.pubKey,
                operator: operator.address,
                clientDataJson,
                authData,
                signature: signature.toCompactHex(),
                metadata,
                dek,
            },
        };
    };
    const buildLoginRequest = (address, challenge) => {
        const { clientDataJson, authData, signature } = (0, passkey_1.signLoginRequest)(address, ORIGIN, challenge, passkey, encDek, newDek);
        return {
            headers: { origin: true },
            body: {
                address,
                clientDataJson,
                authData,
                signature: signature.toCompactHex(),
                encDek,
                newDek,
            },
        };
    };
    const buildResponse = (status, jsonValidator) => {
        return {
            setHeader: () => {
                return;
            },
            getHeader: () => {
                return;
            },
            status: (returnedStatus) => {
                assert_1.default.equal(returnedStatus, status);
                return { json: jsonValidator };
            },
        };
    };
    test("username validation", () => {
        const validateHexlinkError = (name, code, message) => {
            try {
                (0, utils_1.genNameHash)(name);
            }
            catch (e) {
                expect(e).toBeInstanceOf(utils_1.HexlinkError);
                expect(e.code).toEqual(code);
                expect(e.message).toEqual(message);
            }
        };
        validateHexlinkError("peter", 400, utils.INVALID_USER_NAME_NON_MIZU_NAME);
        validateHexlinkError("some.mizu", 400, utils.INVALID_USER_NAME_TOO_SHORT);
        validateHexlinkError(".mizu", 400, utils.INVALID_USER_NAME_TOO_SHORT);
        validateHexlinkError("sub.peter.mizu", 400, utils.SUBDOMAIN_NOT_ALLOWED);
        validateHexlinkError("sub_peter.mizu", 400, utils.INVALID_USER_NAME_DISALLOWED_CHARACTERS);
        expect((0, utils_1.genNameHash)("peter.mizu")).toEqual((0, utils_1.genNameHash)(" PETER.MIZU "));
    });
    test("it should register a new user with passkey", (done) => {
        const username = "peter.mizu";
        const jsonValidator = (response) => {
            expect(response).toHaveProperty("token");
            expect(encDek).toEqual(response.encDek);
            done();
        };
        const req = buildRegisterRequest(username);
        const res = buildResponse(200, jsonValidator);
        auth.registerUserWithPasskey(req, res);
    });
    test("it should throw if user already exists", (done) => {
        jest.spyOn(adb, "registerUser").mockImplementation(() => {
            throw new utils_1.HexlinkError(400, "name already taken");
        });
        const jsonValidator = (response) => {
            expect(response).toHaveProperty("message");
            expect(response.message).toEqual("name already taken");
            done();
        };
        const req = buildRegisterRequest("peter.mizu");
        const res = buildResponse(400, jsonValidator);
        auth.registerUserWithPasskey(req, res);
    });
    test("the user should login with challenge", async () => {
        const username = "peter.mizu";
        const userId = utils.genNameHash(username);
        const authDb = {
            passkey: passkey.pubKey,
            challenge: "",
            updatedAt: new firestore_1.Timestamp(utils.epoch(), 0),
            csrfToken: "",
        };
        jest
            .spyOn(adb, "preAuth")
            .mockImplementation((_uid, challenge) => {
            authDb.challenge = challenge;
            authDb.updatedAt = new firestore_1.Timestamp(utils.epoch(), 0);
            return Promise.resolve();
        });
        jest
            .spyOn(adb, "postAuth")
            .mockImplementation((_uid, csrfToken) => {
            authDb.csrfToken = csrfToken;
            return Promise.resolve();
        });
        jest
            .spyOn(adb, "getAuth")
            .mockImplementation(() => Promise.resolve(authDb));
        const req = {
            headers: { origin: true },
            body: { uid: userId },
        };
        const firstDone = Promise.resolve();
        const jsonValidator = (response) => {
            expect(response).toHaveProperty("challenge");
            expect(response.challenge).toEqual(authDb.challenge);
            firstDone;
        };
        const res = buildResponse(200, jsonValidator);
        await auth.getPasskeyChallenge(req, res);
        await firstDone;
        const loginReq = buildLoginRequest(account, authDb.challenge);
        const secondDone = Promise.resolve();
        const loginRes = buildResponse(200, (response) => {
            expect(response).toHaveProperty("token");
            expect(authDb.csrfToken).toEqual(response.csrfToken);
            expect(dek).toEqual(response.dek);
            expect(encNewDek).toEqual(response.encNewDek);
            secondDone;
        });
        await auth.loginWithPasskey(loginReq, loginRes);
        await secondDone;
    });
    test("it should throw if challenge or origin does not match", async () => {
        const challenge = utils.sha256("valid_challenge").toString("hex");
        const authDb = {
            passkey: passkey.pubKey,
            challenge: "",
            updatedAt: new firestore_1.Timestamp(utils.epoch(), 0),
            csrfToken: "",
        };
        jest
            .spyOn(adb, "getAuth")
            .mockImplementation(() => Promise.resolve(authDb));
        jest
            .spyOn(adb, "postAuth")
            .mockImplementation((_uid, csrfToken) => {
            authDb.csrfToken = csrfToken;
            return Promise.resolve();
        });
        // challenge not set in server
        const loginReq1 = buildLoginRequest(account, challenge);
        const firstDone = Promise.resolve();
        const loginRes1 = buildResponse(404, (response) => {
            expect(response.message).toEqual("User not found or challenge not set");
            firstDone;
        });
        await auth.loginWithPasskey(loginReq1, loginRes1);
        await firstDone;
        // challenge mismatch
        authDb.challenge = challenge;
        const invalidChallenge = utils.sha256("invalid_challenge").toString("hex");
        const invalidLoginReq = buildLoginRequest(account, invalidChallenge);
        const secondDone = Promise.resolve();
        const loginRes2 = buildResponse(400, (response) => {
            expect(response.message).toEqual("invalid client data");
            secondDone;
        });
        await auth.loginWithPasskey(invalidLoginReq, loginRes2);
        await secondDone;
        // valid client data but invalid signature
        const validLoginReq = buildLoginRequest(account, challenge);
        invalidLoginReq.body.clientDataJson = validLoginReq.body.clientDataJson;
        const loginRes3 = buildResponse(400, (response) => {
            expect(response.message).toEqual("invalid signature");
        });
        await auth.loginWithPasskey(invalidLoginReq, loginRes3);
    });
});
//# sourceMappingURL=auth.test.js.map
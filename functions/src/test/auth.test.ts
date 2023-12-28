import assert from "assert";
import {
  Key,
  genPasskey,
  signLoginRequest,
  signRegisterRequest,
} from "./passkey";

import ftest from "firebase-functions-test";
import crypto from "crypto";

const testEnv = ftest();
const ORIGIN = "https://localhost:3000";
const CONTRACT_V0_0_8_ACCOUNT_FACTORY =
  "0xa5727531591A3dE7ADaC6b3759bEF5BD5549c121";
testEnv.mockConfig({
  doppler: {
    ENV: "dev",
    DEV_KEY: crypto.randomBytes(32).toString("hex"),
    DEV_KEY_IV: crypto.randomBytes(16).toString("hex"),
    ORIGIN,
    CONTRACT_V0_0_8_ACCOUNT_PROXY: "0x7CB55518ad352E220882935E419F7Fd3cA68B21A",
    CONTRACT_V0_0_8_ACCOUNT_FACTORY,
    CONTRACT_V0_0_8_PASSSKEY_ADMIN:
      "0x3dAdb4660d8e99B839d1eB6cAb6bB2Fd0414DcF1",
  },
});

jest.mock("firebase-admin", () => {
  return {
    auth: jest.fn().mockReturnThis(),
    createUser: jest.fn(() => Promise.resolve()),
    createCustomToken: jest.fn((uid: string) => Promise.resolve(uid)),
    verifyIdToken: jest.fn((token: string) => Promise.resolve({uid: token})),
  };
});

// import after testEnv is setup and properly mocked
// otherwise the env won't inject into the functions
import * as auth from "../auth";
import * as adb from "../db/auth";
import * as utils from "../utils";
import * as acc from "../account";
import {Timestamp} from "@google-cloud/firestore";
import {encryptWithSymmKey} from "../gcloudKms";
import {ethers} from "ethers";
import {HexlinkError, genNameHash} from "../utils";

const account: string = "0x" + crypto.randomBytes(20).toString("hex");
jest.spyOn(acc, "getAccountAddress").mockImplementation(
    () => Promise.resolve(account));
jest.spyOn(adb, "getAuth").mockImplementation(() => Promise.resolve(null));
jest.spyOn(adb, "registerUser").mockImplementation(() => Promise.resolve());

describe("registerPasskey", () => {
  let passkey: Key;
  let operator: ethers.HDNodeWallet;
  let pkId: string;
  const metadata: string = ethers.ZeroHash.slice(2);
  const dek = crypto.randomBytes(32).toString("hex");
  const newDek = crypto.randomBytes(32).toString("hex");
  const factory = CONTRACT_V0_0_8_ACCOUNT_FACTORY;
  let encDek: string;
  let encNewDek: string;

  beforeAll(async () => {
    jest.clearAllMocks();
    jest.useFakeTimers();
    pkId = "passkey1";
    passkey = genPasskey(pkId);
    operator = ethers.Wallet.createRandom();
    const aad = utils.toBuffer(account);
    encDek = (await encryptWithSymmKey(dek, aad)) as string;
    encNewDek = (await encryptWithSymmKey(newDek, aad)) as string;
  });

  const buildRegisterRequest = (username: string) => {
    const {clientDataJson, authData, signature} = signRegisterRequest(
        username,
        ORIGIN,
        factory,
        passkey,
        operator.address,
        metadata,
        dek
    );
    return {
      headers: {origin: true},
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

  const buildLoginRequest = (address: string, challenge: string) => {
    const {clientDataJson, authData, signature} = signLoginRequest(
        address,
        ORIGIN,
        challenge,
        passkey,
        encDek,
        newDek
    );
    return {
      headers: {origin: true},
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

  const buildResponse = (status: number, jsonValidator: any) => {
    return {
      setHeader: () => {
        return;
      },
      getHeader: () => {
        return;
      },
      status: (returnedStatus: number) => {
        assert.equal(returnedStatus, status);
        return {json: jsonValidator};
      },
    };
  };

  test("username validation", () => {
    const validateHexlinkError = (
        name: string,
        code: number,
        message: string
    ) => {
      try {
        genNameHash(name);
      } catch (e) {
        expect(e).toBeInstanceOf(HexlinkError);
        expect((e as HexlinkError).code).toEqual(code);
        expect((e as HexlinkError).message).toEqual(message);
      }
    };

    validateHexlinkError("peter", 400, utils.INVALID_USER_NAME_NON_MIZU_NAME);
    validateHexlinkError("some.mizu", 400, utils.INVALID_USER_NAME_TOO_SHORT);
    validateHexlinkError(".mizu", 400, utils.INVALID_USER_NAME_TOO_SHORT);
    validateHexlinkError("sub.peter.mizu", 400, utils.SUBDOMAIN_NOT_ALLOWED);
    validateHexlinkError(
        "sub_peter.mizu",
        400,
        utils.INVALID_USER_NAME_DISALLOWED_CHARACTERS
    );
    expect(genNameHash("peter.mizu")).toEqual(genNameHash(" PETER.MIZU "));
  });

  test("it should register a new user with passkey", (done: any) => {
    const username = "peter.mizu";
    const jsonValidator = (response: any) => {
      expect(response).toHaveProperty("token");
      expect(encDek).toEqual(response.encDek);
      done();
    };
    const req = buildRegisterRequest(username);
    const res = buildResponse(200, jsonValidator);
    auth.registerUserWithPasskey(req as any, res as any);
  });

  test("it should throw if user already exists", (done: any) => {
    jest.spyOn(adb, "registerUser").mockImplementation(() => {
      throw new HexlinkError(400, "name already taken");
    });
    const jsonValidator = (response: any) => {
      expect(response).toHaveProperty("message");
      expect(response.message).toEqual("name already taken");
      done();
    };
    const req = buildRegisterRequest("peter.mizu");
    const res = buildResponse(400, jsonValidator);
    auth.registerUserWithPasskey(req as any, res as any);
  });

  test("the user should login with challenge", async () => {
    const username = "peter.mizu";
    const userId = utils.genNameHash(username);
    const authDb: adb.Auth = {
      passkey: passkey.pubKey,
      challenge: "",
      updatedAt: new Timestamp(utils.epoch(), 0),
      csrfToken: "",
    };
    jest
        .spyOn(adb, "preAuth")
        .mockImplementation((_uid: string, challenge: string) => {
          authDb.challenge = challenge;
          authDb.updatedAt = new Timestamp(utils.epoch(), 0);
          return Promise.resolve();
        });
    jest
        .spyOn(adb, "postAuth")
        .mockImplementation((_uid: string, csrfToken: string) => {
          authDb.csrfToken = csrfToken;
          return Promise.resolve();
        });
    jest
        .spyOn(adb, "getAuth")
        .mockImplementation(() => Promise.resolve(authDb));
    const req = {
      headers: {origin: true},
      body: {uid: userId},
    };
    const firstDone = Promise.resolve();
    const jsonValidator = (response: any) => {
      expect(response).toHaveProperty("challenge");
      expect(response.challenge).toEqual(authDb.challenge);
      firstDone;
    };
    const res = buildResponse(200, jsonValidator);
    await auth.getPasskeyChallenge(req as any, res as any);
    await firstDone;

    const loginReq = buildLoginRequest(account, authDb.challenge!);
    const secondDone = Promise.resolve();
    const loginRes = buildResponse(200, (response: any) => {
      expect(response).toHaveProperty("token");
      expect(authDb.csrfToken).toEqual(response.csrfToken);
      expect(dek).toEqual(response.dek);
      expect(encNewDek).toEqual(response.encNewDek);
      secondDone;
    });
    await auth.loginWithPasskey(loginReq as any, loginRes as any);
    await secondDone;
  });

  test("it should throw if challenge or origin does not match", async () => {
    const challenge = utils.sha256("valid_challenge").toString("hex");
    const authDb: adb.Auth = {
      passkey: passkey.pubKey,
      challenge: "",
      updatedAt: new Timestamp(utils.epoch(), 0),
      csrfToken: "",
    };
    jest
        .spyOn(adb, "getAuth")
        .mockImplementation(() => Promise.resolve(authDb));

    jest
        .spyOn(adb, "postAuth")
        .mockImplementation((_uid: string, csrfToken: string) => {
          authDb.csrfToken = csrfToken;
          return Promise.resolve();
        });

    // challenge not set in server
    const loginReq1 = buildLoginRequest(account, challenge);
    const firstDone = Promise.resolve();
    const loginRes1 = buildResponse(404, (response: any) => {
      expect(response.message).toEqual("User not found or challenge not set");
      firstDone;
    });
    await auth.loginWithPasskey(loginReq1 as any, loginRes1 as any);
    await firstDone;

    // challenge mismatch
    authDb.challenge = challenge;
    const invalidChallenge = utils.sha256("invalid_challenge").toString("hex");
    const invalidLoginReq = buildLoginRequest(account, invalidChallenge);
    const secondDone = Promise.resolve();
    const loginRes2 = buildResponse(400, (response: any) => {
      expect(response.message).toEqual("invalid client data");
      secondDone;
    });
    await auth.loginWithPasskey(invalidLoginReq as any, loginRes2 as any);
    await secondDone;

    // valid client data but invalid signature
    const validLoginReq = buildLoginRequest(account, challenge);
    invalidLoginReq.body.clientDataJson = validLoginReq.body.clientDataJson;
    const loginRes3 = buildResponse(400, (response: any) => {
      expect(response.message).toEqual("invalid signature");
    });
    await auth.loginWithPasskey(invalidLoginReq as any, loginRes3 as any);
  });
});

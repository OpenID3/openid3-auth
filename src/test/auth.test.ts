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
testEnv.mockConfig({
  doppler: {
    ENV: "dev",
    DEV_KEY: crypto.randomBytes(32).toString("hex"),
    DEV_KEY_IV: crypto.randomBytes(16).toString("hex"),
    ORIGIN,
    CONTRACT_V0_0_8_ACCOUNT_PROXY: "0x7CB55518ad352E220882935E419F7Fd3cA68B21A",
    CONTRACT_V0_0_8_ACCOUNT_FACTORY:
      "0xa5727531591A3dE7ADaC6b3759bEF5BD5549c121",
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
import * as db from "../db";
import * as utils from "../utils";
import {Timestamp} from "@google-cloud/firestore";
import {encryptWithSymmKey} from "../gcloudKms";
import {ethers} from "ethers";
import {getAccountAddress} from "../account";
import {HexlinkError} from "../utils";

jest.spyOn(db, "getUser").mockImplementation(() => Promise.resolve(null));
jest.spyOn(db, "registerUser").mockImplementation(() => Promise.resolve());

describe("registerPasskey", () => {
  let passkey: Key;
  let operator: ethers.HDNodeWallet;
  let pkId: string;
  const metadata: string = ethers.ZeroHash.slice(2);
  const salt = crypto.randomBytes(32).toString("hex");
  const newSalt = crypto.randomBytes(32).toString("hex");
  let encryptedSalt: string;
  let encryptedNewSalt: string;

  beforeAll(async () => {
    jest.clearAllMocks();
    jest.useFakeTimers();
    pkId = "passkey1";
    passkey = genPasskey(pkId);
    operator = ethers.Wallet.createRandom();
    encryptedSalt = await encryptWithSymmKey(salt);
    encryptedNewSalt = await encryptWithSymmKey(newSalt);
  });

  const buildRegisterRequest = (username: string) => {
    const {clientDataJson, authData, signature} = signRegisterRequest(
        username,
        ORIGIN,
        passkey,
        operator.address,
        metadata,
        salt
    );
    return {
      headers: {origin: true},
      body: {
        username,
        passkey: passkey.pubKey,
        operator: operator.address,
        clientDataJson,
        authData,
        signature: signature.toCompactHex(),
        metadata,
        salt,
      },
    };
  };

  const buildLoginRequest = (
      address: string,
      challenge: string,
      encryptedSalt?: string,
      newSalt?: string
  ) => {
    const {clientDataJson, authData, signature} = signLoginRequest(
        address,
        ORIGIN,
        challenge,
        passkey,
        encryptedSalt,
        newSalt
    );
    return {
      headers: {origin: true},
      body: {
        address,
        clientDataJson,
        authData,
        signature: signature.toCompactHex(),
        encryptedSalt,
        newSalt,
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

  test("it should register a new user with passkey", (done: any) => {
    const username = "SOME.user.mizu";
    const jsonValidator = (response: any) => {
      expect(response).toHaveProperty("token");
      expect(encryptedSalt).toEqual(response.encryptedSalt);
      done();
    };
    const req = buildRegisterRequest(username);
    const res = buildResponse(200, jsonValidator);
    auth.registerUserWithPasskey(req as any, res as any);
  });

  test("it should throw with too short username", (done: any) => {
    const username = "some.mizu";
    const jsonValidator = (response: any) => {
      expect(response).toHaveProperty("message");
      expect(response.message).toEqual(utils.INVALID_USER_NAME_TOO_SHORT);
      done();
    };
    const req = buildRegisterRequest(username);
    const res = buildResponse(400, jsonValidator);
    auth.registerUserWithPasskey(req as any, res as any);
  });

  test("it should throw with disallowed characters", (done: any) => {
    const username = "some_user.mizu";
    const jsonValidator = (response: any) => {
      expect(response).toHaveProperty("message");
      expect(response.message).toEqual(
          utils.INVALID_USER_NAME_DISALLOWED_CHARACTERS
      );
      done();
    };
    const req = buildRegisterRequest(username);
    const res = buildResponse(400, jsonValidator);
    auth.registerUserWithPasskey(req as any, res as any);
  });

  test("it should throw with empty label", (done: any) => {
    const username = "SOME..user.mizu";
    const jsonValidator = (response: any) => {
      expect(response).toHaveProperty("message");
      expect(response.message).toEqual(utils.INVALID_USER_NAME_EMTPY_LABEL);
      done();
    };
    const req = buildRegisterRequest(username);
    const res = buildResponse(400, jsonValidator);
    auth.registerUserWithPasskey(req as any, res as any);
  });

  test("it should throw if user already exists", (done: any) => {
    jest.spyOn(db, "registerUser").mockImplementation(() => {
      throw new HexlinkError(400, "name already taken");
    });
    const jsonValidator = (response: any) => {
      expect(response).toHaveProperty("message");
      expect(response.message).toEqual("name already taken");
      done();
    };
    const req = buildRegisterRequest("some.USER.mizu");
    const res = buildResponse(400, jsonValidator);
    auth.registerUserWithPasskey(req as any, res as any);
  });

  test("the user should login with challenge", async () => {
    const username = "some.user.mizu";
    const userId = utils.genNameHash(username);
    const userDb: db.User = {
      passkey: {id: pkId, ...passkey.pubKey},
      operator: operator.address,
      metadata,
      loginStatus: {
        challenge: "",
        updatedAt: new Timestamp(utils.epoch(), 0),
      },
      createdAt: new Timestamp(utils.epoch(), 0),
      csrfToken: "",
    };
    const account = getAccountAddress(
        userDb.passkey,
        userDb.operator,
        userDb.metadata
    );

    jest
        .spyOn(db, "preAuth")
        .mockImplementation((_uid: string, challenge: string) => {
          userDb.loginStatus = {
            challenge,
            updatedAt: new Timestamp(utils.epoch(), 0),
          };
          return Promise.resolve();
        });
    jest
        .spyOn(db, "postAuth")
        .mockImplementation((_uid: string, csrfToken: string) => {
          userDb.csrfToken = csrfToken;
          return Promise.resolve();
        });
    jest.spyOn(db, "getUser").mockImplementation(() => Promise.resolve(userDb));
    const req = {
      headers: {origin: true},
      body: {uid: userId},
    };
    const firstDone = Promise.resolve();
    const jsonValidator = (response: any) => {
      expect(response).toHaveProperty("challenge");
      expect(response.challenge).toEqual(userDb.loginStatus.challenge);
      firstDone;
    };
    const res = buildResponse(200, jsonValidator);
    await auth.getPasskeyChallenge(req as any, res as any);
    await firstDone;

    const loginReq = buildLoginRequest(
        account,
        userDb.loginStatus.challenge,
        encryptedSalt,
        newSalt
    );
    const secondDone = Promise.resolve();
    const loginRes = buildResponse(200, (response: any) => {
      expect(response).toHaveProperty("token");
      const expectedDek = ethers.solidityPackedKeccak256(
          ["bytes32", "bytes32"],
          ["0x" + salt, ethers.zeroPadValue(account, 32)]
      );
      expect(expectedDek.slice(2)).toEqual(response.dek);
      expect(encryptedNewSalt).toEqual(response.encryptedNewSalt);
      expect(userDb.csrfToken).toEqual(response.csrfToken);
      secondDone;
    });
    await auth.loginWithPasskey(loginReq as any, loginRes as any);
    await secondDone;
  });

  test("it should throw if challenge or origin does not match", async () => {
    const challenge = utils.sha256("valid_challenge").toString("hex");
    const userDb: db.User = {
      passkey: {id: pkId, ...passkey.pubKey},
      operator: operator.address,
      metadata,
      loginStatus: {
        challenge,
        updatedAt: new Timestamp(utils.epoch(), 0),
      },
      createdAt: new Timestamp(utils.epoch(), 0),
      csrfToken: "",
    };
    const account = getAccountAddress(
        userDb.passkey,
        userDb.operator,
        userDb.metadata
    );

    jest
        .spyOn(db, "postAuth")
        .mockImplementation((_uid: string, csrfToken: string) => {
          userDb.csrfToken = csrfToken;
          return Promise.resolve();
        });
    jest.spyOn(db, "getUser").mockImplementation(() => Promise.resolve(userDb));
    const invalidChallenge = utils.sha256("invalid_challenge").toString("hex");
    const invalidLoginReq = buildLoginRequest(
        account,
        invalidChallenge,
        encryptedSalt,
        newSalt
    );
    const firstDone = Promise.resolve();
    const loginRes = buildResponse(400, (response: any) => {
      expect(response.message).toEqual("invalid client data");
      firstDone;
    });
    await auth.loginWithPasskey(invalidLoginReq as any, loginRes as any);
    await firstDone;

    // valid client data but invalid signature
    const validLoginReq = buildLoginRequest(
        account,
        challenge,
        encryptedSalt,
        newSalt
    );
    invalidLoginReq.body.clientDataJson = validLoginReq.body.clientDataJson;
    const loginRes2 = buildResponse(400, (response: any) => {
      expect(response.message).toEqual("invalid signature");
    });
    await auth.loginWithPasskey(invalidLoginReq as any, loginRes2 as any);
  });
});

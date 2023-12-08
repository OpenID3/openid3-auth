import assert from "assert";
import {
  Key,
  genEciesKey,
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
    ACCOUNT_PROXY_CONTRACT_V1: "0x7CB55518ad352E220882935E419F7Fd3cA68B21A",
    ACCOUNT_FACTORY_CONTRACT_V1: "0xa5727531591A3dE7ADaC6b3759bEF5BD5549c121",
    PASSKEY_ADMIN_CONTRACT_V1: "0x3dAdb4660d8e99B839d1eB6cAb6bB2Fd0414DcF1",
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
import {decryptWithSymmKey, encryptWithSymmKey} from "../gcloudKms";
import {decrypt} from "eciesjs";
import {ethers} from "ethers";
import {getAccountAddress} from "../account";
import {HexlinkError} from "../utils";

jest.spyOn(db, "getUser").mockImplementation(() => Promise.resolve(null));
jest.spyOn(db, "registerUser").mockImplementation(() => Promise.resolve());

describe("registerPasskey", () => {
  let passkey: Key;
  let operator: ethers.HDNodeWallet;
  let eciesKey: any;
  let pkId: string;

  beforeAll(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();
    pkId = "passkey1";
    passkey = genPasskey(pkId);
    eciesKey = genEciesKey();
    operator = ethers.Wallet.createRandom();
  });

  const buildRegisterRequest = (username: string) => {
    const {clientDataJson, authData, signature} = signRegisterRequest(
        username,
        ORIGIN,
        eciesKey.pubKey,
        passkey,
        operator.address
    );
    return {
      headers: {origin: true},
      body: {
        username,
        passkey: passkey.pubKey,
        operator: operator.address,
        kek: eciesKey.pubKey,
        clientDataJson,
        authData,
        signature: signature.toCompactHex(),
      },
    };
  };

  const buildLoginRequest = (
      address: string,
      dekId: string,
      kek: string,
      challenge: string
  ) => {
    const {clientDataJson, authData, signature} = signLoginRequest(
        address,
        ORIGIN,
        dekId,
        kek,
        challenge,
        passkey
    );
    return {
      headers: {origin: true},
      body: {
        address,
        passkey: passkey.pubKey,
        operator: operator.address,
        dekId,
        kek,
        clientDataJson,
        authData,
        signature: signature.toCompactHex(),
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
      expect(response).toHaveProperty("dek");
      expect(response).toHaveProperty("token");
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

  test("the user should login with challenge and new kek", async () => {
    const username = "some.user.mizu";
    const userId = utils.genNameHash(username);
    const dek = crypto.randomBytes(32);
    const dekId = utils.sha256(Buffer.from(dek)).toString("hex");
    const dekServerEncrypted = await encryptWithSymmKey(dek.toString("hex"));
    const userDb: db.User = {
      passkey: {id: pkId, ...passkey.pubKey},
      operator: operator.address,
      metadata: ethers.ZeroHash,
      kek: "",
      deks: {[dekId]: dekServerEncrypted},
      loginStatus: {
        challenge: "",
        updatedAt: new Timestamp(utils.epoch(), 0),
      },
      createdAt: new Timestamp(utils.epoch(), 0),
      csrfToken: "",
    };
    const newKek = genEciesKey();
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
        .mockImplementation(
            (
                _uid: string,
                kek: string,
                csrfToken: string,
                deks?: { [key: string]: string }
            ) => {
              userDb.kek = kek;
              if (deks) {
                userDb.deks = deks;
              }
              expect(userDb.kek).toEqual(newKek.pubKey);
              return Promise.resolve();
            }
        );
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
        dekId,
        newKek.pubKey,
        userDb.loginStatus.challenge
    );
    const secondDone = Promise.resolve();
    const loginRes = buildResponse(200, (response: any) => {
      expect(response).toHaveProperty("token");
      expect(response).toHaveProperty("dek");
      const decryptedDek = decrypt(
          newKek.privKey.secret,
          Buffer.from(response.dek, "hex")
      );
      expect(decryptedDek.toString("hex")).toEqual(dek.toString("hex"));
      expect(response).toHaveProperty("newDek");
      secondDone;
    });
    await auth.loginWithPasskey(loginReq as any, loginRes as any);
    await secondDone;
  });

  test("it should throw if challenge or origin does not match", async () => {
    const challenge = utils.sha256("valid_challenge").toString("hex");
    const dek = crypto.randomBytes(32);
    const dekId = utils.sha256(Buffer.from(dek)).toString("hex");
    const dekServerEncrypted = await encryptWithSymmKey(dek.toString("hex"));
    const userDb: db.User = {
      passkey: {id: pkId, ...passkey.pubKey},
      operator: operator.address,
      metadata: ethers.ZeroHash,
      kek: eciesKey.pubKey,
      deks: {[dekId]: dekServerEncrypted},
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
        .mockImplementation((_uid: string, kek: string) => {
          userDb.kek = kek;
          return Promise.resolve();
        });
    jest.spyOn(db, "getUser").mockImplementation(() => Promise.resolve(userDb));
    const invalidChallenge = utils.sha256("invalid_challenge").toString("hex");
    const newKek = genEciesKey();
    const invalidLoginReq = buildLoginRequest(
        account,
        dekId,
        newKek.pubKey,
        invalidChallenge
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
        dekId,
        newKek.pubKey,
        challenge
    );
    invalidLoginReq.body.clientDataJson = validLoginReq.body.clientDataJson;
    const loginRes2 = buildResponse(400, (response: any) => {
      expect(response.message).toEqual("invalid signature");
    });
    await auth.loginWithPasskey(invalidLoginReq as any, loginRes2 as any);
  });

  test("it should get dek and new dek", async () => {
    const username = "some.user.mizu";
    const userId = utils.genNameHash(username);
    const dek = crypto.randomBytes(32).toString("hex");
    const dekId = utils.sha256(Buffer.from(dek, "hex")).toString("hex");
    const dekServerEncrypted = await encryptWithSymmKey(dek);
    const userDb = {
      kek: eciesKey.pubKey,
      deks: {[dekId]: dekServerEncrypted},
    };

    jest
        .spyOn(db, "getUser")
        .mockImplementation(() => {
          return Promise.resolve(userDb as unknown as db.User);
        });
    jest
        .spyOn(db, "updateDeks")
        .mockImplementation(
            async (_uid: string, deks: { [key: string]: string }) => {
              userDb.deks = deks;
              return Promise.resolve();
            }
        );
    const req = {
      headers: {
        origin: true,
        authorization: "Bearer " + userId,
      },
      body: {keyId: dekId},
    };
    const res = buildResponse(200, async (response: any) => {
      const dekFromClient = decrypt(
          eciesKey.privKey.secret,
          Buffer.from(response.dek, "hex")
      ).toString("hex");
      const dekFromServer = await decryptWithSymmKey(userDb.deks[dekId]);
      expect(dekFromServer).toEqual(dekFromClient);

      const newDekFromClient = decrypt(
          eciesKey.privKey.secret,
          Buffer.from(response.newDek, "hex")
      );
      const newDekId = utils.sha256(newDekFromClient).toString("hex");
      const newDekFromServer = await decryptWithSymmKey(userDb.deks[newDekId]);
      expect(newDekFromServer).toEqual(newDekFromClient.toString("hex"));
    });
    await auth.getDataEncryptionKey(req as any, res as any);
  });
});

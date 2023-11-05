import assert from "assert";
import { Key, genEciesKey, genPasskey, signLoginRequest, signRegisterRequest } from "./passkey";

import ftest from "firebase-functions-test";
import crypto from "crypto";

const testEnv = ftest();
testEnv.mockConfig({ doppler: {
  ENV: "dev",
  DEV_KEY: crypto.randomBytes(32).toString("hex"),
  DEV_KEY_IV: crypto.randomBytes(16).toString("hex"),
  ORIGIN: "https://openid3.org",
} });

jest.mock("firebase-admin", () => {
  return {
    auth: jest.fn().mockReturnThis(),
    createUser: jest.fn(() => Promise.resolve()),
    createCustomToken: jest.fn((uid: string) => Promise.resolve(uid)),
  };
});

// import after testEnv is setup and properly mocked
// otherwise the env won't inject into the functions
import * as auth from "../auth";
import * as user from "../user";
import { epoch, sha3 } from "../utils";
import { Timestamp } from "@google-cloud/firestore";

jest.spyOn(user, "getUser").mockImplementation(
  () => Promise.resolve(null));
jest.spyOn(user, "createUser").mockImplementation(
  () => Promise.resolve());

describe('registerPasskey', () => {
  let passkey: Key;
  let eciesKey: any;

  beforeAll(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();
    passkey = genPasskey();
    eciesKey = genEciesKey();
  });

  const buildRegisterRequest = (username: string) => {
    const {
      clientDataJson,
      authData,
      signature
    } = signRegisterRequest(username, eciesKey.pubKey, passkey);
    return {
      headers: { origin: true },
      body: {
        username,
        passkey: Buffer.from(passkey.pubKey).toString('hex'),
        kek: eciesKey.pubKey,
        clientDataJson,
        authData,
        signature: signature.toCompactHex(),
      }
    };
  }

  const buildLoginRequest = (uid: string, kek: string, challenge: string) => {
    const {
      clientDataJson,
      authData,
      signature
    } = signLoginRequest(uid, kek, challenge, passkey);
    return {
      headers: { origin: true },
      body: {
        uid,
        passkey: Buffer.from(passkey.pubKey).toString('hex'),
        kek,
        clientDataJson,
        authData,
        signature: signature.toCompactHex(),
      }
    };
  }

  const buildResponse = (
    status: number,
    jsonValidator: any,
  ) => {
    return {
      setHeader: () => {},
      getHeader: () => {},
      status: (returnedStatus: number) => {
        assert.equal(returnedStatus, status);
        return {json: jsonValidator};
      },
    }
  }

  test('it should register a new user with passkey', (done: any) => {
    const username = "SOME.user";
    const jsonValidator = (response: any) => {
      expect(response).toHaveProperty("dek");
      expect(response).toHaveProperty("token");
      done();
    };
    const req = buildRegisterRequest(username);
    const res = buildResponse(200, jsonValidator);
    auth.registerUserWithPasskey(req as any, res as any);
  });

  test('it should throw with too short username', (done: any) => {
    const username = "some";
    const jsonValidator = (response: any) => {
      expect(response).toHaveProperty("message");
      expect(response.message).toEqual(user.INVALID_USER_NAME_TOO_SHORT);
      done();
    };
    const req = buildRegisterRequest(username);
    const res = buildResponse(400, jsonValidator);
    auth.registerUserWithPasskey(req as any, res as any);
  });

  test('it should throw with disallowed characters', (done: any) => {
    const username = "some_user";
    const jsonValidator = (response: any) => {
      expect(response).toHaveProperty("message");
      expect(response.message).toEqual(
        user.INVALID_USER_NAME_DISALLOWED_CHARACTERS);
      done();
    };
    const req = buildRegisterRequest(username);
    const res = buildResponse(400, jsonValidator);
    auth.registerUserWithPasskey(req as any, res as any);
  });

  test('it should throw with empty label', (done: any) => {
    const username = "SOME..user";
    const jsonValidator = (response: any) => {
      expect(response).toHaveProperty("message");
      expect(response.message).toEqual(
        user.INVALID_USER_NAME_EMTPY_LABEL);
      done();
    };
    const req = buildRegisterRequest(username);
    const res = buildResponse(400, jsonValidator);
    auth.registerUserWithPasskey(req as any, res as any);
  });

  test('it should throw if user already exists', (done: any) => {
    const username = " SOME.user ";
    jest.spyOn(user, "getUser").mockImplementation(
      (uid: string) => {
        if (uid == user.genNameHash(username)) {
          return Promise.resolve({
            passkey: passkey.pubKey,
            kek: eciesKey.pubKey,
            deks: [],
            createdAt: { seconds: 0, nanoseconds: 0 },
          } as unknown as user.User);
        } else {
          return Promise.resolve(null);
        }
      });
    const jsonValidator = (response: any) => {
      expect(response).toHaveProperty("message");
      expect(response.message).toEqual("user already exists");
      done();
    };
    const req = buildRegisterRequest("some.USER");
    const res = buildResponse(400, jsonValidator);
    auth.registerUserWithPasskey(req as any, res as any);
  });

  test('the user should login with challenge and new kek', async () => {
    const username = "some.user";
    const userId = user.genNameHash(username);
    const pubKeyHex = Buffer.from(passkey.pubKey).toString("hex");
    const userDb : user.User = {
      passkey: pubKeyHex,
      kek: "",
      deks: [],
      loginStatus: {
        challenge: "",
        updatedAt: new Timestamp(epoch(), 0),
      },
      createdAt: new Timestamp(epoch(), 0),
    };
    jest.spyOn(user, "preAuth").mockImplementation(
      (_uid: string, challenge: string) => {
        userDb.loginStatus = {
          challenge,
          updatedAt: new Timestamp(epoch(), 0),
        };
        return Promise.resolve();
      }
    );
    jest.spyOn(user, "postAuth").mockImplementation(
      (_uid: string, kek: string) => {
        userDb.kek = kek;
        return Promise.resolve();
      }
    );
    jest.spyOn(user, "getUser").mockImplementation(
      (uid: string) => {
        if (uid == userId) {
          return Promise.resolve(userDb);
        } else {
          return Promise.resolve(null);
        }
      });
    const req = {
      headers: { origin: true },
      body: { uid: userId },
    };
    const firstDone = Promise.resolve(true);
    const jsonValidator = (response: any) => {
      expect(response).toHaveProperty("challenge");
      expect(response.challenge).toEqual(userDb.loginStatus.challenge);
      firstDone;
    };
    const res = buildResponse(200, jsonValidator);
    await auth.getPasskeyChallenge(req as any, res as any);
    await firstDone;

    const newKek = genEciesKey();
    const loginReq = buildLoginRequest(
      userId, newKek.pubKey, userDb.loginStatus.challenge);
    const secondDone = Promise.resolve(true);
    const loginRes = buildResponse(200, (response: any) => {
      expect(response).toHaveProperty("token");
      secondDone;
    });
    await auth.loginWithPasskey(loginReq as any, loginRes as any);
    await secondDone;
    expect(userDb.kek).toEqual(newKek.pubKey);
  });

  test('it should throw if challenge or origin does not match', async () => {
    const username = "some.user";
    const userId = user.genNameHash(username);
    const challenge = sha3("valid_challenge").toString("hex");
    const userDb : user.User = {
      passkey: Buffer.from(passkey.pubKey).toString("hex"),
      kek: eciesKey.pubKey,
      deks: [],
      loginStatus: {
        challenge,
        updatedAt: new Timestamp(epoch(), 0),
      },
      createdAt: new Timestamp(epoch(), 0),
    };
    jest.spyOn(user, "postAuth").mockImplementation(
      (_uid: string, kek: string) => {
        userDb.kek = kek;
        return Promise.resolve();
      }
    );
    jest.spyOn(user, "getUser").mockImplementation(
      (uid: string) => {
        if (uid == userId) {
          return Promise.resolve(userDb);
        } else {
          return Promise.resolve(null);
        }
      });
    const invalidChallenge = sha3("invalid_challenge").toString("hex");
    const newKek = genEciesKey();
    const invalidLoginReq = buildLoginRequest(
      userId, newKek.pubKey, invalidChallenge);
    const firstDone = Promise.resolve();
    const loginRes = buildResponse(400, (response: any) => {
      expect(response.message).toEqual("invalid client data");
      firstDone;
    });
    await auth.loginWithPasskey(invalidLoginReq as any, loginRes as any);
    await firstDone;

    // valid client data but invalid signature
    const validLoginReq = buildLoginRequest(
      userId, newKek.pubKey, challenge);
    invalidLoginReq.body.clientDataJson = validLoginReq.body.clientDataJson;
    const loginRes2 = buildResponse(400, (response: any) => {
      expect(response.message).toEqual("invalid signature");
    });
    await auth.loginWithPasskey(invalidLoginReq as any, loginRes2 as any);
  });
});
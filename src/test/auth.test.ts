import assert from "assert";
import { Key, genEciesKey, genPasskey, signRegisterRequest } from "./passkey";

import ftest from "firebase-functions-test";
import crypto from "crypto";

const testEnv = ftest();
testEnv.mockConfig({ doppler: {
  ENV: "dev",
  DEV_KEY: crypto.randomBytes(32).toString("hex"),
  DEV_KEY_IV: crypto.randomBytes(16).toString("hex"),
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

  const buildRegisterResponse = (
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
    const res = buildRegisterResponse(200, jsonValidator);
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
    const res = buildRegisterResponse(400, jsonValidator);
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
    const res = buildRegisterResponse(400, jsonValidator);
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
    const res = buildRegisterResponse(400, jsonValidator);
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
    const res = buildRegisterResponse(400, jsonValidator);
    auth.registerUserWithPasskey(req as any, res as any);
  });
});
import assert from "assert";
import ftest from "firebase-functions-test";
import { PrivateKey } from 'eciesjs'
import crypto from "crypto";
import { genPasskey, signRegisterRequest } from "./passkey";

export interface Key {
  privKey: Uint8Array | Buffer,
  pubKey: Uint8Array | Buffer,
}

export const genEciesKey = () => {
  const privKey = new PrivateKey();
  return {
    privKey,
    pubKey: privKey.publicKey.toHex(),
  }
}

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
  }
});

// import after testEnv is setup and properly mocked
// otherwise the env won't inject into the functions
import * as auth from "../auth";
import * as user from "../user";

describe('registerPasskey', () => {
  let passkey: Key;
  let eciesKey: any;

  beforeAll(() => {
    jest.useFakeTimers();
    passkey = genPasskey();
    eciesKey = genEciesKey();
  });

  afterAll(() => {
    testEnv.cleanup()
  });

  test('it registers a new user with passkey', (done: any) => {
    const username = "someuser";
    const {
      clientDataJson,
      authData,
      signature
    } = signRegisterRequest(username, eciesKey.pubKey, passkey);
    const req = {
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
    const res = {
      setHeader: () => {},
      getHeader: () => {},
      status: (status: number) => {
        assert.equal(status, 200);
        return {
          json: (response: any) => {
            expect(response).toHaveProperty("dek");
            expect(response).toHaveProperty("token");
            done();
          },
        };
      },
    };
    jest.spyOn(user, "createUser").mockImplementation(
      () => Promise.resolve());
    auth.registerUserWithPasskey(req as any, res as any);
  });
});
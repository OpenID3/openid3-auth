import assert from "assert";
import ftest from "firebase-functions-test";
import { PrivateKey } from 'eciesjs'
import * as admin from "firebase-admin";
import crypto from "crypto";
import { genPasskey, signRegisterRequest } from "./passkey";

export interface Key {
  privKey: Uint8Array | Buffer,
  pubKey: Uint8Array | Buffer,
}

export const genEciesKey = () => {
  // const privKey = eccrypto.generatePrivate();
  const privKey = PrivateKey.fromHex("bfa4a75f88092e91945413e18103e6564d03c15d95df4020b015f61221ff7048");
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
admin.initializeApp({projectId: "test"});

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

  test('it register a new user with passkey', (done: any) => {
    const uid = "someuser";
    const {
      clientDataJson,
      authData,
      signature
    } = signRegisterRequest(uid, passkey);
    const req = {
      headers: { origin: true },
      body: {
        uid,
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

    jest.spyOn(user, "getUser").mockImplementation(
      () => Promise.resolve(null));
    jest.spyOn(user, "createUser").mockImplementation(
      () => Promise.resolve());
    auth.registerUserWithPasskey(req as any, res as any);
  });
});
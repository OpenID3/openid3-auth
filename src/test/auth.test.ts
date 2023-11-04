import assert from "assert";
import ftest from "firebase-functions-test";
import eccrypto from "eccrypto";
import * as admin from "firebase-admin";
import { genPasskey, signRegisterRequest } from "./passkey";

export interface Key {
  privKey: Uint8Array | Buffer,
  pubKey: Uint8Array | Buffer,
}

export const genEciesKey = () => {
  const privKey = eccrypto.generatePrivate();
  return {
    privKey,
    pubKey: eccrypto.getPublic(privKey),
  }
}

const testEnv = ftest({
  databaseURL: process.env.FIREBASE_DATABASE_URL,
  projectId: process.env.FIREBASE_PROJECT_ID,
}, process.env.SERVICE_ACCOUNT_KEY_PATH);
testEnv.mockConfig({ doppler: { ENV: "dev" } });
admin.initializeApp();

// import after testEnv is setup and properly mocked
// otherwise the env won't inject into the functions
import { registerUserWithPasskey } from "../auth"

describe('registerPasskey', () => {
  let passkey: Key;
  let eciesKey: Key;

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
        uid: "someuser",
        passkey: Buffer.from(passkey.pubKey).toString('hex'),
        kek: eciesKey.pubKey.toString("hex"),
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
      },
      json: (response: any) => {
        console.log(response);
        expect(response).toBe({});
        done();
      },
    };
    registerUserWithPasskey(req as any, res as any);
  });
});
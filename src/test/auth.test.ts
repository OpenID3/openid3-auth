import assert from "assert";
import {Key, genEciesKey, genPasskey, signLoginRequest, signRegisterRequest} from "./passkey";

import ftest from "firebase-functions-test";
import crypto from "crypto";

const testEnv = ftest();
const ORIGIN = "https://localhost:3000";
testEnv.mockConfig({doppler: {
  ENV: "dev",
  DEV_KEY: crypto.randomBytes(32).toString("hex"),
  DEV_KEY_IV: crypto.randomBytes(16).toString("hex"),
  ORIGIN,
}});

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
import * as user from "../user";
import {epoch, sha256} from "../utils";
import {Timestamp} from "@google-cloud/firestore";
import {decryptWithSymmKey, encryptWithSymmKey} from "../gcloudKms";
import {decrypt} from "eciesjs";

jest.spyOn(user, "getUser").mockImplementation(
    () => Promise.resolve(null));
jest.spyOn(user, "createUser").mockImplementation(
    () => Promise.resolve());

describe("registerPasskey", () => {
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
      signature,
    } = signRegisterRequest(username, ORIGIN, eciesKey.pubKey, passkey);
    return {
      headers: {origin: true},
      body: {
        username,
        passkey: passkey.pubKey,
        kek: eciesKey.pubKey,
        clientDataJson,
        authData,
        signature: signature.toCompactHex(),
      },
    };
  };

  const buildLoginRequest = (
      uid: string,
      dekId: string,
      kek: string,
      challenge: string
  ) => {
    const {
      clientDataJson,
      authData,
      signature,
    } = signLoginRequest(uid, ORIGIN, dekId, kek, challenge, passkey);
    return {
      headers: {origin: true},
      body: {
        uid,
        passkey: passkey.pubKey,
        dekId,
        kek,
        clientDataJson,
        authData,
        signature: signature.toCompactHex(),
      },
    };
  };

  const buildResponse = (
      status: number,
      jsonValidator: any,
  ) => {
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
      expect(response.message).toEqual(user.INVALID_USER_NAME_TOO_SHORT);
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
          user.INVALID_USER_NAME_DISALLOWED_CHARACTERS);
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
      expect(response.message).toEqual(
          user.INVALID_USER_NAME_EMTPY_LABEL);
      done();
    };
    const req = buildRegisterRequest(username);
    const res = buildResponse(400, jsonValidator);
    auth.registerUserWithPasskey(req as any, res as any);
  });

  test("it should throw if user already exists", (done: any) => {
    const username = "SOME.user.mizu";
    jest.spyOn(user, "getUser").mockImplementation(
        (uid: string) => {
          if (uid == user.genNameHash(username)) {
            return Promise.resolve({
              passkey: passkey.pubKey,
              kek: eciesKey.pubKey,
              deks: {},
              createdAt: {seconds: 0, nanoseconds: 0},
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
    const req = buildRegisterRequest("some.USER.mizu");
    const res = buildResponse(400, jsonValidator);
    auth.registerUserWithPasskey(req as any, res as any);
  });

  test("the user should login with challenge and new kek", async () => {
    const username = "some.user.mizu";
    const userId = user.genNameHash(username);
    const dek = crypto.randomBytes(32);
    const dekId = sha256(Buffer.from(dek)).toString("hex");
    const dekServerEncrypted = await encryptWithSymmKey(dek.toString("hex"));
    const userDb : user.User = {
      passkey: passkey.pubKey,
      kek: "",
      deks: {[dekId]: dekServerEncrypted},
      loginStatus: {
        challenge: "",
        updatedAt: new Timestamp(epoch(), 0),
      },
      createdAt: new Timestamp(epoch(), 0),
    };
    const newKek = genEciesKey();

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
        (_uid: string, kek: string, deks: {[key: string]: string}) => {
          userDb.kek = kek;
          userDb.deks = deks;
          expect(userDb.kek).toEqual(newKek.pubKey);
          return Promise.resolve();
        }
    );
    jest.spyOn(user, "getUser").mockImplementation(
        () => Promise.resolve(userDb));
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
        userId, dekId, newKek.pubKey, userDb.loginStatus.challenge);
    const secondDone = Promise.resolve();
    const loginRes = buildResponse(200, (response: any) => {
      expect(response).toHaveProperty("token");
      expect(response).toHaveProperty("dek");
      const decryptedDek = decrypt(
          newKek.privKey.secret, Buffer.from(response.dek, "hex"));
      expect(decryptedDek.toString("hex")).toEqual(dek.toString("hex"));
      expect(response).toHaveProperty("newDek");
      secondDone;
    });
    await auth.loginWithPasskey(loginReq as any, loginRes as any);
    await secondDone;
  });

  test("it should throw if challenge or origin does not match", async () => {
    const username = "some.user.mizu";
    const userId = user.genNameHash(username);
    const challenge = sha256("valid_challenge").toString("hex");
    const dek = crypto.randomBytes(32);
    const dekId = sha256(Buffer.from(dek)).toString("hex");
    const dekServerEncrypted = await encryptWithSymmKey(dek.toString("hex"));
    const userDb : user.User = {
      passkey: passkey.pubKey,
      kek: eciesKey.pubKey,
      deks: {[dekId]: dekServerEncrypted},
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
        () => Promise.resolve(userDb));
    const invalidChallenge = sha256("invalid_challenge").toString("hex");
    const newKek = genEciesKey();
    const invalidLoginReq = buildLoginRequest(
        userId, dekId, newKek.pubKey, invalidChallenge);
    const firstDone = Promise.resolve();
    const loginRes = buildResponse(400, (response: any) => {
      expect(response.message).toEqual("invalid client data");
      firstDone;
    });
    await auth.loginWithPasskey(invalidLoginReq as any, loginRes as any);
    await firstDone;

    // valid client data but invalid signature
    const validLoginReq = buildLoginRequest(
        userId, dekId, newKek.pubKey, challenge);
    invalidLoginReq.body.clientDataJson = validLoginReq.body.clientDataJson;
    const loginRes2 = buildResponse(400, (response: any) => {
      expect(response.message).toEqual("invalid signature");
    });
    await auth.loginWithPasskey(invalidLoginReq as any, loginRes2 as any);
  });

  test("it should get dek and new dek", async () => {
    const username = "some.user.mizu";
    const userId = user.genNameHash(username);
    const dek = crypto.randomBytes(32).toString("hex");
    const dekId = sha256(Buffer.from(dek, "hex")).toString("hex");
    const dekServerEncrypted = await encryptWithSymmKey(dek);
    const userDb = {
      kek: eciesKey.pubKey,
      deks: {[dekId]: dekServerEncrypted},
    };
    jest.spyOn(user, "getUser").mockImplementation(
        () => Promise.resolve(userDb as unknown as user.User));
    jest.spyOn(user, "updateDeks").mockImplementation(
        async (_uid: string, deks: {[key: string]: string}) => {
          userDb.deks = deks;
          return Promise.resolve();
        });
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
      const newDekId = sha256(newDekFromClient).toString("hex");
      const newDekFromServer = await decryptWithSymmKey(userDb.deks[newDekId]);
      expect(newDekFromServer).toEqual(newDekFromClient.toString("hex"));
    });
    await auth.getDataEncryptionKey(req as any, res as any);
  });
});

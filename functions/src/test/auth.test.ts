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
const REACT_APP_ORIGIN = "https://localhost:3000";
const CONTRACT_V0_0_8_ACCOUNT_FACTORY =
  "0xa5727531591A3dE7ADaC6b3759bEF5BD5549c121";
const JWT_SIGNER_DEV_PUB_PEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6gsSat0h0c3hFoar3vSP
YKGB9CDgCoeRX++uk7BDJEjZ/y09ew4mLcaemOHKd/yHUUBrNWwHeyaUIj27AK9K
Gh/zXGWwqlijb1hYWMJTinoawgscJ25KfE1Mwnnopv+lFAPlWew5S8U8ZU8iVcJm
VQsYxAQSHrKozecxKOwdqV4Y0/O2yR/7v/KTkoW+FAGCaFlFIwikCPojq1msB4b9
SiBh5UXp2P4DtKPt0whCo7LIlubXKyC9WCI81ZeJiMU8pCHB/hyjumnggS+lQTtY
HFZYccuYDq0u5grFyWGLbvI/jMKBodPzoL0DoDBmruIWPh6Qj1aLUTUF2i0auEtI
MQIDAQAB
-----END PUBLIC KEY-----`;
const JWT_SIGNER_DEV_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDqCxJq3SHRzeEW
hqve9I9goYH0IOAKh5Ff766TsEMkSNn/LT17DiYtxp6Y4cp3/IdRQGs1bAd7JpQi
PbsAr0oaH/NcZbCqWKNvWFhYwlOKehrCCxwnbkp8TUzCeeim/6UUA+VZ7DlLxTxl
TyJVwmZVCxjEBBIesqjN5zEo7B2pXhjT87bJH/u/8pOShb4UAYJoWUUjCKQI+iOr
WawHhv1KIGHlRenY/gO0o+3TCEKjssiW5tcrIL1YIjzVl4mIxTykIcH+HKO6aeCB
L6VBO1gcVlhxy5gOrS7mCsXJYYtu8j+MwoGh0/OgvQOgMGau4hY+HpCPVotRNQXa
LRq4S0gxAgMBAAECggEAAnZn3FZ8amX1tm4PNBTxFaRpFaZchH86tHwIysysV979
DZbEjscm7hve/FzGv2DyMZ6lJdKnGvWrUhKGtDNaHDqa8rwkozNvcFQ6ijPFYtSY
G12G6A7rTugCdhN0LihCjyRfbcUJJ19rzYKLIBNMRLBNmuywHgrqiag7yinXhuZy
gEE+BTszx5TxgOKmT+xOnXWQzhNfA4L/s8dp5/EM2U57VXiaqcotSnT14xCbMESW
avJ6Vh+dC0SC7+fvEZDWj55NuYZBCGjqljSPtKC3Kdc0RyHmn8CYUr2wV+9uNSro
J+Xn9TJ8P33rExgdile+JapZ6tSr0F4fwCxgL7S37QKBgQD8DBt7g53CORnmTVED
fuhEi2OpvSnFbPkmcvRqwmrBk4+cTBODA/YFVmdPE9IXJejvWgBBBSYZowAHf+vz
FKdpJSaFdgJzWvbgsrm6DIjiAWxaxUdi0Vz842j6sGqDy+0D1rtejXtBPRjFZ6/u
u4iK3YxPP3Ala31ygK/Zmu4HPQKBgQDttq8R+sEZFiyVfPOD1NTJ3LFBblRowGy+
iFYB/UvcI+e21H+45Zx+RaQM68OxwMS3v33ozqVwaWnIt4Hqul/9k/NG7vYe2U9u
gj+4bl0Fs67/DisDHQ+9oFwfo8/GH9GWbRqPVvqVT70/1jTau8raAn6/eGtaSAH/
Dzhswav0BQKBgDWA/HSDxAFuzait0PzE+9lRHZ7yoONf9qPK00e2baMaB+pN2/Z7
6MXJSbTnqDlxurjUiilDRos6ps7wwM2hHMidMkgyfOKv9KhOSE7OSmBvnOjH6Bd6
ChtEywwsVvATYgTmmG/B6OA4cAG3uQkcliekUByigtPutXqRBsNSuCShAoGACBII
tZKO1bwz/UtFtTcXllbgybjmMrw9tOZKDT09QxcQ+dsTDwL0ojDZFfs3JKTHyPk+
XBYP9dYOWlsolQCI28IXI1RflMKJ+NWBNlDA5b2o9k3T1gI5k5WLKyPTnQVdhz7j
BPTOAx227iDmoHp5s5ccGIINGv6Q2sj4gHC+1sUCgYB5kIgaSbYEAn/3D9TI/G5s
Wy+Gg/MWXG4GpfPO8aTfQeJNQmAfVZqpJWlB8G9Qxrs1kI5gpSmwe0UYFYU63Lhc
NIoQU3eWYoQTRkFhEJsBOzpWQXe3TQeaUL+rFJcpO+/mxkP1P+8SmnddvDr4U7X5
tQdoUZQOOrxSv5d2fdEtgg==
-----END PRIVATE KEY-----`;
testEnv.mockConfig({
  doppler: {
    ENV: "dev",
    DEV_KEY: crypto.randomBytes(32).toString("hex"),
    DEV_KEY_IV: crypto.randomBytes(16).toString("hex"),
    REACT_APP_ORIGIN,
    CONTRACT_V0_0_8_ACCOUNT_PROXY: "0x7CB55518ad352E220882935E419F7Fd3cA68B21A",
    CONTRACT_V0_0_8_ACCOUNT_FACTORY,
    CONTRACT_V0_0_8_PASSSKEY_ADMIN:
      "0x3dAdb4660d8e99B839d1eB6cAb6bB2Fd0414DcF1",
    JWT_SIGNER_DEV_PUB_PEM,
    JWT_SIGNER_DEV_PRIVATE_KEY,
  },
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
import {ServerError, genNameHash} from "../utils";

const account: string = "0x" + crypto.randomBytes(20).toString("hex");
jest.spyOn(acc, "getAccountAddress").mockImplementation(
    () => Promise.resolve(account));
jest.spyOn(adb, "getAuth").mockImplementation(() => Promise.resolve(null));
jest.spyOn(adb, "registerUser").mockImplementation(() => Promise.resolve());

class MockedResponse {
  _status: number;
  _jsonValidator: any;
  _cookie: string | null = null;

  constructor(status: number, jsonValidator: any) {
    this._status = status;
    this._jsonValidator = jsonValidator;
  }

  setHeader() {
    return this;
  }

  getHeader() {
    return this;
  }

  appendHeader() {
    return this;
  }

  cookie(_name: string, cookie: string) {
    this._cookie = cookie;
    return this;
  }

  status(status: number) {
    assert.equal(status, this._status);
    return {json: this._jsonValidator};
  }
}

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
        REACT_APP_ORIGIN,
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
        REACT_APP_ORIGIN,
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

  test("username validation", () => {
    const validateHexlinkError = (
        name: string,
        code: number,
        message: string
    ) => {
      try {
        genNameHash(name);
      } catch (e) {
        expect(e).toBeInstanceOf(ServerError);
        expect((e as ServerError).code).toEqual(code);
        expect((e as ServerError).message).toEqual(message);
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
      expect(encDek).toEqual(response.encDek);
      done();
    };
    const req = buildRegisterRequest(username);
    const res = new MockedResponse(200, jsonValidator);
    auth.registerUserWithPasskey(req as any, res as any);
  });

  test("it should throw if user already exists", (done: any) => {
    jest.spyOn(adb, "registerUser").mockImplementation(() => {
      throw new ServerError(400, "name already taken");
    });
    const jsonValidator = (response: any) => {
      expect(response).toHaveProperty("message");
      expect(response.message).toEqual("name already taken");
      done();
    };
    const req = buildRegisterRequest("peter.mizu");
    const res = new MockedResponse(400, jsonValidator);
    auth.registerUserWithPasskey(req as any, res as any);
  });

  test("the user should login with challenge", async () => {
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
      body: {address: account},
    };
    const firstDone = Promise.resolve();
    const jsonValidator = (response: any) => {
      expect(response).toHaveProperty("challenge");
      expect(response.challenge).toEqual(authDb.challenge);
      firstDone;
    };
    const res = new MockedResponse(200, jsonValidator);
    await auth.getPasskeyChallenge(req as any, res as any);
    await firstDone;

    const loginReq = buildLoginRequest(account, authDb.challenge!);
    const secondDone = Promise.resolve();
    const loginRes = new MockedResponse(200, (response: any) => {
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
    const loginRes1 = new MockedResponse(404, (response: any) => {
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
    const loginRes2 = new MockedResponse(400, (response: any) => {
      expect(response.message).toEqual("invalid client data");
      secondDone;
    });
    await auth.loginWithPasskey(invalidLoginReq as any, loginRes2 as any);
    await secondDone;

    // valid client data but invalid signature
    const validLoginReq = buildLoginRequest(account, challenge);
    invalidLoginReq.body.clientDataJson = validLoginReq.body.clientDataJson;
    const loginRes3 = new MockedResponse(400, (response: any) => {
      expect(response.message).toEqual("invalid signature");
    });
    await auth.loginWithPasskey(invalidLoginReq as any, loginRes3 as any);
  });
});

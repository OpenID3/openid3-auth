import {Timestamp} from "firebase-admin/firestore";
import {Passkey, firestore} from "./utils";
import {HexlinkError, epoch} from "../utils";

export interface Auth {
  passkey: Passkey;
  challenge: string | null;
  csrfToken: string;
  updatedAt: Timestamp;
}

export async function getAuth(address: string): Promise<Auth | null> {
  const result = await firestore().collection("auth").doc(address).get();
  if (result && result.exists) {
    return result.data() as Auth;
  }
  return null;
}

export async function preAuth(address: string, challenge: string) {
  await firestore()
      .collection("auth")
      .doc(address)
      .update({
        challenge: challenge,
        updatedAt: new Timestamp(epoch(), 0),
      });
}

export async function postAuth(address: string, csrfToken: string) {
  await firestore()
      .collection("auth")
      .doc(address)
      .update({
        challenge: null,
        updatedAt: new Timestamp(epoch(), 0),
        csrfToken,
      });
}

export async function registerUser(
    uid: string,
    address: string,
    passkey: Passkey,
    factory: string,
    operator: string,
    metadata: string,
    csrfToken: string,
) {
  const db = firestore();
  const nsRef = db.collection("mns").doc(uid);
  const userRef = db.collection("users").doc(address);
  const authRef = db.collection("auth").doc(address);
  await db.runTransaction(async (t) => {
    const doc = await t.get(nsRef);
    if (doc && doc.exists) {
      throw new HexlinkError(400, "name already taken");
    }
    t.set(nsRef, {address});
    t.set(userRef, {
      passkey,
      factory,
      operator,
      metadata,
      createdAt: new Timestamp(epoch(), 0),
    });
    t.set(authRef, {
      passkey,
      csrfToken,
      updatedAt: new Timestamp(epoch(), 0),
    });
  });
}

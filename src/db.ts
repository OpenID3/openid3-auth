import * as admin from "firebase-admin";
import {HexlinkError, epoch} from "./utils";
import {Timestamp} from "firebase-admin/firestore";
import {Chain, JwtInput, OidcZkProof, UserOperationStruct} from "./userop";

export interface Passkey {
  x: string; // pubKeyX
  y: string; // pubKeyY
  id: string;
}

// use address as key for user
export interface User {
    passkey: Passkey;
    operator: string; // operator address
    kek: string; // stored at client side to decrypt the dek from server
    deks: {[key: string]: string};
    loginStatus: {
        challenge: string,
        updatedAt: Timestamp,
    };
    createdAt: Timestamp;
}

export interface NameData {
  address: string;
}

const firestore = () => {
  return admin.firestore();
};

export async function resolveName(
    uid: string
) {
  const name = await firestore().collection("mns").doc(uid).get();
  if (name && name.exists) {
    return (name.data() as NameData).address;
  }
  return null;
}

export async function registerUser(
    uid: string,
    address: string,
    passkey: Passkey,
    operator: string,
    kek: string,
    deks: {[key: string]: string}
) {
  const db = firestore();
  const nsRef = db.collection("mns").doc(uid);
  const userRef = db.collection("users").doc(address);
  await db.runTransaction(async (t) => {
    const doc = await t.get(nsRef);
    if (doc && doc.exists) {
      throw new HexlinkError(400, "name already taken");
    }
    t.set(nsRef, {address});
    t.set(userRef, {
      passkey,
      operator,
      kek,
      deks,
      createdAt: new Timestamp(epoch(), 0),
      loginStatus: {
        challenge: "",
        updatedAt: new Timestamp(epoch(), 0),
      },
    });
  });
}

export async function getUser(
    address: string,
) : Promise<User | null> {
  const result = await firestore().collection(
      "users").doc(address).get();
  if (result && result.exists) {
    return result.data() as User;
  }
  return null;
}

export async function userExist(
    address: string,
) : Promise<boolean> {
  const result = await firestore().collection(
      "users").doc(address).get();
  if (result && result.exists) {
    return true;
  }
  return false;
}

export async function preAuth(address: string, challenge: string) {
  await firestore().collection("users").doc(address).update({
    loginStatus: {
      challenge: challenge,
      updatedAt: new Timestamp(epoch(), 0),
    },
  });
}

export async function postAuth(
    address: string,
    kek: string,
    deks?: {[key: string]: string}
) {
  const loginStatus = {
    challenge: "",
    updatedAt: new Timestamp(epoch(), 0),
  };
  if (deks) {
    await firestore().collection("users").doc(
        address).update({kek, deks, loginStatus});
  } else {
    await firestore().collection("users").doc(
        address).update({kek, loginStatus});
  }
}

export async function updateDeks(
    address: string,
    deks: {[key: string]: string}
) {
  await firestore().collection("users").doc(address).update({deks});
}

export interface ZKP {
    uid: string;
    status: "processing" | "done" | "error";
    proof: OidcZkProof | null; // for done status
    error: string | null; // for error status
    chain: Chain,
    userOp: UserOperationStruct;
    jwtInput: JwtInput,
    createdAt: Timestamp;
    finishedAt: Timestamp | null;
}

export async function getZkp(
    uid: string,
) : Promise<ZKP | null> {
  const result = await firestore().collection("zkp").doc(uid).get();
  if (result && result.exists) {
    return result.data() as ZKP;
  }
  return null;
}

export async function addNewZkpRequest(
    uid: string,
    jwtInput: JwtInput,
    chain: Chain,
    userOp: UserOperationStruct,
) {
  await firestore().collection("zkp").doc(uid).set({
    status: "processing",
    jwtInput,
    chain,
    userOp,
    createdAt: new Timestamp(epoch(), 0),
  });
}

export async function addZkProof(
    uid: string,
    proof: string,
) {
  await firestore().collection("zkp").doc(uid).update({
    status: "done",
    proof,
  });
}

export async function markZkProofError(
    uid: string,
    error: string,
) {
  await firestore().collection("zkp").doc(uid).update({
    status: "error",
    error,
  });
}

